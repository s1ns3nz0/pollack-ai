#!/usr/bin/env python3
"""OSCAL POA&M 임계값 검증 게이트.

`compliance/oscal/poam/uav-soc-poam.json` (OSCAL 1.1.2 plan-of-action-and-milestones)을
파싱해 미해결 리스크 카운트가 사전 정의 임계값을 초과하는지 검증한다.

정식 배치 경로:
    ``compliance/oscal/check_poam_thresholds.py``
    (워크플로(`cd-staging.yml` / `cd-prod.yml`)는 이 경로를 호출한다.
    현 파일은 산출물 워크스페이스(`_workspace/02_pipeline_config/scripts/`)의
    원본이며, 정식 경로로 동기 승격되어야 한다 — infra-engineer 인계 사항.)

사용 예:
    python check_poam_thresholds.py \\
        compliance/oscal/poam/uav-soc-poam.json \\
        --critical-max 0 --high-max 3 \\
        --mode block --partial-warn 25 \\
        --report-md _workspace/04_security_scan_poam.md \\
        --report-json poam_summary.json

종료 코드:
    0 — 임계값 통과 (CI 게이트 OK) 또는 ``--mode warn``
    1 — 임계값 초과 + ``--mode block`` (CI 게이트 차단)
    2 — 입력/스키마 오류 (운영 오류)

설계 원칙:
    - 표준 라이브러리만 사용 (Python 3.11+).
    - POAM 항목의 ``props[name=risk]`` 와 ``props[name=implementation-status]`` 양쪽을
      참고해 심각도를 결정한다 (한국어/영어 라벨 모두 허용).
    - ``remediation-tracking`` 이 종결(closed) 상태로 명시된 항목은 카운트에서 제외.
    - 임계값을 환경변수(OSCAL_POAM_CRITICAL_MAX 등)로도 주입 가능.
    - ``--mode {warn,block}`` 로 게이트 동작 모드 명시 (block=기본, warn=staging/PR).
    - ``--partial-warn N`` 로 partial 상태 누적량 경고 (차단 아님).
    - 구버전 호환을 위해 ``--warn-only`` 는 ``--mode warn`` 의 deprecated 별칭으로 유지.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import sys
from typing import TypeGuard

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_ERROR = 2

# ─────────────────────────────────────────────────────────────────────────
# 심각도 매핑
# ─────────────────────────────────────────────────────────────────────────
# OSCAL prop[name=risk] 의 한국어/영어 값을 정규화.
SEVERITY_ALIASES: dict[str, str] = {
    "critical": "critical",
    "심각": "critical",
    "치명": "critical",
    "high": "high",
    "높음": "high",
    "상": "high",
    "medium": "medium",
    "중간": "medium",
    "중": "medium",
    "moderate": "medium",
    "low": "low",
    "낮음": "low",
    "하": "low",
    "informational": "low",
    "info": "low",
}

# implementation-status → 기본 심각도 매핑 (risk prop 부재 시 백업)
STATUS_FALLBACK_SEVERITY: dict[str, str] = {
    "planned": "high",   # 미구현 = 즉시 위험 1단계 상향
    "partial": "medium",
    "implemented": "low",
}

CLOSED_TRACKING_KEYWORDS: tuple[str, ...] = (
    "closed",
    "completed",
    "종결",
    "완료",
    "해결",
)


# ─────────────────────────────────────────────────────────────────────────
# 타입 가드
# ─────────────────────────────────────────────────────────────────────────
def _is_str_dict(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(k, str) for k in value)


def _is_list_of_dicts(value: object) -> TypeGuard[list[dict[str, object]]]:
    return isinstance(value, list) and all(isinstance(v, dict) for v in value)


# ─────────────────────────────────────────────────────────────────────────
# 데이터 모델
# ─────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class PoamItem:
    """POAM 단일 항목 요약."""

    uuid: str
    title: str
    severity: str  # critical/high/medium/low
    status: str    # implemented/partial/planned/unknown
    closed: bool
    raw_risk: str


@dataclass
class PoamSummary:
    """POAM 임계 검증 결과."""

    counts: dict[str, int] = field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0}
    )
    open_items: list[PoamItem] = field(default_factory=list)
    closed_items: list[PoamItem] = field(default_factory=list)
    total_items: int = 0

    @property
    def critical(self) -> int:
        return self.counts["critical"]

    @property
    def high(self) -> int:
        return self.counts["high"]

    @property
    def medium(self) -> int:
        return self.counts["medium"]

    @property
    def low(self) -> int:
        return self.counts["low"]

    def to_dict(self) -> dict[str, object]:
        return {
            "generated": datetime.now(UTC).isoformat(timespec="seconds"),
            "total_items": self.total_items,
            "open_counts": dict(self.counts),
            "open_items": [
                {
                    "uuid": it.uuid,
                    "title": it.title,
                    "severity": it.severity,
                    "status": it.status,
                    "raw_risk": it.raw_risk,
                }
                for it in self.open_items
            ],
            "closed_count": len(self.closed_items),
        }


# ─────────────────────────────────────────────────────────────────────────
# 파싱
# ─────────────────────────────────────────────────────────────────────────
class PoamParseError(Exception):
    """POAM JSON 파싱·스키마 오류."""


def _normalize_severity(raw: str) -> str:
    """원시 severity 라벨을 정규화. 매칭 실패 시 'unknown'."""
    if not raw:
        return "unknown"
    key = raw.strip().lower()
    return SEVERITY_ALIASES.get(key, "unknown")


def _extract_props(item: dict[str, object]) -> dict[str, str]:
    """OSCAL ``props`` 배열을 {name: value} 매핑으로 평탄화."""
    props_raw = item.get("props", [])
    if not _is_list_of_dicts(props_raw):
        return {}
    out: dict[str, str] = {}
    for p in props_raw:
        name = p.get("name")
        value = p.get("value")
        if isinstance(name, str) and isinstance(value, str):
            out[name] = value
    return out


def _is_closed(item: dict[str, object]) -> bool:
    """``remediation-tracking`` 의 마지막 엔트리가 종결 키워드면 closed."""
    rt = item.get("remediation-tracking")
    if not _is_str_dict(rt):
        return False
    entries = rt.get("tracking-entries")
    if not _is_list_of_dicts(entries) or not entries:
        return False
    last = entries[-1]
    title = str(last.get("title", "")).lower()
    desc = str(last.get("description", "")).lower()
    blob = f"{title} {desc}"
    return any(kw in blob for kw in CLOSED_TRACKING_KEYWORDS)


def _classify_item(item: dict[str, object]) -> PoamItem:
    """단일 POAM item 을 PoamItem 으로 변환."""
    props = _extract_props(item)
    raw_risk = props.get("risk", "")
    status = props.get("implementation-status", "unknown")
    severity = _normalize_severity(raw_risk)
    if severity == "unknown":
        severity = STATUS_FALLBACK_SEVERITY.get(status, "medium")
    return PoamItem(
        uuid=str(item.get("uuid", "")),
        title=str(item.get("title", ""))[:120],
        severity=severity,
        status=status,
        closed=_is_closed(item),
        raw_risk=raw_risk,
    )


def parse_poam(path: Path) -> PoamSummary:
    """POAM JSON 파일을 파싱해 ``PoamSummary`` 반환.

    Args:
        path: ``uav-soc-poam.json`` 경로.

    Returns:
        파싱된 요약 객체 (open/closed 분리, 심각도별 카운트).

    Raises:
        PoamParseError: JSON 파싱 실패 또는 OSCAL 스키마 누락 시.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise PoamParseError(f"POAM 파일 없음: {path}") from e
    except json.JSONDecodeError as e:
        raise PoamParseError(f"POAM JSON 파싱 실패: {path}: {e}") from e

    if not _is_str_dict(raw):
        raise PoamParseError(f"POAM 루트가 객체가 아님: {type(raw).__name__}")

    root = raw.get("plan-of-action-and-milestones")
    if not _is_str_dict(root):
        raise PoamParseError(
            "OSCAL 스키마 위반: 루트에 'plan-of-action-and-milestones' 키 부재"
        )

    items_raw = root.get("poam-items", [])
    if not _is_list_of_dicts(items_raw):
        raise PoamParseError("'poam-items' 가 배열이 아님")

    summary = PoamSummary(total_items=len(items_raw))
    for item in items_raw:
        classified = _classify_item(item)
        if classified.closed:
            summary.closed_items.append(classified)
            continue
        if classified.severity in summary.counts:
            summary.counts[classified.severity] += 1
        summary.open_items.append(classified)
    return summary


# ─────────────────────────────────────────────────────────────────────────
# 게이트 평가
# ─────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Thresholds:
    """차단 임계값. 각 값은 '허용 최댓값' (≤)."""

    critical_max: int
    high_max: int
    medium_max: int
    low_max: int

    def violations(self, summary: PoamSummary) -> list[str]:
        """초과 항목을 사람이 읽을 수 있는 메시지 리스트로 반환."""
        msgs: list[str] = []
        if summary.critical > self.critical_max:
            msgs.append(
                f"critical 미해결 {summary.critical}건 > 허용 {self.critical_max}건"
            )
        if summary.high > self.high_max:
            msgs.append(
                f"high 미해결 {summary.high}건 > 허용 {self.high_max}건"
            )
        if summary.medium > self.medium_max:
            msgs.append(
                f"medium 미해결 {summary.medium}건 > 허용 {self.medium_max}건"
            )
        if summary.low > self.low_max:
            msgs.append(
                f"low 미해결 {summary.low}건 > 허용 {self.low_max}건"
            )
        return msgs


# ─────────────────────────────────────────────────────────────────────────
# 리포트 생성
# ─────────────────────────────────────────────────────────────────────────
def render_markdown(
    summary: PoamSummary,
    thresholds: Thresholds,
    violations: list[str],
    poam_path: Path,
) -> str:
    """Markdown 리포트 문자열을 생성."""
    verdict = "차단" if violations else "통과"
    lines: list[str] = []
    lines.append("# OSCAL POA&M 임계값 게이트 결과")
    lines.append("")
    lines.append(f"- **판정**: {verdict}")
    lines.append(f"- **POAM 파일**: `{poam_path}`")
    lines.append(
        f"- **총 항목**: {summary.total_items} "
        f"(open {len(summary.open_items)} / closed {len(summary.closed_items)})"
    )
    lines.append("")
    lines.append("## 미해결 카운트 vs 임계값")
    lines.append("")
    lines.append("| 심각도 | 미해결 | 허용 최대 | 상태 |")
    lines.append("|--------|--------|-----------|------|")
    for sev, allowed in (
        ("critical", thresholds.critical_max),
        ("high", thresholds.high_max),
        ("medium", thresholds.medium_max),
        ("low", thresholds.low_max),
    ):
        actual = summary.counts[sev]
        status = "OK" if actual <= allowed else "초과"
        lines.append(f"| {sev} | {actual} | {allowed} | {status} |")
    lines.append("")
    if violations:
        lines.append("## 차단 사유")
        lines.append("")
        for v in violations:
            lines.append(f"- {v}")
        lines.append("")
    lines.append("## 미해결 항목 (severity 내림차순)")
    lines.append("")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    sorted_items = sorted(
        summary.open_items, key=lambda it: order.get(it.severity, 9)
    )
    if not sorted_items:
        lines.append("(없음)")
    else:
        lines.append("| UUID | severity | status | 제목 |")
        lines.append("|------|----------|--------|------|")
        for it in sorted_items:
            short_uuid = it.uuid[:8] if it.uuid else "-"
            lines.append(
                f"| {short_uuid} | {it.severity} | {it.status} | {it.title} |"
            )
    lines.append("")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────
def _env_int(name: str, default: int) -> int:
    """환경변수에서 int 를 안전하게 읽는다."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _count_partial(summary: PoamSummary) -> int:
    """미해결 항목 중 ``implementation-status == partial`` 항목 수.

    Args:
        summary: 파싱된 POAM 요약.

    Returns:
        partial 상태 미해결 항목 수.
    """
    return sum(1 for it in summary.open_items if it.status == "partial")


def build_parser() -> argparse.ArgumentParser:
    """argparse 파서를 구성해 반환한다.

    Returns:
        ``--mode {warn,block}`` 와 ``--partial-warn N`` 옵션을 포함한 파서.
        구버전 워크플로 호환을 위해 ``--warn-only`` 는 deprecated 별칭으로 잔존.
    """
    p = argparse.ArgumentParser(
        description="OSCAL POA&M 임계값 게이트",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "poam_path",
        type=Path,
        nargs="?",
        default=Path("compliance/oscal/poam/uav-soc-poam.json"),
        help="POAM JSON 경로",
    )
    p.add_argument(
        "--critical-max",
        type=int,
        default=_env_int("OSCAL_POAM_CRITICAL_MAX", 0),
        help="critical 미해결 허용 최댓값",
    )
    p.add_argument(
        "--high-max",
        type=int,
        default=_env_int("OSCAL_POAM_HIGH_MAX", 3),
        help="high 미해결 허용 최댓값",
    )
    p.add_argument(
        "--medium-max",
        type=int,
        default=_env_int("OSCAL_POAM_MEDIUM_MAX", 9999),
        help="medium 미해결 허용 최댓값 (기본=경고만)",
    )
    p.add_argument(
        "--low-max",
        type=int,
        default=_env_int("OSCAL_POAM_LOW_MAX", 9999),
        help="low 미해결 허용 최댓값",
    )
    p.add_argument(
        "--report-md",
        type=Path,
        default=None,
        help="Markdown 리포트 출력 경로",
    )
    p.add_argument(
        "--report-json",
        type=Path,
        default=None,
        help="JSON 요약 출력 경로",
    )
    p.add_argument(
        "--mode",
        choices=("warn", "block"),
        default=os.environ.get("OSCAL_POAM_MODE", "block"),
        help=(
            "게이트 동작 모드. block=임계 초과 시 exit 1 (prod 기본), "
            "warn=경고만 출력하고 항상 exit 0 (PR/staging 용)."
        ),
    )
    p.add_argument(
        "--partial-warn",
        type=int,
        default=_env_int("OSCAL_POAM_PARTIAL_WARN", 25),
        help=(
            "partial 상태 미해결 항목이 N건을 초과하면 stderr 경고 (차단하지 않음). "
            "OSCAL NIST AI RMF 부분구현 누적 모니터링용."
        ),
    )
    p.add_argument(
        "--warn-only",
        action="store_true",
        help=(
            "[DEPRECATED] --mode warn 의 별칭. "
            "구버전 워크플로 호환용 — 신규 코드는 --mode 사용 권장."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    """엔트리포인트. argv 를 파싱하고 종료 코드를 반환한다.

    Args:
        argv: 명령행 인자. ``None`` 이면 ``sys.argv[1:]`` 사용.

    Returns:
        ``EXIT_OK`` / ``EXIT_FAIL`` / ``EXIT_ERROR`` 중 하나.
    """
    args = build_parser().parse_args(argv)

    # --warn-only (deprecated) → --mode warn 으로 정규화.
    effective_mode: str = args.mode
    if args.warn_only:
        if args.mode == "block":
            effective_mode = "warn"
        print(
            "[DEPRECATED] --warn-only 는 --mode warn 별칭으로 유지됩니다. "
            "신규 워크플로는 --mode warn 을 사용하세요.",
            file=sys.stderr,
        )

    thresholds = Thresholds(
        critical_max=args.critical_max,
        high_max=args.high_max,
        medium_max=args.medium_max,
        low_max=args.low_max,
    )
    try:
        summary = parse_poam(args.poam_path)
    except PoamParseError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return EXIT_ERROR

    violations = thresholds.violations(summary)
    partial_count = _count_partial(summary)
    partial_warned = partial_count > args.partial_warn

    # JSON 요약
    if args.report_json is not None:
        args.report_json.parent.mkdir(parents=True, exist_ok=True)
        args.report_json.write_text(
            json.dumps(
                {
                    **summary.to_dict(),
                    "thresholds": {
                        "critical_max": thresholds.critical_max,
                        "high_max": thresholds.high_max,
                        "medium_max": thresholds.medium_max,
                        "low_max": thresholds.low_max,
                        "partial_warn": args.partial_warn,
                    },
                    "mode": effective_mode,
                    "partial_count": partial_count,
                    "partial_warned": partial_warned,
                    "violations": violations,
                    "verdict": (
                        "block"
                        if violations and effective_mode == "block"
                        else ("warn" if violations else "pass")
                    ),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    # Markdown 리포트
    md = render_markdown(summary, thresholds, violations, args.poam_path)
    if args.report_md is not None:
        args.report_md.parent.mkdir(parents=True, exist_ok=True)
        args.report_md.write_text(md, encoding="utf-8")

    # 콘솔 출력
    print(md)
    print("---")

    # partial 경고 (차단 X)
    if partial_warned:
        print(
            f"[WARN] partial 상태 미해결 {partial_count}건 "
            f"> 임계 {args.partial_warn}건 "
            f"— NIST AI RMF 부분구현 누적 모니터링 필요",
            file=sys.stderr,
        )

    if violations:
        print(f"[GATE] 임계 초과: {len(violations)}건")
        for v in violations:
            print(f"  - {v}")
        if effective_mode == "warn":
            print("[GATE] --mode warn -> exit 0 (경고만)")
            return EXIT_OK
        print("[GATE] --mode block -> exit 1 (차단)")
        return EXIT_FAIL
    print("[GATE] 통과")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
