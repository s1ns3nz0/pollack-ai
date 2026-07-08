"""OSCAL JSON 산출물(SSP/POAM)을 Prometheus 메트릭으로 변환.

이 스크립트는 두 가지 출력 모드를 지원한다:

1. **Pushgateway 푸시 모드** (`--push-url`): nightly CronJob 에서 사용.
   `prometheus_client.push_to_gateway` 로 직접 전송한다.

2. **Textfile collector 모드** (`--textfile`): node_exporter textfile 디렉터리에
   `.prom` 파일을 작성한다. CronJob 대신 호스트 측 스케줄러용 폴백.

노출 메트릭 (3종 + 메타 1종):

- ``oscal_controls_total{status,framework}``         — implemented/partial/planned 카운트
- ``oscal_poam_open_total{severity,framework}``      — critical/high/medium/low (open 만)
- ``oscal_compliance_ratio{framework}``              — implemented / 채택 통제 총합
- ``oscal_last_build_timestamp{framework}``          — unix epoch (s)

라벨 카디널리티 통제:
    - 사용자/세션/통제 ID 라벨 금지 — 위 4개 라벨만 노출.
    - framework 는 현재 ``ai-rmf`` 1종.

참고:
    - SSP/POAM 스키마 출처: ``compliance/oscal/build_oscal.py`` (NIST OSCAL 1.1.2).
    - POAM open 판정: ``remediation-tracking.tracking-entries[]`` 의 마지막 엔트리에
      ``closed/completed/종결/완료/해결`` 키워드가 포함되면 closed 로 분류.
      (security-scanner ``check_poam_thresholds.py`` 와 동일 규칙)
    - 심각도 정규화: 한국어 ``심각/높음/중간/낮음`` ↔ 영어 ``critical/high/medium/low``.

사용 예시:
    # nightly CronJob (Pushgateway 모드):
    python oscal_to_metrics.py \\
        --oscal-dir compliance/oscal \\
        --push-url http://prometheus-pushgateway.monitoring.svc.cluster.local:9091 \\
        --job oscal-export

    # textfile 모드:
    python oscal_to_metrics.py \\
        --oscal-dir compliance/oscal \\
        --textfile /var/lib/node_exporter/textfile/oscal.prom
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TypeGuard

logger = logging.getLogger("oscal_to_metrics")


# ---------------------------------------------------------------------------
# 예외
# ---------------------------------------------------------------------------


class OSCALMetricsError(Exception):
    """OSCAL → 메트릭 변환 베이스 예외."""


class OSCALParseError(OSCALMetricsError):
    """OSCAL JSON 파싱 오류."""


class OSCALPushError(OSCALMetricsError):
    """Pushgateway 전송 오류."""


# ---------------------------------------------------------------------------
# 정규화 매핑 — check_poam_thresholds.py 와 정합
# ---------------------------------------------------------------------------

#: 한국어/영어 심각도 → 영어 정규형.
SEVERITY_ALIASES: dict[str, str] = {
    "critical": "critical",
    "심각": "critical",
    "high": "high",
    "높음": "high",
    "medium": "medium",
    "중간": "medium",
    "low": "low",
    "낮음": "low",
}

#: implementation-status → severity 폴백.
STATUS_FALLBACK_SEVERITY: dict[str, str] = {
    "planned": "high",
    "partial": "medium",
    "implemented": "low",
}

#: remediation-tracking 마지막 엔트리에 포함되면 closed 로 분류하는 키워드.
CLOSED_TRACKING_KEYWORDS: tuple[str, ...] = (
    "closed",
    "completed",
    "종결",
    "완료",
    "해결",
)

#: 노출 라벨에 사용하는 framework 식별자.
FRAMEWORK_ID: str = "ai-rmf"


# ---------------------------------------------------------------------------
# 타입 가드 (Any 금지 — Unknown + TypeGuard 패턴)
# ---------------------------------------------------------------------------


def _is_str_object_dict(val: object) -> TypeGuard[dict[str, object]]:
    """``dict[str, object]`` 여부를 안전하게 판정."""
    return isinstance(val, dict) and all(isinstance(k, str) for k in val)


def _is_list_of_dicts(val: object) -> TypeGuard[list[dict[str, object]]]:
    """``list[dict[str, object]]`` 여부 판정."""
    return isinstance(val, list) and all(_is_str_object_dict(v) for v in val)


# ---------------------------------------------------------------------------
# 결과 dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OSCALMetrics:
    """추출된 OSCAL 컴플라이언스 지표."""

    controls_by_status: dict[str, int]
    poam_open_by_severity: dict[str, int]
    compliance_ratio: float
    last_build_timestamp: int

    def total_adopted_controls(self) -> int:
        """채택된 통제 총합 (status 합).

        Returns:
            implemented + partial + planned 합계.
        """
        return sum(self.controls_by_status.values())


# ---------------------------------------------------------------------------
# 파서
# ---------------------------------------------------------------------------


def _normalize_severity(raw: str) -> str:
    """한국어/영어 심각도를 정규화.

    Args:
        raw: 원본 문자열.

    Returns:
        ``critical|high|medium|low`` 중 하나. 미인식 시 ``medium``.
    """
    return SEVERITY_ALIASES.get(
        raw.strip().lower(), SEVERITY_ALIASES.get(raw.strip(), "medium")
    )


def _is_closed(item: dict[str, object]) -> bool:
    """POAM 항목의 closed 여부 판정.

    Args:
        item: POAM Item dict.

    Returns:
        마지막 tracking-entry 의 title/description 에 closed 키워드가 있으면 True.
    """
    tracking = item.get("remediation-tracking")
    if not _is_str_object_dict(tracking):
        return False
    entries = tracking.get("tracking-entries")
    if not _is_list_of_dicts(entries) or not entries:
        return False
    last = entries[-1]
    text_parts: list[str] = []
    for key in ("title", "description"):
        val = last.get(key)
        if isinstance(val, str):
            text_parts.append(val.lower())
    text = " ".join(text_parts)
    return any(kw in text for kw in CLOSED_TRACKING_KEYWORDS)


def _severity_of_poam(item: dict[str, object]) -> str:
    """POAM 항목의 심각도 추출.

    1차로 ``props[name=risk]``, 폴백으로 ``props[name=implementation-status]``
    를 사용한다.

    Args:
        item: POAM Item dict.

    Returns:
        ``critical|high|medium|low``.
    """
    props = item.get("props")
    risk_value: str | None = None
    status_value: str | None = None
    if _is_list_of_dicts(props):
        for prop in props:
            name = prop.get("name")
            value = prop.get("value")
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            if name == "risk":
                risk_value = value
            elif name == "implementation-status":
                status_value = value
    if risk_value is not None:
        return _normalize_severity(risk_value)
    if status_value is not None:
        return STATUS_FALLBACK_SEVERITY.get(status_value.strip().lower(), "medium")
    return "medium"


def parse_ssp(ssp_path: Path) -> dict[str, int]:
    """SSP JSON 에서 implementation-status 분포 추출.

    Args:
        ssp_path: ``ssp/uav-soc-ssp.json`` 경로.

    Returns:
        ``{"implemented": N, "partial": N, "planned": N}``.

    Raises:
        OSCALParseError: JSON 파싱 실패 또는 구조 불일치.
    """
    try:
        with ssp_path.open(encoding="utf-8") as f:
            ssp = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise OSCALParseError(f"SSP 파싱 실패: {ssp_path} — {e}") from e

    counter: Counter[str] = Counter()

    def _walk(obj: object) -> None:
        if _is_str_object_dict(obj):
            if obj.get("name") == "implementation-status":
                val = obj.get("value")
                if isinstance(val, str):
                    counter[val.strip().lower()] += 1
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for v in obj:
                _walk(v)

    _walk(ssp)

    # 모든 키 보장 (없는 status 도 0 으로 노출 — 그래프 갭 방지)
    return {
        "implemented": counter.get("implemented", 0),
        "partial": counter.get("partial", 0),
        "planned": counter.get("planned", 0),
    }


def parse_poam(poam_path: Path) -> dict[str, int]:
    """POAM JSON 에서 open 항목의 severity 분포 추출.

    Args:
        poam_path: ``poam/uav-soc-poam.json`` 경로.

    Returns:
        ``{"critical": N, "high": N, "medium": N, "low": N}``.

    Raises:
        OSCALParseError: JSON 파싱 실패 또는 ``poam-items`` 키 부재.
    """
    try:
        with poam_path.open(encoding="utf-8") as f:
            poam = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise OSCALParseError(f"POAM 파싱 실패: {poam_path} — {e}") from e

    if not _is_str_object_dict(poam):
        raise OSCALParseError("POAM 최상위가 객체가 아닙니다.")
    plan = poam.get("plan-of-action-and-milestones")
    if not _is_str_object_dict(plan):
        raise OSCALParseError("POAM 에 'plan-of-action-and-milestones' 키 부재")
    items = plan.get("poam-items")
    if not _is_list_of_dicts(items):
        raise OSCALParseError("POAM 에 'poam-items' 배열 부재")

    severity_counter: Counter[str] = Counter()
    for item in items:
        if _is_closed(item):
            continue
        sev = _severity_of_poam(item)
        severity_counter[sev] += 1

    return {
        "critical": severity_counter.get("critical", 0),
        "high": severity_counter.get("high", 0),
        "medium": severity_counter.get("medium", 0),
        "low": severity_counter.get("low", 0),
    }


def compute_compliance_ratio(controls: dict[str, int]) -> float:
    """implemented / total 비율 계산.

    Args:
        controls: ``parse_ssp`` 결과.

    Returns:
        0.0 ~ 1.0. 분모 0 일 시 0.0.
    """
    total = sum(controls.values())
    if total == 0:
        return 0.0
    return controls.get("implemented", 0) / total


def collect_metrics(oscal_dir: Path) -> OSCALMetrics:
    """OSCAL 디렉터리에서 모든 메트릭 추출.

    Args:
        oscal_dir: ``compliance/oscal`` 루트 경로.

    Returns:
        ``OSCALMetrics`` 인스턴스.

    Raises:
        OSCALParseError: 필수 파일 부재 또는 파싱 실패.
    """
    ssp_path = oscal_dir / "ssp" / "uav-soc-ssp.json"
    poam_path = oscal_dir / "poam" / "uav-soc-poam.json"

    if not ssp_path.is_file():
        raise OSCALParseError(f"SSP 파일 부재: {ssp_path}")
    if not poam_path.is_file():
        raise OSCALParseError(f"POAM 파일 부재: {poam_path}")

    controls = parse_ssp(ssp_path)
    poam_open = parse_poam(poam_path)
    ratio = compute_compliance_ratio(controls)
    timestamp = int(time.time())

    return OSCALMetrics(
        controls_by_status=controls,
        poam_open_by_severity=poam_open,
        compliance_ratio=ratio,
        last_build_timestamp=timestamp,
    )


# ---------------------------------------------------------------------------
# 출력 (textfile / pushgateway)
# ---------------------------------------------------------------------------


def render_textfile(metrics: OSCALMetrics) -> str:
    """node_exporter textfile collector 형식 텍스트 생성.

    Args:
        metrics: 수집된 메트릭.

    Returns:
        Prometheus exposition 형식 문자열.
    """
    lines: list[str] = []
    lines.append(
        "# HELP oscal_controls_total Adopted AI RMF controls by implementation status."
    )
    lines.append("# TYPE oscal_controls_total gauge")
    for status, count in metrics.controls_by_status.items():
        lines.append(
            f'oscal_controls_total{{status="{status}",framework="{FRAMEWORK_ID}"}} {count}'
        )

    lines.append("")
    lines.append("# HELP oscal_poam_open_total Open POAM items by severity.")
    lines.append("# TYPE oscal_poam_open_total gauge")
    for severity, count in metrics.poam_open_by_severity.items():
        lines.append(
            f'oscal_poam_open_total{{severity="{severity}",framework="{FRAMEWORK_ID}"}} {count}'
        )

    lines.append("")
    lines.append("# HELP oscal_compliance_ratio Implemented / total adopted controls.")
    lines.append("# TYPE oscal_compliance_ratio gauge")
    lines.append(
        f'oscal_compliance_ratio{{framework="{FRAMEWORK_ID}"}} {metrics.compliance_ratio:.6f}'
    )

    lines.append("")
    lines.append(
        "# HELP oscal_last_build_timestamp Unix epoch (s) of last OSCAL build."
    )
    lines.append("# TYPE oscal_last_build_timestamp gauge")
    lines.append(
        f'oscal_last_build_timestamp{{framework="{FRAMEWORK_ID}"}} {metrics.last_build_timestamp}'
    )

    lines.append("")  # trailing newline
    return "\n".join(lines)


def push_to_gateway(metrics: OSCALMetrics, url: str, job: str) -> None:
    """Pushgateway 로 메트릭 전송.

    Args:
        metrics: 수집된 메트릭.
        url: ``http://prometheus-pushgateway...:9091``.
        job: pushgateway job 라벨.

    Raises:
        OSCALPushError: ``prometheus_client`` 미설치 또는 전송 실패.
    """
    try:
        from prometheus_client import CollectorRegistry, Gauge, push_to_gateway as _push
    except ImportError as e:
        raise OSCALPushError(
            "prometheus_client 미설치. `pip install prometheus_client` 필요."
        ) from e

    registry = CollectorRegistry()

    controls_gauge = Gauge(
        "oscal_controls_total",
        "Adopted AI RMF controls by implementation status.",
        ["status", "framework"],
        registry=registry,
    )
    for status, count in metrics.controls_by_status.items():
        controls_gauge.labels(status=status, framework=FRAMEWORK_ID).set(count)

    poam_gauge = Gauge(
        "oscal_poam_open_total",
        "Open POAM items by severity.",
        ["severity", "framework"],
        registry=registry,
    )
    for severity, count in metrics.poam_open_by_severity.items():
        poam_gauge.labels(severity=severity, framework=FRAMEWORK_ID).set(count)

    ratio_gauge = Gauge(
        "oscal_compliance_ratio",
        "Implemented / total adopted controls.",
        ["framework"],
        registry=registry,
    )
    ratio_gauge.labels(framework=FRAMEWORK_ID).set(metrics.compliance_ratio)

    timestamp_gauge = Gauge(
        "oscal_last_build_timestamp",
        "Unix epoch (s) of last OSCAL build.",
        ["framework"],
        registry=registry,
    )
    timestamp_gauge.labels(framework=FRAMEWORK_ID).set(metrics.last_build_timestamp)

    try:
        _push(url, job=job, registry=registry)
    except Exception as e:  # prometheus_client 가 던지는 urllib 오류 등
        raise OSCALPushError(f"Pushgateway 전송 실패: {url} — {e}") from e


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    """CLI 파서 빌드."""
    parser = argparse.ArgumentParser(
        description="OSCAL JSON → Prometheus 메트릭 변환",
    )
    parser.add_argument(
        "--oscal-dir",
        type=Path,
        default=Path("compliance/oscal"),
        help="OSCAL 산출물 루트 (기본: compliance/oscal)",
    )
    parser.add_argument(
        "--push-url",
        type=str,
        default=None,
        help="Pushgateway URL (예: http://prometheus-pushgateway.monitoring.svc.cluster.local:9091)",
    )
    parser.add_argument(
        "--job",
        type=str,
        default="oscal-export",
        help="Pushgateway job 라벨 (기본: oscal-export)",
    )
    parser.add_argument(
        "--textfile",
        type=Path,
        default=None,
        help="textfile collector 출력 경로. 미지정 시 stdout 또는 push 만.",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="로그 레벨 (기본: INFO)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI 엔트리.

    Args:
        argv: 인자 리스트 (None 일 시 sys.argv).

    Returns:
        종료 코드.
            - 0: 정상
            - 1: 파싱/푸시 오류
    """
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    try:
        metrics = collect_metrics(args.oscal_dir)
    except OSCALMetricsError as e:
        logger.error("OSCAL 메트릭 수집 실패: %s", e)
        return 1

    logger.info(
        "수집 결과: controls=%s poam_open=%s ratio=%.4f",
        metrics.controls_by_status,
        metrics.poam_open_by_severity,
        metrics.compliance_ratio,
    )

    text = render_textfile(metrics)

    if args.textfile is not None:
        try:
            args.textfile.parent.mkdir(parents=True, exist_ok=True)
            # node_exporter 권장 패턴 — 임시 파일 쓰고 rename (atomic).
            tmp_path = args.textfile.with_suffix(args.textfile.suffix + ".tmp")
            tmp_path.write_text(text, encoding="utf-8")
            tmp_path.replace(args.textfile)
            logger.info("textfile 출력: %s", args.textfile)
        except OSError as e:
            logger.error("textfile 쓰기 실패: %s", e)
            return 1
    elif args.push_url is None:
        # 둘 다 미지정 — stdout 으로 출력 (디버깅 용도).
        sys.stdout.write(text)

    if args.push_url is not None:
        try:
            push_to_gateway(metrics, args.push_url, args.job)
            logger.info("Pushgateway 전송 성공: %s (job=%s)", args.push_url, args.job)
        except OSCALPushError as e:
            logger.error("%s", e)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
