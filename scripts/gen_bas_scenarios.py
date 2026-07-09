#!/usr/bin/env python3
"""dah-sentinel-content 배포 룰(AnalyticsRules/S*.json + C*.json)에서
core/policy/bas-scenarios.yaml 항목을 자동 추출한다.

dah-sentinel-content 쪽에서 시나리오 재정렬/신규 룰 추가가 있을 때마다
이 스크립트를 재실행해 카탈로그를 동기화한다.

추출 규칙(전부 기계적 — 소스 JSON에서 그대로 유도):
  id            : 파일명 stem을 kebab-case로 변환 (예: S34_Operator_BruteForce -> S34-OPERATOR-BRUTEFORCE)
  name          : displayName에서 "UAV S<n> - " 접두 제거
  signals       : description에서 "실제 컬럼:"/"MITRE" 메타데이터 이전 부분을 문장 단위로 분리(최대 3개)
  detection_rule: 원본 파일명
  tactic        : tactics[] 배열의 첫 번째 값(대표 전술)
  stride        : displayName+description 키워드 매칭(휴리스틱 — 결과는 수동 검수 권장)
  campaign      : C1~C33 캠페인 description의 "(S<n>)" 패턴을 역매핑
  status        : MaGMA UCF 라이프사이클(planned/deployed/deprecated) — 아래 참고

campaign 필드는 캠페인 JSON을 별도 카탈로그 항목으로 만들지 않고(기존 스키마 컨벤션 유지),
시나리오 항목의 참조 필드로만 채운다.

status(MaGMA UCF 라이프사이클) 병합 규칙 — 재실행해도 수동 이력이 안 사라지게:
  - 스캔되는 파일은 전부 실배포 상태이므로 기본값 "deployed".
  - 단, 기존 출력 YAML에 이미 "deprecated"로 표시된 id 는 그 값을 그대로 보존
    (재정렬로 재스캔돼도 사람이 수동으로 내린 폐기 판정을 덮어쓰지 않는다).
  - 기존 YAML에는 있었는데 이번 스캔에 없는 id(소스 JSON 삭제됨)는 항목 자체를
    카탈로그에서 지우지 않고 마지막 상태 그대로 캐리포워드한다(폐기 이력 보존).
  - "planned"(아직 룰 파일이 없는 계획 단계)는 스크립트가 만들지 않는다 — 스캔
    대상 자체가 "파일이 존재하는" 것들이라 필연적으로 deployed. planned 항목은
    사람이 YAML에 직접 추가하고, 이후 실제 파일이 생기면 재실행 시 deployed로
    자동 전환된다(단, 그 사이 deprecated로 바뀐 적 없을 때만).

실행: python scripts/gen_bas_scenarios.py <dah-sentinel-content 경로> [--out core/policy/bas-scenarios.yaml]
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_STRIDE_KEYWORDS = {
    "S": ["스푸핑", "spoof", "위조", "가장", "forge", "forgery"],
    "T": ["변조", "tamper", "조작", "주입", "injection", "무결성", "manipulat", "우회", "bypass"],
    "R": ["삭제", "파괴", "destruction", "증거인멸", "anti-forensic", "은폐", "로그 조작"],
    "I": [
        "유출", "exfil", "노출", "수집", "collection", "정찰", "recon", "스캔", "scan",
        "인터셉트", "intercept", "도청", "추출", "extraction",
    ],
    "D": ["dos", "flood", "과부하", "kill", "중단", "차단", "suppress", "resource", "포화", "saturation"],
    "E": [
        "권한", "privilege", "escalation", "비인가", "unauthorized", "2인통제",
        "self-approval", "selfapproval", "자기승인",
    ],
}

_META_MARKERS = ["실제 컬럼:", "MITRE ICS ATT&CK:", "MITRE:"]


def _slug_id(stem: str) -> str:
    m = re.match(r"^([SC]\d+)_(.+)$", stem)
    if not m:
        return stem.upper()
    num, rest = m.groups()
    slug = re.sub(r"[^A-Za-z0-9]+", "-", rest).strip("-").upper()
    return f"{num}-{slug}"


def _clean_name(display_name: str, num: str) -> str:
    return re.sub(rf"^UAV\s+{num}\s*-\s*", "", display_name).strip()


def _signals(description: str) -> list[str]:
    text = description
    for marker in _META_MARKERS:
        idx = text.find(marker)
        if idx != -1:
            text = text[:idx]
    # 소수점(예: "1.5")·점표기 식별자(예: "List.OffHoursStart")는 문장 구분자로 취급하지
    # 않는다 — 뒤에 공백이 최소 1개 오는 마침표/개행만 문장 경계로 인정.
    parts = [s.strip() for s in re.split(r"(?<!\d)\.(?!\d)\s+|\n\s*", text) if s.strip()]
    return parts[:3] or [text.strip()[:120]]


def _stride(display_name: str, description: str) -> list[str]:
    haystack = f"{display_name} {description}".lower()
    letters = [ltr for ltr, kws in _STRIDE_KEYWORDS.items() if any(kw in haystack for kw in kws)]
    return letters or ["T"]  # 매칭 없으면 Tampering 기본값(대부분 조작/주입류)


def _load_properties(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["resources"][0]["properties"]


def build(rules_dir: Path) -> list[dict]:
    """AnalyticsRules 디렉토리에서 시나리오 카탈로그 항목을 추출한다."""
    scenario_files = sorted(
        rules_dir.glob("S*.json"), key=lambda p: int(re.match(r"S(\d+)", p.stem).group(1))
    )
    campaign_files = sorted(
        rules_dir.glob("C*.json"), key=lambda p: int(re.match(r"C(\d+)", p.stem).group(1))
    )

    scenario_to_campaigns: dict[str, list[str]] = {}
    for cf in campaign_files:
        props = _load_properties(cf)
        cnum = re.match(r"(C\d+)", cf.stem).group(1)
        for snum in re.findall(r"\(S(\d+)\)", props.get("description", "")):
            scenario_to_campaigns.setdefault(f"S{snum}", []).append(cnum)

    entries = []
    for sf in scenario_files:
        props = _load_properties(sf)
        num = re.match(r"(S\d+)", sf.stem).group(1)
        display_name = props.get("displayName", "")
        description = props.get("description", "")
        tactics = props.get("tactics") or ["Execution"]
        entries.append(
            {
                "id": _slug_id(sf.stem),
                "name": _clean_name(display_name, num),
                "status": "deployed",  # 스캔된 파일 = 실배포. merge_with_existing 이 보정.
                "signals": _signals(description),
                "detection_rule": sf.name,
                "tactic": tactics[0],
                "stride": _stride(display_name, description),
                "campaign": scenario_to_campaigns.get(num, []),
            }
        )
    return entries


def merge_with_existing(entries: list[dict], existing_path: Path) -> list[dict]:
    """이전 출력 YAML과 병합 — deprecated 보존 + 소스 사라진 항목 캐리포워드.

    Args:
        entries: 이번 스캔으로 새로 빌드한 항목(전부 status="deployed").
        existing_path: 이전에 생성된 bas-scenarios.yaml 경로(없으면 그대로 반환).

    Returns:
        병합된 항목 목록(새 항목 + 캐리포워드된 orphan 항목).
    """
    if not existing_path.is_file():
        return entries

    import yaml as _yaml

    existing = _yaml.safe_load(existing_path.read_text(encoding="utf-8")) or {}
    existing_by_id = {s["id"]: s for s in existing.get("scenarios", []) if isinstance(s, dict)}

    new_ids = {e["id"] for e in entries}
    for e in entries:
        prior = existing_by_id.get(e["id"])
        if prior and prior.get("status") == "deprecated":
            e["status"] = "deprecated"  # 수동 폐기 판정은 재스캔으로 안 덮어씀

    # 이번 스캔에 없는(소스 JSON 삭제된) 기존 항목은 마지막 상태 그대로 캐리포워드.
    orphans = [s for sid, s in existing_by_id.items() if sid not in new_ids]
    return entries + orphans


def render_yaml(entries: list[dict]) -> str:
    """추출 결과를 프로젝트 컨벤션 스타일(flow-list) YAML 텍스트로 렌더링한다."""

    def q(s: str) -> str:
        return json.dumps(s, ensure_ascii=False)

    def flow(items: list[str], quote: bool = True) -> str:
        if not items:
            return "[]"
        return "[" + ", ".join(q(i) if quote else i for i in items) + "]"

    lines = [
        "# " + "=" * 77,
        "# BAS(Breach & Attack Simulation) 시나리오 세트 — 방어 상시 검증",
        "# " + "-" * 77,
        '# "우리 탐지룰이 진짜 이 공격을 막나" 를 결정론으로 상시 검증한다. 각 공격 케이스를',
        "# 방어 판정(신호 존재 + 매칭 탐지룰 존재)에 통과시켜 탐지 성공/미탐(gap)을 집계하고,",
        "# tactic·STRIDE 별 커버리지를 산출한다. detection_rule 이 비면 = 미탐 갭(방어 공백).",
        "#",
        "# 출처: dah-sentinel-content AnalyticsRules/*.json — scripts/gen_bas_scenarios.py 로",
        "# 자동 추출(재정렬/신규 룰 추가 시 재실행). stride 는 키워드 휴리스틱이라 검수 권장.",
        '# campaign 은 C1~C33 description의 "(S<n>)" 참조를 역매핑.',
        "# tactic 키는 data/attack_coverage.yaml tactic 이름과 일치(PascalCase).",
        "# " + "=" * 77,
        "",
        "version: 0.3",
        "owner: 황준식",
        "",
        "scenarios:",
    ]
    def sort_key(e: dict) -> tuple[int, str]:
        m = re.match(r"S(\d+)", e["id"])
        return (int(m.group(1)) if m else 0, e["id"])

    for e in sorted(entries, key=sort_key):
        rule = e.get("detection_rule") or ""
        lines.append(f"  - id: {e['id']}")
        lines.append(f"    name: {q(e['name'])}")
        lines.append(f"    status: {e.get('status', 'deployed')}")
        lines.append(f"    signals: {flow(e['signals'])}")
        lines.append(f"    detection_rule: {q(rule) if not rule else rule}")
        lines.append(f"    tactic: {e['tactic']}")
        lines.append(f"    stride: {flow(e['stride'], quote=False)}")
        if e.get("campaign"):
            lines.append(f"    campaign: {flow(e['campaign'], quote=False)}")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rules_dir", type=Path, help="dah-sentinel-content 저장소 경로")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "core" / "policy" / "bas-scenarios.yaml",
        help="출력 경로(기본: core/policy/bas-scenarios.yaml)",
    )
    args = parser.parse_args()

    analytics_dir = args.rules_dir / "AnalyticsRules"
    entries = build(analytics_dir)
    scanned = len(entries)
    entries = merge_with_existing(entries, args.out)
    orphaned = len(entries) - scanned
    args.out.write_text(render_yaml(entries), encoding="utf-8")
    with_campaign = sum(1 for e in entries if e.get("campaign"))
    print(
        f"{scanned}개 스캔 + {orphaned}개 캐리포워드(orphan) = {len(entries)}개 → {args.out} "
        f"(캠페인 연결 {with_campaign}개)"
    )


if __name__ == "__main__":
    main()
