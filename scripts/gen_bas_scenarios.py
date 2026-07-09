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

campaign 필드는 캠페인 JSON을 별도 카탈로그 항목으로 만들지 않고(기존 스키마 컨벤션 유지),
시나리오 항목의 참조 필드로만 채운다.

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
                "signals": _signals(description),
                "detection_rule": sf.name,
                "tactic": tactics[0],
                "stride": _stride(display_name, description),
                "campaign": scenario_to_campaigns.get(num, []),
            }
        )
    return entries


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
    for e in entries:
        lines.append(f"  - id: {e['id']}")
        lines.append(f"    name: {q(e['name'])}")
        lines.append(f"    signals: {flow(e['signals'])}")
        lines.append(f"    detection_rule: {e['detection_rule']}")
        lines.append(f"    tactic: {e['tactic']}")
        lines.append(f"    stride: {flow(e['stride'], quote=False)}")
        if e["campaign"]:
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
    args.out.write_text(render_yaml(entries), encoding="utf-8")
    with_campaign = sum(1 for e in entries if e["campaign"])
    print(f"{len(entries)}개 시나리오 추출 → {args.out} (캠페인 연결 {with_campaign}개)")


if __name__ == "__main__":
    main()
