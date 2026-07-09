"""ACH 경쟁가설 평가 — 조사 신호의 지지/반증 재구조화.

Heuer ACH: 가설은 지지의 양이 아니라 반증의 부재로 선별한다. 카탈로그
(`core/policy/hypothesis-catalog.yaml`)의 경쟁가설(귀무가설 필수)에 대해 조사
11단계 산출물을 증거로 정규화하고 지지/반증 원장·순위를 산출한다. **비권위
참고정보** — confidence 산식·validation 라우팅에 관여하지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from core.exceptions import HypothesisCatalogError
from core.severity import POLICY_DIR, load_yaml

NULL_HYPOTHESIS_ID = "HYP-BENIGN-ENV"
_ID_RE = re.compile(r"^HYP-[A-Z0-9-]+$")
# 3형태 고정: `key` / `key>0` / `key>=n` (n 은 음이 아닌 십진수)
_COND_RE = re.compile(r"^([a-z_][a-z0-9_]*)(?:>(=?)(\d+(?:\.\d+)?))?$")
_SCORE_NDIGITS = 4

EVIDENCE_KEYS: frozenset[str] = frozenset(
    {
        "ti_malicious_count",
        "sandbox_malicious",
        "kev_present",
        "gnss_jam_level",
        "airspace_hostile",
        "actor_ttp_overlap",
        "prediction_match",
        "experience_corroboration",
        "suppression_corroboration",
        "trusted_chunk_coverage",
        "decoy_hit",
        "key_terrain",
        "kill_chain_advanced",
        "prediction_probability",
    }
)


@dataclass(frozen=True)
class EvidenceRule:
    """카탈로그 증거 룰 하나(파싱 완료 형태)."""

    key: str
    op: str  # ">" | ">="
    threshold: float
    direction: str  # "consistent" | "inconsistent"
    weight: float

    def matches(self, value: float) -> bool:
        """정규화 증거값이 조건을 만족하는지."""
        if self.op == ">":
            return value > self.threshold
        return value >= self.threshold


@dataclass(frozen=True)
class HypothesisDef:
    """경쟁가설 정의(카탈로그 한 항목)."""

    hypothesis_id: str
    name: str
    mitre: tuple[str, ...]
    rules: tuple[EvidenceRule, ...]


def _parse_condition(expr: str) -> tuple[str, str, float]:
    """조건식 3형태를 (key, op, threshold) 로 파싱.

    Args:
        expr: `key` / `key>0` / `key>=n` 중 하나.

    Returns:
        (증거 키, 비교 연산자, 임계값).

    Raises:
        HypothesisCatalogError: 3형태 밖 문법 또는 미지의 증거 키.
    """
    m = _COND_RE.match(expr.strip())
    if m is None:
        raise HypothesisCatalogError(f"조건식 문법 오류: {expr!r}")
    key, eq, num = m.group(1), m.group(2), m.group(3)
    if key not in EVIDENCE_KEYS:
        raise HypothesisCatalogError(f"미지의 증거 키: {key!r}")
    if num is None:
        return key, ">", 0.0  # truthy
    if eq == "=":
        return key, ">=", float(num)
    if num != "0":
        raise HypothesisCatalogError(f"조건식 `key>n` 은 n=0 만 허용: {expr!r}")
    return key, ">", 0.0


def _parse_rule(expr: str, spec: object) -> EvidenceRule:
    """증거 룰 하나 파싱 — direction 정확히 하나 + 가중치 범위 검증."""
    key, op, threshold = _parse_condition(expr)
    if not isinstance(spec, dict) or len(spec) != 1:
        raise HypothesisCatalogError(
            f"룰 {expr!r}: consistent/inconsistent 중 정확히 하나만 선언"
        )
    direction, weight_raw = next(iter(spec.items()))
    if direction not in ("consistent", "inconsistent"):
        raise HypothesisCatalogError(
            f"룰 {expr!r}: consistent/inconsistent 중 정확히 하나만 선언"
        )
    if not isinstance(weight_raw, (int, float)) or isinstance(weight_raw, bool):
        raise HypothesisCatalogError(f"룰 {expr!r}: 가중치는 수치여야 함")
    weight = float(weight_raw)
    if not 0.0 < weight <= 1.0:
        raise HypothesisCatalogError(f"룰 {expr!r}: 가중치 범위 위반(0<w<=1): {weight}")
    return EvidenceRule(
        key=key, op=op, threshold=threshold, direction=direction, weight=weight
    )


def load_hypothesis_catalog(path: Path | None = None) -> tuple[HypothesisDef, ...]:
    """가설 카탈로그 YAML 로드 + 스키마 검증(fail-fast).

    Args:
        path: 카탈로그 경로. 생략 시 `core/policy/hypothesis-catalog.yaml`.

    Returns:
        선언 순서를 보존한 가설 정의 튜플.

    Raises:
        HypothesisCatalogError: 목록 형식·id 패턴/중복·조건식·가중치·귀무가설
            부재 등 스키마 위반.
    """
    data = load_yaml(path or POLICY_DIR / "hypothesis-catalog.yaml")
    raw = data.get("hypotheses")
    if not isinstance(raw, list) or not raw:
        raise HypothesisCatalogError("hypotheses 목록이 비었거나 형식 오류")
    defs: list[HypothesisDef] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise HypothesisCatalogError(f"가설 항목 형식 오류: {entry!r}")
        hid = entry.get("id")
        name = entry.get("name")
        if not isinstance(hid, str) or _ID_RE.match(hid) is None:
            raise HypothesisCatalogError(f"가설 id 패턴 위반: {hid!r}")
        if hid in seen:
            raise HypothesisCatalogError(f"가설 id 중복: {hid}")
        seen.add(hid)
        if not isinstance(name, str) or not name:
            raise HypothesisCatalogError(f"가설 {hid}: name 필수")
        mitre_raw = entry.get("mitre", [])
        mitre = tuple(str(t) for t in mitre_raw) if isinstance(mitre_raw, list) else ()
        evidence = entry.get("evidence")
        if not isinstance(evidence, dict) or not evidence:
            raise HypothesisCatalogError(f"가설 {hid}: evidence 필수")
        rules = tuple(_parse_rule(str(k), v) for k, v in evidence.items())
        defs.append(
            HypothesisDef(hypothesis_id=hid, name=name, mitre=mitre, rules=rules)
        )
    if NULL_HYPOTHESIS_ID not in seen:
        raise HypothesisCatalogError(
            f"귀무가설 {NULL_HYPOTHESIS_ID} 부재 — 경쟁 구도 없는 ACH 금지"
        )
    return tuple(defs)
