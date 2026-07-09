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
from typing import Literal

import yaml

from core.exceptions import HypothesisCatalogError, PolicyError
from core.models import (
    Alert,
    EvidenceEntry,
    HypothesisAssessment,
    InvestigationResult,
    TiVerdict,
)
from core.severity import POLICY_DIR, load_yaml
from utils.logging import get_logger

_logger = get_logger("hypothesis")
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
    direction: Literal["consistent", "inconsistent"]
    weight: float

    def matches(self, value: float) -> bool:
        """정규화 증거값이 조건을 만족하는지.

        Args:
            value: `extract_evidence()` 가 산출한 증거 수치.

        Returns:
            카탈로그 조건식이 참이면 True.
        """
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
        threshold = float(num)
        if threshold <= 0.0:
            raise HypothesisCatalogError(
                f"조건식 `key>=n` 의 n 은 0보다 커야 함: {expr!r}"
            )
        return key, ">=", threshold
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
            부재 등 스키마 위반, 또는 YAML top-level 이 매핑이 아닌 경우(단일
            예외 계약 — `core.severity.load_yaml` 의 `PolicyError` 를 흡수).
    """
    try:
        data = load_yaml(path or POLICY_DIR / "hypothesis-catalog.yaml")
    except (OSError, PolicyError, yaml.YAMLError) as exc:
        raise HypothesisCatalogError(f"카탈로그 YAML 형식 오류: {exc}") from exc
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


def extract_evidence(
    result: InvestigationResult,
    alert: Alert,
    actor_ttp_overlap: bool = False,
) -> dict[str, float]:
    """조사 산출물 + 경보 플래그를 증거값으로 정규화.

    bool 계열은 0.0/1.0, count/level/probability 는 원값(스코어링에서
    `min(1.0, 강도)` 로 캡). `airspace_hostile` 은 기존 confidence 보강 조건
    (hostile + 10km 이내)과 동일 기준 — 증거 정의의 이중 표준 방지.

    Args:
        result: investigation 11단계 산출물.
        alert: 경보(pre-investigation enrichment 플래그 포함).
        actor_ttp_overlap: run() 의 actor 상위 TTP 교집합 여부(결과 미보존 신호).

    Returns:
        `EVIDENCE_KEYS` 전 키를 포함한 증거값 딕셔너리.
    """
    return {
        "ti_malicious_count": float(
            sum(1 for f in result.ti_findings if f.verdict is TiVerdict.MALICIOUS)
        ),
        "sandbox_malicious": float(
            any(r.verdict is TiVerdict.MALICIOUS for r in result.sandbox_reports)
        ),
        "kev_present": float(any(v.known_exploited for v in result.vuln_findings)),
        "gnss_jam_level": float(
            max((f.level for f in result.gnss_jam_findings), default=0)
        ),
        "airspace_hostile": float(
            any(f.hostile and f.distance_km <= 10.0 for f in result.airspace_findings)
        ),
        "actor_ttp_overlap": float(actor_ttp_overlap),
        "prediction_match": float(alert.prediction_match),
        "experience_corroboration": float(result.experience_corroboration),
        "suppression_corroboration": float(result.suppression_corroboration),
        "trusted_chunk_coverage": float(len(result.similar_cases)),
        "decoy_hit": float(alert.decoy_hit),
        "key_terrain": float(alert.key_terrain),
        "kill_chain_advanced": float(alert.kill_chain_advanced),
        "prediction_probability": max(
            (p.probability for p in result.predictions), default=0.0
        ),
    }


class AchEvaluator:
    """카탈로그 기반 ACH 평가기 — 순수 결정론, IO 없음.

    반증 최소 승자: `inconsistency` 오름차순, `consistency` 내림차순, id
    사전순. 점수는 소수 4자리 반올림 후 비교해 float 누적오차로 인한 순위 요동을
    막는다.
    """

    def __init__(self, catalog: tuple[HypothesisDef, ...]) -> None:
        """평가할 가설 카탈로그를 보관한다.

        Args:
            catalog: `load_hypothesis_catalog()` 가 반환한 가설 정의 튜플.
        """
        self._catalog = catalog

    def evaluate(self, evidence: dict[str, float]) -> list[HypothesisAssessment]:
        """증거값으로 전 가설을 평가하고 순위를 부여한다.

        Args:
            evidence: `extract_evidence` 산출 증거값(키→정규화 값).

        Returns:
            rank 오름차순 정렬 결과. 매칭 증거가 전무하면 전 가설 rank=None
            (카탈로그 선언 순). 개별 가설 평가 실패는 해당 가설만 제외한다.
        """
        assessments: list[HypothesisAssessment] = []
        key_hits: dict[str, int] = {}
        key_dirs: dict[str, set[str]] = {}
        for hyp in self._catalog:
            try:
                assessment = self._evaluate_hypothesis(hyp, evidence)
            except Exception:  # noqa: BLE001 — 가설 단위 격리(전체 소실 금지)
                _logger.warning(
                    "가설 %s 평가 실패 — 해당 가설만 제외",
                    hyp.hypothesis_id,
                    exc_info=True,
                )
                continue
            assessments.append(assessment)
            seen_keys: set[str] = set()
            for entry in assessment.ledger:
                if entry.key not in seen_keys:
                    seen_keys.add(entry.key)
                    key_hits[entry.key] = key_hits.get(entry.key, 0) + 1
                key_dirs.setdefault(entry.key, set()).add(entry.direction)

        self._mark_nondiagnostic(assessments, key_hits, key_dirs)
        if not any(a.ledger for a in assessments):
            return assessments

        ordered = sorted(
            assessments,
            key=lambda a: (a.inconsistency, -a.consistency, a.hypothesis_id),
        )
        for rank, assessment in enumerate(ordered, start=1):
            assessment.rank = rank
        return ordered

    def _evaluate_hypothesis(
        self, hyp: HypothesisDef, evidence: dict[str, float]
    ) -> HypothesisAssessment:
        """단일 가설을 평가한다.

        Args:
            hyp: 평가할 가설 정의.
            evidence: 정규화 증거값.

        Returns:
            순위 미부여 상태의 평가 결과.
        """
        ledger: list[EvidenceEntry] = []
        for rule in hyp.rules:
            value = evidence.get(rule.key, 0.0)
            if not rule.matches(value):
                continue
            ledger.append(
                EvidenceEntry(
                    key=rule.key,
                    value=value,
                    direction=rule.direction,
                    weight=rule.weight,
                )
            )
        consistency = round(
            sum(
                e.weight * min(1.0, e.value)
                for e in ledger
                if e.direction == "consistent"
            ),
            _SCORE_NDIGITS,
        )
        inconsistency = round(
            sum(
                e.weight * min(1.0, e.value)
                for e in ledger
                if e.direction == "inconsistent"
            ),
            _SCORE_NDIGITS,
        )
        return HypothesisAssessment(
            hypothesis_id=hyp.hypothesis_id,
            name=hyp.name,
            consistency=consistency,
            inconsistency=inconsistency,
            ledger=ledger,
        )

    def _mark_nondiagnostic(
        self,
        assessments: list[HypothesisAssessment],
        key_hits: dict[str, int],
        key_dirs: dict[str, set[str]],
    ) -> None:
        """전 가설에 같은 방향으로만 걸린 증거를 비변별로 표시한다.

        Args:
            assessments: 평가 성공한 가설 결과.
            key_hits: 증거 키별 매칭 가설 수.
            key_dirs: 증거 키별 매칭 방향 집합.
        """
        total = len(assessments)
        nondiagnostic = {
            key
            for key, hits in key_hits.items()
            if total > 1 and hits == total and len(key_dirs[key]) == 1
        }
        for assessment in assessments:
            for entry in assessment.ledger:
                if entry.key in nondiagnostic:
                    entry.diagnostic = False
