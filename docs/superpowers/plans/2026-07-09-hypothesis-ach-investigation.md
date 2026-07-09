# 가설 기반 조사(ACH층) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Investigation agent 의 11단계 조사 산출물을 경쟁가설(ACH) 지지/반증 매트릭스로 재구조화해 `InvestigationResult.hypothesis_assessments` 로 산출한다 (비권위 참고정보).

**Architecture:** 신규 `core/hypothesis.py`(정규화 + 카탈로그 로더 + AchEvaluator, 순수 결정론) + `core/policy/hypothesis-catalog.yaml`(경쟁가설 7개, 귀무가설 필수). investigation run() 말미 1블록에서 광역 격리 호출. confidence·라우팅·기존 필드 불변.

**Tech Stack:** Python 3.11+, pydantic v2, PyYAML(`core.severity.load_yaml` 재사용), pytest.

**Spec:** `docs/superpowers/specs/2026-07-09-hypothesis-ach-investigation-design.md`

**불가침(충돌 회피):** `core/cacao.py` · `core/policy/cacao-playbooks.yaml` · `core/policy/recovery-matrix.yaml` · `agents/response_agent.py` · `core/correlation.py` · `agents/graph.py` · `_confidence` 산식.

---

### Task 1: 예외 + 모델 (additive)

**Files:**
- Modify: `core/exceptions.py` (PolicyError 클래스 바로 아래 삽입 — 파일 말단 금지, 옆 세션 append 충돌 회피)
- Modify: `core/models.py:273` (InvestigationResult 직전에 신규 모델 2개, InvestigationResult 말미 필드 1개)
- Test: `tests/__tests__/test_hypothesis.py` (신규)

- [ ] **Step 1: Write the failing test**

`tests/__tests__/test_hypothesis.py` 생성:

```python
"""ACH 가설 평가(core/hypothesis.py) 단위 테스트."""

from core.exceptions import HypothesisCatalogError, SOCPlatformError
from core.models import EvidenceEntry, HypothesisAssessment, InvestigationResult


class TestModels:
    def test_hypothesis_catalog_error_is_soc_error(self) -> None:
        assert issubclass(HypothesisCatalogError, SOCPlatformError)

    def test_assessment_defaults(self) -> None:
        a = HypothesisAssessment(hypothesis_id="HYP-X", name="x")
        assert a.rank is None
        assert a.consistency == 0.0
        assert a.inconsistency == 0.0
        assert a.ledger == []

    def test_evidence_entry_fields(self) -> None:
        e = EvidenceEntry(
            key="ti_malicious_count", value=2.0, direction="consistent", weight=0.7
        )
        assert e.diagnostic is True

    def test_investigation_result_has_assessments_field(self) -> None:
        r = InvestigationResult()
        assert r.hypothesis_assessments == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/__tests__/test_hypothesis.py -v`
Expected: FAIL — `ImportError: cannot import name 'HypothesisCatalogError'`

- [ ] **Step 3: Implement**

`core/exceptions.py` — `class PolicyError` 정의 바로 아래(중간 삽입):

```python
class HypothesisCatalogError(SOCPlatformError):
    """ACH 가설 카탈로그(hypothesis-catalog.yaml) 로드/스키마 오류."""
```

`core/models.py` — `class InvestigationResult` 바로 위에 삽입:

```python
class EvidenceEntry(BaseModel):
    """ACH 원장 한 줄 — 매칭된 증거의 방향·가중치·변별력.

    Attributes:
        key: 증거 키(`core.hypothesis.EVIDENCE_KEYS` 폐쇄 집합).
        value: 정규화 값(bool 계열 0.0/1.0, count/level/prob 은 원값).
        direction: 가설 지지(consistent) / 반증(inconsistent).
        weight: 카탈로그 선언 가중치(0.0 < w <= 1.0).
        diagnostic: 변별력 — 활성 가설 전부에 같은 방향으로만 걸리면 False.
    """

    key: str
    value: float
    direction: Literal["consistent", "inconsistent"]
    weight: float
    diagnostic: bool = True


class HypothesisAssessment(BaseModel):
    """경쟁가설 하나의 ACH 평가 결과(비권위 참고정보).

    ACH: 반증(inconsistency) 최소가 승자. rank 는 1부터, 매칭 증거가 전무하면
    None(근거 없는 순위 금지 — 정직성 불변식).
    """

    hypothesis_id: str
    name: str
    consistency: float = 0.0
    inconsistency: float = 0.0
    rank: int | None = None
    ledger: list[EvidenceEntry] = Field(default_factory=list)
```

`typing` 임포트에 `Literal` 이 없으면 추가 (`from typing import Literal` — 기존 typing 임포트 라인에 병합).

`InvestigationResult` 필드 말미(`predictions` 아래)에 추가:

```python
    hypothesis_assessments: list[HypothesisAssessment] = Field(
        default_factory=list,
        description="ACH 경쟁가설 평가(비권위 참고정보 — confidence/라우팅 불변).",
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/__tests__/test_hypothesis.py -v`
Expected: 4 PASS

- [ ] **Step 5: 기존 스위트 회귀 확인 + Commit**

Run: `pytest -q` → 전건 PASS (baseline 1188 + 4)

```bash
git add core/exceptions.py core/models.py tests/__tests__/test_hypothesis.py
git commit -m "feat(analysis): ACH 가설 모델 + 카탈로그 예외 — additive 전용"
```

---

### Task 2: 카탈로그 YAML + DSL 파서 + 로더

**Files:**
- Create: `core/policy/hypothesis-catalog.yaml`
- Create: `core/hypothesis.py` (로더 파트)
- Test: `tests/__tests__/test_hypothesis.py` (추가)

- [ ] **Step 1: Write the failing tests**

`test_hypothesis.py` 에 추가:

```python
from pathlib import Path

import pytest

from core.hypothesis import (
    EVIDENCE_KEYS,
    NULL_HYPOTHESIS_ID,
    load_hypothesis_catalog,
)

_VALID_YAML = """
hypotheses:
  - id: HYP-A
    name: "가설 A"
    mitre: ["T1600"]
    evidence:
      "gnss_jam_level>=2": {consistent: 0.9}
      "ti_malicious_count>0": {inconsistent: 0.5}
  - id: HYP-BENIGN-ENV
    name: "오탐/환경요인"
    evidence:
      "suppression_corroboration>0": {consistent: 0.8}
      "prediction_probability>=0.6": {inconsistent: 0.4}
"""


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "cat.yaml"
    p.write_text(text, encoding="utf-8")
    return p


class TestCatalogLoad:
    def test_valid_catalog_loads(self, tmp_path: Path) -> None:
        defs = load_hypothesis_catalog(_write(tmp_path, _VALID_YAML))
        assert [d.hypothesis_id for d in defs] == ["HYP-A", "HYP-BENIGN-ENV"]
        rules = defs[0].rules
        assert rules[0].key == "gnss_jam_level"
        assert rules[0].op == ">=" and rules[0].threshold == 2.0
        assert rules[1].direction == "inconsistent"

    def test_float_threshold_allowed(self, tmp_path: Path) -> None:
        defs = load_hypothesis_catalog(_write(tmp_path, _VALID_YAML))
        prob_rule = defs[1].rules[1]
        assert prob_rule.threshold == pytest.approx(0.6)

    def test_missing_null_hypothesis_rejected(self, tmp_path: Path) -> None:
        bad = _VALID_YAML.replace("HYP-BENIGN-ENV", "HYP-OTHER")
        with pytest.raises(HypothesisCatalogError, match="귀무가설"):
            load_hypothesis_catalog(_write(tmp_path, bad))

    def test_duplicate_id_rejected(self, tmp_path: Path) -> None:
        bad = _VALID_YAML.replace("id: HYP-A", "id: HYP-BENIGN-ENV", 1)
        with pytest.raises(HypothesisCatalogError, match="중복"):
            load_hypothesis_catalog(_write(tmp_path, bad))

    def test_unknown_evidence_key_rejected(self, tmp_path: Path) -> None:
        bad = _VALID_YAML.replace("gnss_jam_level>=2", "no_such_key>=2")
        with pytest.raises(HypothesisCatalogError, match="미지의 증거 키"):
            load_hypothesis_catalog(_write(tmp_path, bad))

    def test_bad_dsl_rejected(self, tmp_path: Path) -> None:
        bad = _VALID_YAML.replace("gnss_jam_level>=2", "gnss_jam_level<2")
        with pytest.raises(HypothesisCatalogError, match="조건식"):
            load_hypothesis_catalog(_write(tmp_path, bad))

    def test_gt_nonzero_rejected(self, tmp_path: Path) -> None:
        # `key>0` 만 허용 — `key>5` 는 거부(스펙 3형태 고정)
        bad = _VALID_YAML.replace("ti_malicious_count>0", "ti_malicious_count>5")
        with pytest.raises(HypothesisCatalogError, match="조건식"):
            load_hypothesis_catalog(_write(tmp_path, bad))

    def test_weight_out_of_range_rejected(self, tmp_path: Path) -> None:
        bad = _VALID_YAML.replace("consistent: 0.9", "consistent: 1.5")
        with pytest.raises(HypothesisCatalogError, match="가중치"):
            load_hypothesis_catalog(_write(tmp_path, bad))

    def test_both_directions_rejected(self, tmp_path: Path) -> None:
        bad = _VALID_YAML.replace(
            "{consistent: 0.9}", "{consistent: 0.9, inconsistent: 0.1}"
        )
        with pytest.raises(HypothesisCatalogError, match="정확히 하나"):
            load_hypothesis_catalog(_write(tmp_path, bad))

    def test_repo_catalog_loads_with_null_hypothesis(self) -> None:
        defs = load_hypothesis_catalog()
        ids = {d.hypothesis_id for d in defs}
        assert NULL_HYPOTHESIS_ID in ids
        assert len(ids) >= 5
        for d in defs:
            for r in d.rules:
                assert r.key in EVIDENCE_KEYS
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/__tests__/test_hypothesis.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'core.hypothesis'`

- [ ] **Step 3: Create `core/policy/hypothesis-catalog.yaml`**

```yaml
# UAV 경쟁가설 카탈로그 — ACH(Analysis of Competing Hypotheses)
# 반증(inconsistent) 최소가 승자. 귀무가설 HYP-BENIGN-ENV 필수(로더가 강제).
# 조건식 3형태만: key(truthy) / key>0 / key>=n (n 은 int 또는 float).
# 가중치 0.0 < w <= 1.0. 판정 비권위 — confidence/라우팅에 관여하지 않는다.
hypotheses:
  - id: HYP-GNSS-SPOOF
    name: "GNSS 스푸핑/재밍"
    mitre: ["T1600"]
    evidence:
      "gnss_jam_level>=2": {consistent: 0.9}
      "key_terrain": {consistent: 0.3}
      "airspace_hostile": {consistent: 0.4}
      "suppression_corroboration>0": {inconsistent: 0.5}

  - id: HYP-C2-HIJACK
    name: "C2 링크 탈취"
    mitre: []
    evidence:
      "ti_malicious_count>0": {consistent: 0.7}
      "prediction_match": {consistent: 0.5}
      "kill_chain_advanced": {consistent: 0.6}
      "decoy_hit": {consistent: 0.5}
      "gnss_jam_level>=2": {inconsistent: 0.2}

  - id: HYP-DATALINK-INTERCEPT
    name: "데이터링크 감청"
    mitre: []
    evidence:
      "airspace_hostile": {consistent: 0.6}
      "actor_ttp_overlap": {consistent: 0.5}
      "trusted_chunk_coverage>=3": {consistent: 0.2}
      "sandbox_malicious": {inconsistent: 0.3}

  - id: HYP-SUPPLY-CHAIN
    name: "공급망/펌웨어 침해"
    mitre: []
    evidence:
      "sandbox_malicious": {consistent: 0.9}
      "kev_present": {consistent: 0.7}
      "ti_malicious_count>0": {consistent: 0.4}
      "gnss_jam_level>=2": {inconsistent: 0.3}

  - id: HYP-RECON-TRACK
    name: "정찰/추적"
    mitre: []
    evidence:
      "airspace_hostile": {consistent: 0.7}
      "decoy_hit": {consistent: 0.6}
      "prediction_probability>=0.6": {consistent: 0.4}
      "kev_present": {inconsistent: 0.2}

  - id: HYP-INSIDER
    name: "내부자 위협"
    mitre: []
    evidence:
      "key_terrain": {consistent: 0.4}
      "experience_corroboration>0": {consistent: 0.3}
      "ti_malicious_count>0": {inconsistent: 0.4}
      "airspace_hostile": {inconsistent: 0.3}

  - id: HYP-BENIGN-ENV
    name: "오탐/환경요인"
    mitre: []
    evidence:
      "suppression_corroboration>0": {consistent: 0.8}
      "ti_malicious_count>0": {inconsistent: 0.9}
      "sandbox_malicious": {inconsistent: 0.8}
      "kill_chain_advanced": {inconsistent: 0.5}
      "decoy_hit": {inconsistent: 0.7}
```

- [ ] **Step 4: Create `core/hypothesis.py` (로더 파트)**

```python
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
        mitre = (
            tuple(str(t) for t in mitre_raw) if isinstance(mitre_raw, list) else ()
        )
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
```

주의: `utils/logging.py` 의 `get_logger` 가 없다면(임포트 오류 시) `logging.getLogger("soc.hypothesis")` 로 대체하고 리포 실제 관례를 확인할 것 — `core/severity.py` 나 인접 core 모듈이 로거를 어떻게 얻는지 그대로 따른다. `Alert`/`InvestigationResult`/`TiVerdict`/`EvidenceEntry`/`HypothesisAssessment` 임포트는 Task 3·4 에서 사용한다 (이 시점 미사용 임포트는 ruff 가 잡으므로 Task 2 커밋 전에는 로더가 실제 쓰는 것만 임포트하고, Task 3·4 에서 추가).

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/__tests__/test_hypothesis.py -v`
Expected: Task1 4건 + Task2 10건 = 14 PASS

- [ ] **Step 6: Commit**

```bash
git add core/hypothesis.py core/policy/hypothesis-catalog.yaml tests/__tests__/test_hypothesis.py
git commit -m "feat(analysis): ACH 가설 카탈로그 YAML + DSL 파서/로더 — fail-fast 스키마 검증"
```

---

### Task 3: 증거 정규화 `extract_evidence`

**Files:**
- Modify: `core/hypothesis.py` (함수 추가)
- Test: `tests/__tests__/test_hypothesis.py` (추가)

- [ ] **Step 1: Write the failing tests**

```python
from core.hypothesis import extract_evidence
from core.models import (
    Alert,
    AttackPrediction,
    GnssJamFinding,
    RetrievedChunk,
    Severity,
    ThreatIntelFinding,
    TiVerdict,
    VulnFinding,
)


def _alert(**kwargs: object) -> Alert:
    base: dict[str, object] = {
        "id": "a1",
        "scenario_id": "S1-GNSS-001",
        "title": "X",
        "severity_baseline": Severity.MEDIUM,
        "signals": ["GPS_GLITCH_FLAG"],
        "expected_detection": {"sigma_rule": "r1"},
        "asset_id": "GNSS",
    }
    base.update(kwargs)
    return Alert.model_validate(base)


class TestExtractEvidence:
    def test_empty_result_all_zero(self) -> None:
        ev = extract_evidence(InvestigationResult(), _alert())
        assert set(ev) == set(EVIDENCE_KEYS)
        assert all(v == 0.0 for v in ev.values())

    def test_signals_normalized(self) -> None:
        result = InvestigationResult(
            ti_findings=[
                ThreatIntelFinding(indicator="1.2.3.4", verdict=TiVerdict.MALICIOUS),
                ThreatIntelFinding(indicator="5.6.7.8", verdict=TiVerdict.CLEAN),
            ],
            vuln_findings=[
                VulnFinding(cve="CVE-2024-1", known_exploited=True),
            ],
            gnss_jam_findings=[
                GnssJamFinding(cell="1,2", level=3, as_of="2026-07-09"),
            ],
            suppression_corroboration=2,
            similar_cases=[RetrievedChunk(text="t", source="kb/x", score=0.9)],
            predictions=[
                AttackPrediction(
                    next_technique="T1", probability=0.75,
                    support_count=3, basis_actor_id="ac1",
                )
            ],
        )
        alert = _alert(decoy_hit=True, kill_chain_advanced=True)
        ev = extract_evidence(result, alert, actor_ttp_overlap=True)
        assert ev["ti_malicious_count"] == 1.0  # CLEAN 은 미집계
        assert ev["kev_present"] == 1.0
        assert ev["gnss_jam_level"] == 3.0
        assert ev["suppression_corroboration"] == 2.0
        assert ev["trusted_chunk_coverage"] == 1.0
        assert ev["prediction_probability"] == 0.75
        assert ev["actor_ttp_overlap"] == 1.0
        assert ev["decoy_hit"] == 1.0
        assert ev["kill_chain_advanced"] == 1.0
        assert ev["sandbox_malicious"] == 0.0
        assert ev["airspace_hostile"] == 0.0
```

주의: `VulnFinding`/`GnssJamFinding`/`AttackPrediction` 의 필수 필드가 위와 다르면
`core/models.py` 정의를 열어 맞춘다(필드 임의 추정 금지).

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/__tests__/test_hypothesis.py::TestExtractEvidence -v`
Expected: FAIL — `ImportError: cannot import name 'extract_evidence'`

- [ ] **Step 3: Implement — `core/hypothesis.py` 에 추가**

```python
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
            any(
                f.hostile and f.distance_km <= 10.0
                for f in result.airspace_findings
            )
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/__tests__/test_hypothesis.py -v`
Expected: 16 PASS

- [ ] **Step 5: Commit**

```bash
git add core/hypothesis.py tests/__tests__/test_hypothesis.py
git commit -m "feat(analysis): 조사 산출물→ACH 증거 정규화 extract_evidence"
```

---

### Task 4: `AchEvaluator` — 스코어링·diagnosticity·순위

**Files:**
- Modify: `core/hypothesis.py` (클래스 추가)
- Test: `tests/__tests__/test_hypothesis.py` (추가)

- [ ] **Step 1: Write the failing tests**

```python
from core.hypothesis import AchEvaluator, EvidenceRule, HypothesisDef


def _hyp(hid: str, *rules: EvidenceRule) -> HypothesisDef:
    return HypothesisDef(hypothesis_id=hid, name=hid, mitre=(), rules=rules)


def _r(key: str, direction: str, weight: float, op: str = ">", th: float = 0.0) -> EvidenceRule:
    return EvidenceRule(key=key, op=op, threshold=th, direction=direction, weight=weight)


class TestAchEvaluator:
    def test_least_refuted_wins_despite_less_support(self) -> None:
        # A: 지지 2건(1.2) + 반증 1건 / B: 지지 1건(0.5) + 반증 0건 → B 승
        cat = (
            _hyp(
                "HYP-A",
                _r("ti_malicious_count", "consistent", 0.7),
                _r("kev_present", "consistent", 0.5),
                _r("suppression_corroboration", "inconsistent", 0.4),
            ),
            _hyp("HYP-B", _r("ti_malicious_count", "consistent", 0.5)),
        )
        ev = {
            "ti_malicious_count": 2.0,
            "kev_present": 1.0,
            "suppression_corroboration": 1.0,
        }
        out = AchEvaluator(cat).evaluate(ev)
        assert out[0].hypothesis_id == "HYP-B"
        assert out[0].rank == 1
        assert out[1].hypothesis_id == "HYP-A"
        assert out[1].inconsistency == pytest.approx(0.4)

    def test_strength_capped_at_one(self) -> None:
        cat = (_hyp("HYP-A", _r("ti_malicious_count", "consistent", 0.5)),)
        out = AchEvaluator(cat).evaluate({"ti_malicious_count": 7.0})
        assert out[0].consistency == pytest.approx(0.5)  # 0.5 * min(1, 7)

    def test_fractional_strength_scales(self) -> None:
        cat = (
            _hyp(
                "HYP-A",
                _r("prediction_probability", "consistent", 1.0, op=">=", th=0.6),
            ),
        )
        out = AchEvaluator(cat).evaluate({"prediction_probability": 0.8})
        assert out[0].consistency == pytest.approx(0.8)

    def test_no_evidence_all_rank_none_catalog_order(self) -> None:
        cat = (
            _hyp("HYP-B", _r("decoy_hit", "consistent", 0.5)),
            _hyp("HYP-A", _r("kev_present", "consistent", 0.5)),
        )
        out = AchEvaluator(cat).evaluate({"decoy_hit": 0.0, "kev_present": 0.0})
        assert [a.hypothesis_id for a in out] == ["HYP-B", "HYP-A"]  # 선언 순
        assert all(a.rank is None for a in out)
        assert all(not a.ledger for a in out)

    def test_tiebreak_id_lexicographic_deterministic(self) -> None:
        cat = (
            _hyp("HYP-B", _r("kev_present", "consistent", 0.5)),
            _hyp("HYP-A", _r("kev_present", "consistent", 0.5)),
        )
        for _ in range(5):
            out = AchEvaluator(cat).evaluate({"kev_present": 1.0})
            assert [a.hypothesis_id for a in out] == ["HYP-A", "HYP-B"]
            assert out[0].rank == 1 and out[1].rank == 2

    def test_rounding_boundary_treated_as_tie(self) -> None:
        # 4자리 라운딩 후 동률 → id 사전순
        cat = (
            _hyp("HYP-B", _r("prediction_probability", "consistent", 0.500049999)),
            _hyp("HYP-A", _r("prediction_probability", "consistent", 0.5)),
        )
        out = AchEvaluator(cat).evaluate({"prediction_probability": 1.0})
        assert out[0].consistency == out[1].consistency  # 둘 다 0.5(4자리)
        assert out[0].hypothesis_id == "HYP-A"

    def test_common_consistent_evidence_nondiagnostic(self) -> None:
        cat = (
            _hyp("HYP-A", _r("kev_present", "consistent", 0.5)),
            _hyp("HYP-B", _r("kev_present", "consistent", 0.3)),
        )
        out = AchEvaluator(cat).evaluate({"kev_present": 1.0})
        for a in out:
            assert all(e.diagnostic is False for e in a.ledger)

    def test_common_inconsistent_evidence_nondiagnostic(self) -> None:
        cat = (
            _hyp("HYP-A", _r("kev_present", "inconsistent", 0.5)),
            _hyp("HYP-B", _r("kev_present", "inconsistent", 0.3)),
        )
        out = AchEvaluator(cat).evaluate({"kev_present": 1.0})
        for a in out:
            assert all(e.diagnostic is False for e in a.ledger)

    def test_mixed_direction_evidence_diagnostic(self) -> None:
        cat = (
            _hyp("HYP-A", _r("kev_present", "consistent", 0.5)),
            _hyp("HYP-B", _r("kev_present", "inconsistent", 0.3)),
        )
        out = AchEvaluator(cat).evaluate({"kev_present": 1.0})
        for a in out:
            assert all(e.diagnostic is True for e in a.ledger)

    def test_partial_match_evidence_diagnostic(self) -> None:
        # 한 가설만 매칭한 증거는 변별력 있음
        cat = (
            _hyp("HYP-A", _r("kev_present", "consistent", 0.5)),
            _hyp("HYP-B", _r("decoy_hit", "consistent", 0.3)),
        )
        out = AchEvaluator(cat).evaluate({"kev_present": 1.0, "decoy_hit": 0.0})
        assert out[0].hypothesis_id == "HYP-A"
        assert out[0].ledger[0].diagnostic is True

    def test_per_hypothesis_isolation(self) -> None:
        # 개별 가설 평가 실패 → 해당 가설만 제외, 나머지 유지
        class _Boom(EvidenceRule):
            def matches(self, value: float) -> bool:
                raise RuntimeError("boom")

        bad = _hyp(
            "HYP-BAD",
            _Boom(key="kev_present", op=">", threshold=0.0,
                  direction="consistent", weight=0.5),
        )
        good = _hyp("HYP-GOOD", _r("kev_present", "consistent", 0.5))
        out = AchEvaluator((bad, good)).evaluate({"kev_present": 1.0})
        assert [a.hypothesis_id for a in out] == ["HYP-GOOD"]
        assert out[0].rank == 1
```

주의: `EvidenceRule` 이 frozen dataclass 라 상속 오버라이드는 유효(`matches` 만
재정의). dataclass 상속 오류 시 `_Boom` 을 `matches` 가 raise 하는 별도 frozen
dataclass 로 정의해도 됨 — 시그니처(key/op/threshold/direction/weight/matches)만
같으면 된다.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/__tests__/test_hypothesis.py::TestAchEvaluator -v`
Expected: FAIL — `ImportError: cannot import name 'AchEvaluator'`

- [ ] **Step 3: Implement — `core/hypothesis.py` 에 추가**

```python
class AchEvaluator:
    """카탈로그 기반 ACH 평가기 — 순수 결정론, IO 없음.

    반증 최소 승자: (inconsistency 오름차순, consistency 내림차순, id 사전순).
    점수는 소수 4자리 반올림 후 비교(float 누적오차 순위 요동 방지).
    """

    def __init__(self, catalog: tuple[HypothesisDef, ...]) -> None:
        self._catalog = catalog

    def evaluate(self, evidence: dict[str, float]) -> list[HypothesisAssessment]:
        """증거값으로 전 가설을 평가하고 순위를 부여한다.

        Args:
            evidence: `extract_evidence` 산출 증거값(키→정규화 값).

        Returns:
            rank 오름차순 정렬 결과. 매칭 증거가 전무하면 전 가설 rank=None
            (카탈로그 선언 순). 개별 가설 평가 실패는 해당 가설만 제외.
        """
        assessments: list[HypothesisAssessment] = []
        # diagnosticity 집계: 증거 키 → (매칭 가설 수, 방향 집합)
        key_hits: dict[str, int] = {}
        key_dirs: dict[str, set[str]] = {}
        for hyp in self._catalog:
            try:
                ledger: list[EvidenceEntry] = []
                seen_keys: set[str] = set()
                for rule in hyp.rules:
                    value = evidence.get(rule.key, 0.0)
                    if not rule.matches(value):
                        continue
                    ledger.append(
                        EvidenceEntry(
                            key=rule.key,
                            value=value,
                            direction=rule.direction,  # type: ignore[arg-type]
                            weight=rule.weight,
                        )
                    )
                    if rule.key not in seen_keys:
                        seen_keys.add(rule.key)
                        key_hits[rule.key] = key_hits.get(rule.key, 0) + 1
                    key_dirs.setdefault(rule.key, set()).add(rule.direction)
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
                assessments.append(
                    HypothesisAssessment(
                        hypothesis_id=hyp.hypothesis_id,
                        name=hyp.name,
                        consistency=consistency,
                        inconsistency=inconsistency,
                        ledger=ledger,
                    )
                )
            except Exception:  # noqa: BLE001 — 가설 단위 격리(전체 소실 금지)
                _logger.warning(
                    "가설 %s 평가 실패 — 해당 가설만 제외", hyp.hypothesis_id,
                    exc_info=True,
                )
        # diagnosticity: 평가 성공한 전 가설에 같은 방향으로만 걸린 증거 = 변별력 0
        total = len(assessments)
        nondiagnostic = {
            k
            for k, hits in key_hits.items()
            if total > 1 and hits == total and len(key_dirs[k]) == 1
        }
        for a in assessments:
            for e in a.ledger:
                if e.key in nondiagnostic:
                    e.diagnostic = False
        if not any(a.ledger for a in assessments):
            return assessments  # 증거 0건 — 전건 rank=None, 카탈로그 순
        ordered = sorted(
            assessments,
            key=lambda a: (a.inconsistency, -a.consistency, a.hypothesis_id),
        )
        for i, a in enumerate(ordered, start=1):
            a.rank = i
        return ordered
```

주의: pydantic v2 기본 모델은 속성 재할당 허용 — `e.diagnostic = False`/`a.rank = i`
가 실패하면(`model_config` 에 frozen 등) 모델 쪽 설정을 확인하고 `model_copy`
방식으로 바꾼다. `# type: ignore[arg-type]` 는 `EvidenceRule.direction: str` →
`Literal` 대입 때문 — mypy 가 통과하면 제거.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/__tests__/test_hypothesis.py -v`
Expected: 27 PASS

- [ ] **Step 5: Commit**

```bash
git add core/hypothesis.py tests/__tests__/test_hypothesis.py
git commit -m "feat(analysis): AchEvaluator — 반증최소 순위·diagnosticity·가설단위 격리"
```

---

### Task 5: investigation agent 배선 + 통합 테스트

**Files:**
- Modify: `agents/investigation_agent.py` (임포트 + `__init__` 1줄 + run() 말미 재구성)
- Test: `tests/__tests__/test_hypothesis.py` (통합 클래스 추가)

- [ ] **Step 1: Write the failing tests**

```python
import pytest

from agents.investigation_agent import InvestigationAgent
from core.settings import Settings


class TestInvestigationWiring:
    @pytest.mark.asyncio
    async def test_run_populates_assessments_nonauthoritative(self) -> None:
        agent = InvestigationAgent(Settings(), retriever=None)
        out = await agent.run({"alert": _alert()})
        inv = out["investigation"]
        # 신규 필드 채움: 카탈로그 전 가설 반환
        assert len(inv.hypothesis_assessments) >= 5
        # 증거 0건(외부 도구 전부 미주입) → 전건 rank=None (침묵)
        assert all(a.rank is None for a in inv.hypothesis_assessments)

    @pytest.mark.asyncio
    async def test_evaluator_failure_isolated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        agent = InvestigationAgent(Settings(), retriever=None)

        def _boom(evidence: dict[str, float]) -> list[object]:
            raise RuntimeError("ach boom")  # 비 SOCPlatformError

        monkeypatch.setattr(agent._ach, "evaluate", _boom)
        out = await agent.run({"alert": _alert()})
        inv = out["investigation"]
        assert inv.hypothesis_assessments == []  # 가설 없이 진행
        assert inv.matched_signals == ["GPS_GLITCH_FLAG"]  # 조사 자체는 정상

    @pytest.mark.asyncio
    async def test_confidence_and_fields_unchanged_by_ach(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # 비권위 불변: ACH 유무와 무관하게 나머지 필드 동일
        agent_on = InvestigationAgent(Settings(), retriever=None)
        agent_off = InvestigationAgent(Settings(), retriever=None)
        monkeypatch.setattr(
            agent_off._ach, "evaluate", lambda evidence: (_ for _ in ()).throw(RuntimeError())
        )
        inv_on = (await agent_on.run({"alert": _alert()}))["investigation"]
        inv_off = (await agent_off.run({"alert": _alert()}))["investigation"]
        dump_on = inv_on.model_dump(exclude={"hypothesis_assessments"})
        dump_off = inv_off.model_dump(exclude={"hypothesis_assessments"})
        assert dump_on == dump_off
        assert inv_on.confidence == inv_off.confidence
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/__tests__/test_hypothesis.py::TestInvestigationWiring -v`
Expected: FAIL — `AttributeError: 'InvestigationAgent' object has no attribute '_ach'`

- [ ] **Step 3: Implement — `agents/investigation_agent.py`**

임포트 블록(로컬 모듈 섹션, isort 순서)에 추가:

```python
from core.hypothesis import AchEvaluator, extract_evidence, load_hypothesis_catalog
```

`__init__` 말미(`self._asset_coords = _load_asset_coords()` 아래)에 추가:

```python
        # ACH 경쟁가설 평가기 — 카탈로그 로드는 기동 시 fail-fast(스키마 보증).
        self._ach = AchEvaluator(load_hypothesis_catalog())
```

run() 의 actor 블록(현재 `profile = await self._recall_actor(alert)` 부근, 약 329행)
— TTP 교집합 여부를 변수로 보존(기존 동작 불변):

```python
        # spec #2: actor 회상 후 TTP 매치 시 confidence +0.2 (한 번).
        profile = await self._recall_actor(alert)
        predictions: list[AttackPrediction] = []
        actor_ttp_overlap = False
        if profile is not None:
            techs_raw = alert.mitre.get("techniques", [])
            current_techs = (
                {str(t) for t in techs_raw} if isinstance(techs_raw, list) else set()
            )
            top_techs = {
                s.technique
                for s in sorted(profile.ttp_stats, key=lambda x: -x.count)[:3]
            }
            if current_techs & top_techs:
                actor_ttp_overlap = True
                confidence = round(min(1.0, confidence + 0.2), 3)
                flags.append(f"actor[{profile.actor_id}] TTP 매치 → conf +0.2")
```

run() 의 결과 구성(현재 367~384행) — `InvestigationResult` 를 지역변수로 빼고
ACH 블록 삽입(dict 구성은 그 아래로):

```python
        investigation = InvestigationResult(
            matched_signals=alert.signals,
            mitre=alert.mitre,
            similar_cases=trusted,
            summary=summary,
            confidence=confidence,
            ti_findings=ti_findings,
            experience_corroboration=exp_corroboration,
            suppression_corroboration=suppression,
            sandbox_reports=sandbox_reports,
            vuln_findings=vuln_findings,
            gnss_jam_findings=gnss_jam_findings,
            airspace_findings=airspace_findings,
            predictions=predictions,
        )
        # ACH 경쟁가설 평가 — 비권위 참고정보. 어떤 예외도 조사 실패로 승격 금지.
        try:
            evidence = extract_evidence(investigation, alert, actor_ttp_overlap)
            investigation.hypothesis_assessments = self._ach.evaluate(evidence)
        except Exception:  # noqa: BLE001 — 비권위 부가층 광역 격리 지점
            self._logger.warning("ACH 가설 평가 실패 — 가설 없이 진행", exc_info=True)

        result: SOCState = {
            "investigation": investigation,
            "trace": ["investigation"],
        }
```

이후 기존 RAGAS/guardrail_flags 코드는 그대로.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/__tests__/test_hypothesis.py -v`
Expected: 30 PASS

- [ ] **Step 5: 전체 회귀 (기존 investigation 테스트 포함)**

Run: `pytest -q`
Expected: 전건 PASS (baseline 1188 + 신규 30). 기존 investigation 테스트가
`_ach` 기동 로드로 깨지면 카탈로그 경로/로드 오류 — 카탈로그 파일 커밋 여부 확인.

- [ ] **Step 6: Commit**

```bash
git add agents/investigation_agent.py tests/__tests__/test_hypothesis.py
git commit -m "feat(analysis): investigation에 ACH 가설층 배선 — 광역 격리·비권위"
```

---

### Task 6: 품질 게이트 + 마무리

**Files:** 수정 없음 (게이트 실패 시 해당 파일 수정)

- [ ] **Step 1: 포매터/린터/타입 게이트**

Run (순서대로, 이 브랜치 변경 파일 대상):

```bash
black core/hypothesis.py core/models.py core/exceptions.py agents/investigation_agent.py tests/__tests__/test_hypothesis.py
ruff check core/hypothesis.py core/models.py core/exceptions.py agents/investigation_agent.py tests/__tests__/test_hypothesis.py
mypy core/hypothesis.py agents/investigation_agent.py
```

Expected: black 무변경(또는 재포맷 후 재커밋), ruff 0건, mypy 0건.
주의: **전체 리포 `black .`/`ruff check .` 금지** — main 에 pre-existing red
(CJK E501 등) 존재, 이 브랜치 소관 아님. 변경 파일만 게이트.

- [ ] **Step 2: 최종 전체 테스트**

Run: `pytest -q`
Expected: 전건 PASS

- [ ] **Step 3: 게이트 수정 있었으면 커밋**

```bash
git add -u
git commit -m "chore(analysis): ACH 가설층 품질 게이트 정리 (black/ruff/mypy)"
```

- [ ] **Step 4: 완료 보고**

superpowers:finishing-a-development-branch 스킬로 머지/PR 옵션 제시.
PR 시 베이스 main — response 레인(feat/cacao-catalog 후속)과 접점은
`core/models.py`·`core/exceptions.py` additive 뿐이므로 순서 무관 자동 머지 기대.
