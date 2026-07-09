"""ACH 가설 평가(core/hypothesis.py) 단위 테스트."""

from pathlib import Path

import pytest

from core.exceptions import HypothesisCatalogError, SOCPlatformError
from core.hypothesis import (
    EVIDENCE_KEYS,
    NULL_HYPOTHESIS_ID,
    load_hypothesis_catalog,
)
from core.models import EvidenceEntry, HypothesisAssessment, InvestigationResult

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


class TestModels:
    """ACH 모델/예외 기본 동작 테스트."""

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


class TestCatalogLoad:
    """카탈로그 로더/DSL 스키마 검증 테스트."""

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
        """`key>0` 만 허용 — `key>5` 는 거부(스펙 3형태 고정)."""
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
