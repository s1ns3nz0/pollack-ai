"""ACH 가설 평가(core/hypothesis.py) 단위 테스트."""

from pathlib import Path

import pytest

from agents.investigation_agent import InvestigationAgent
from core.exceptions import HypothesisCatalogError, SOCPlatformError
from core.hypothesis import (
    EVIDENCE_KEYS,
    NULL_HYPOTHESIS_ID,
    AchEvaluator,
    EvidenceRule,
    HypothesisDef,
    extract_evidence,
    load_hypothesis_catalog,
)
from core.models import (
    Alert,
    AttackPrediction,
    EvidenceEntry,
    GnssJamFinding,
    HypothesisAssessment,
    InvestigationResult,
    RetrievedChunk,
    Severity,
    ThreatIntelFinding,
    TiVerdict,
    VulnFinding,
)
from core.settings import Settings

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

    def test_non_mapping_toplevel_normalized(self, tmp_path: Path) -> None:
        """top-level 비매핑(YAML 리스트) → PolicyError 아닌 HypothesisCatalogError."""
        with pytest.raises(HypothesisCatalogError):
            load_hypothesis_catalog(_write(tmp_path, "- just\n- a list\n"))


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
    """조사 산출물 → ACH 증거 정규화 테스트."""

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
                    next_technique="T1",
                    probability=0.75,
                    support_count=3,
                    basis_actor_id="ac1",
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


def _hyp(hid: str, *rules: EvidenceRule) -> HypothesisDef:
    return HypothesisDef(hypothesis_id=hid, name=hid, mitre=(), rules=rules)


def _r(
    key: str,
    direction: str,
    weight: float,
    op: str = ">",
    th: float = 0.0,
) -> EvidenceRule:
    return EvidenceRule(
        key=key, op=op, threshold=th, direction=direction, weight=weight
    )


class TestAchEvaluator:
    """ACH 스코어링·순위·diagnosticity 테스트."""

    def test_least_refuted_wins_despite_less_support(self) -> None:
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
        assert out[0].consistency == pytest.approx(0.5)

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
        assert [a.hypothesis_id for a in out] == ["HYP-B", "HYP-A"]
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
        cat = (
            _hyp("HYP-B", _r("prediction_probability", "consistent", 0.500049999)),
            _hyp("HYP-A", _r("prediction_probability", "consistent", 0.5)),
        )
        out = AchEvaluator(cat).evaluate({"prediction_probability": 1.0})
        assert out[0].consistency == out[1].consistency
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
        cat = (
            _hyp("HYP-A", _r("kev_present", "consistent", 0.5)),
            _hyp("HYP-B", _r("decoy_hit", "consistent", 0.3)),
        )
        out = AchEvaluator(cat).evaluate({"kev_present": 1.0, "decoy_hit": 0.0})
        assert out[0].hypothesis_id == "HYP-A"
        assert out[0].ledger[0].diagnostic is True

    def test_per_hypothesis_isolation(self) -> None:
        class _Boom(EvidenceRule):
            def matches(self, value: float) -> bool:
                raise RuntimeError("boom")

        bad = _hyp(
            "HYP-BAD",
            _Boom(
                key="kev_present",
                op=">",
                threshold=0.0,
                direction="consistent",
                weight=0.5,
            ),
        )
        good = _hyp("HYP-GOOD", _r("kev_present", "consistent", 0.5))
        out = AchEvaluator((bad, good)).evaluate({"kev_present": 1.0})
        assert [a.hypothesis_id for a in out] == ["HYP-GOOD"]
        assert out[0].rank == 1


class TestInvestigationWiring:
    """InvestigationAgent ACH 비권위 배선 테스트."""

    @pytest.mark.asyncio
    async def test_run_populates_assessments_nonauthoritative(self) -> None:
        agent = InvestigationAgent(Settings(), retriever=None)
        out = await agent.run({"alert": _alert()})
        inv = out["investigation"]
        assert len(inv.hypothesis_assessments) >= 5
        assert all(a.rank is None for a in inv.hypothesis_assessments)

    @pytest.mark.asyncio
    async def test_evaluator_failure_isolated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent = InvestigationAgent(Settings(), retriever=None)

        def _boom(evidence: dict[str, float]) -> list[HypothesisAssessment]:
            raise RuntimeError("ach boom")

        monkeypatch.setattr(agent._ach, "evaluate", _boom)
        out = await agent.run({"alert": _alert()})
        inv = out["investigation"]
        assert inv.hypothesis_assessments == []
        assert inv.matched_signals == ["GPS_GLITCH_FLAG"]

    @pytest.mark.asyncio
    async def test_confidence_and_fields_unchanged_by_ach(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent_on = InvestigationAgent(Settings(), retriever=None)
        agent_off = InvestigationAgent(Settings(), retriever=None)

        def _boom(evidence: dict[str, float]) -> list[HypothesisAssessment]:
            raise RuntimeError("ach boom")

        monkeypatch.setattr(agent_off._ach, "evaluate", _boom)
        inv_on = (await agent_on.run({"alert": _alert()}))["investigation"]
        inv_off = (await agent_off.run({"alert": _alert()}))["investigation"]
        dump_on = inv_on.model_dump(exclude={"hypothesis_assessments"})
        dump_off = inv_off.model_dump(exclude={"hypothesis_assessments"})
        assert dump_on == dump_off
        assert inv_on.confidence == inv_off.confidence
