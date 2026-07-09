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
