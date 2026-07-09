"""CISA CIRCIA 72h 연방 보고 — 권위 중대 case 만(트러스트 게이팅)."""

from core.commander import IncidentCommander
from core.incident import cisa_report_due, is_cisa_overdue, is_cisa_reportable
from core.models import IncidentCase


def _case(**kw: object) -> IncidentCase:
    base: dict[str, object] = {"case_id": "c", "actor_id": "APT-X"}
    base.update(kw)
    return IncidentCase(**base)  # type: ignore[arg-type]


class TestReportable:
    def test_authoritative_covered_cats(self) -> None:
        for cat in ("CAT1", "CAT4", "CAT7"):
            assert is_cisa_reportable(_case(cat=cat, provisional=False))

    def test_provisional_not_reportable(self) -> None:
        """hostile — provisional CAT7 은 연방 보고 대상 아님(오보 방지)."""
        assert not is_cisa_reportable(_case(cat="CAT7", provisional=True))

    def test_cat2_alone_not_reportable(self) -> None:
        assert not is_cisa_reportable(_case(cat="CAT2", provisional=False))

    def test_cat2_recidivist_reportable(self) -> None:
        """CAT2 + 재범(reopen>0 = 지속 침해·substantial) → 대상."""
        assert is_cisa_reportable(_case(cat="CAT2", provisional=False, reopen_count=1))

    def test_low_cats_not_reportable(self) -> None:
        for cat in ("CAT6", "CAT8", "CAT3"):
            assert not is_cisa_reportable(_case(cat=cat, provisional=False))


class TestOverdue:
    def test_72h_overdue(self) -> None:
        c = _case(cat="CAT1", provisional=False, opened_at="2026-07-01T00:00:00Z")
        assert cisa_report_due(c) == "2026-07-04T00:00:00Z"
        assert is_cisa_overdue(c, "2026-07-09T00:00:00Z")

    def test_within_72h_not_overdue(self) -> None:
        c = _case(cat="CAT1", provisional=False, opened_at="2026-07-01T00:00:00Z")
        assert not is_cisa_overdue(c, "2026-07-02T00:00:00Z")

    def test_not_reportable_never_overdue(self) -> None:
        c = _case(cat="CAT6", provisional=False, opened_at="2026-07-01T00:00:00Z")
        assert not is_cisa_overdue(c, "2026-07-09T00:00:00Z")

    def test_graceful_no_now(self) -> None:
        c = _case(cat="CAT1", provisional=False, opened_at="2026-07-01T00:00:00Z")
        assert not is_cisa_overdue(c, "")

    def test_graceful_bad_opened(self) -> None:
        assert cisa_report_due(_case(opened_at="garbage")) == ""


class TestDirective:
    def test_directive_exposes_cisa(self) -> None:
        d = IncidentCommander().direct(
            _case(cat="CAT7", provisional=False, opened_at="2026-07-01T00:00:00Z"),
            "2026-07-09T00:00:00Z",
        )
        assert d.cisa_reportable and d.cisa_report_overdue
        assert any("CIRCIA" in r for r in d.rationale)

    def test_provisional_directive_no_cisa(self) -> None:
        d = IncidentCommander().direct(_case(cat="CAT8", provisional=True))
        assert not d.cisa_reportable and not d.cisa_report_overdue


class TestMetricWiring:
    def test_outcome_probe_records_cisa(self) -> None:
        """OutcomeProbe 가 권위 확증 후 cisa_reportable 이면 metric(M1 posture)."""
        from app.metrics import metrics
        from core.incident import CaseManager, InMemoryIncidentStore
        from core.models import Alert, EnvVerdict, Severity

        alert = Alert(
            id="w1",
            scenario_id="S2-C2",
            title="t",
            severity_baseline=Severity.HIGH,
            signals=["sig"],
            mitre={"tactics": ["CommandAndControl"], "techniques": ["T1071"]},
            actor_id="APT-X",
            kill_chain_advanced=True,
        )
        mgr = CaseManager(InMemoryIncidentStore())
        case = mgr.observe_outcome(alert, EnvVerdict.CONFIRMED_TP)
        # 권위 CAT1(order11) → cisa_reportable
        assert case is not None and is_cisa_reportable(case)
        before = metrics().cisa_reportable_total
        metrics().record_cisa_reportable()
        assert metrics().cisa_reportable_total == before + 1
