"""인시던트 보고시한 SLA — CJCSM 6510 CAT별 데드라인 + 초과판정(결정론)."""

import pytest

from core.exceptions import PolicyError
from core.incident import (
    CaseManager,
    IncidentReportingSla,
    InMemoryIncidentStore,
    _report_due,
    is_case_overdue,
)
from core.models import Alert, EnvVerdict, IncidentCase, Severity


def _alert(*, aid: str = "a1", scenario: str = "S2-C2") -> Alert:
    return Alert(
        id=aid,
        scenario_id=scenario,
        title="t",
        severity_baseline=Severity.HIGH,
        signals=["sig"],
        mitre={"tactics": ["CommandAndControl"], "techniques": ["T1071"]},
        actor_id="APT-X",
        kill_chain_advanced=True,
    )


class TestSlaPolicy:
    def test_loads_cat_minutes(self) -> None:
        sla = IncidentReportingSla.from_yaml()
        assert sla.minutes_for("CAT1") == 60
        assert sla.minutes_for("CAT6") == 1440

    def test_unmapped_cat_default(self) -> None:
        sla = IncidentReportingSla.from_yaml()
        assert sla.minutes_for("CAT99") == 1440  # 기본

    def test_malformed_policy_raises(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        p = tmp_path / "bad.yaml"
        p.write_text("reporting_sla: 5\n", encoding="utf-8")  # 매핑 아님
        with pytest.raises(PolicyError):
            IncidentReportingSla.from_yaml(p)

    def test_missing_section_raises(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """필수 섹션 누락 → PolicyError(조용한 기본값 강등 차단, Codex M)."""
        p1 = tmp_path / "m1.yaml"
        p1.write_text("other: 1\n", encoding="utf-8")  # reporting_sla 없음
        with pytest.raises(PolicyError):
            IncidentReportingSla.from_yaml(p1)
        p2 = tmp_path / "m2.yaml"
        p2.write_text("reporting_sla:\n  default_minutes: 60\n", encoding="utf-8")
        with pytest.raises(PolicyError):  # sla_minutes 없음
            IncidentReportingSla.from_yaml(p2)


class TestReportDue:
    def test_due_is_opened_plus_sla(self) -> None:
        assert _report_due("2026-07-08T00:00:00Z", 60) == "2026-07-08T01:00:00Z"
        assert _report_due("2026-07-08T00:00:00Z", 1440) == "2026-07-09T00:00:00Z"

    def test_empty_or_malformed_opened(self) -> None:
        assert _report_due("", 60) == ""
        assert _report_due("not-a-time", 60) == ""


class TestOverdue:
    def test_overdue_true_false(self) -> None:
        c = IncidentCase(
            case_id="c", actor_id="a", report_due_at="2026-07-08T01:00:00Z"
        )
        assert is_case_overdue(c, "2026-07-08T02:00:00Z") is True
        assert is_case_overdue(c, "2026-07-08T00:30:00Z") is False

    def test_no_due_not_overdue(self) -> None:
        c = IncidentCase(case_id="c", actor_id="a")
        assert is_case_overdue(c, "2026-07-08T02:00:00Z") is False


class TestCaseManagerSla:
    def test_authoritative_cat1_sla_60(self) -> None:
        """CAT1 권위 → SLA 60분, due=opened+60."""
        mgr = CaseManager(InMemoryIncidentStore())
        c = mgr.observe_outcome(_alert(), EnvVerdict.CONFIRMED_TP)
        assert c is not None and c.cat == "CAT1"
        assert c.report_sla_min == 60
        assert c.report_due_at  # 세팅됨

    def test_provisional_cat8_sla_1440(self) -> None:
        """report 잠정 CAT8 → SLA 1440분."""
        mgr = CaseManager(InMemoryIncidentStore())
        c = mgr.observe_alert(_alert(), Severity.MEDIUM)
        assert c is not None and c.cat == "CAT8"
        assert c.report_sla_min == 1440

    def test_cat_tightening_shortens_deadline(self) -> None:
        """CAT8(잠정)→CAT1(권위) 강화 시 시한 단축(opened_at 앵커 — 드리프트 없음)."""
        store = InMemoryIncidentStore()
        mgr = CaseManager(store)
        prov = mgr.observe_alert(_alert(aid="a1"), Severity.MEDIUM)
        assert prov is not None
        due_prov = prov.report_due_at
        auth = mgr.observe_outcome(_alert(aid="a1"), EnvVerdict.CONFIRMED_TP)
        assert auth is not None and auth.cat == "CAT1"
        assert auth.report_due_at < due_prov  # 60분 < 1440분 → 더 이른 데드라인
