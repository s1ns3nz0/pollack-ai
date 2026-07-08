"""Incident Case 생명주기 MVP — 봉합·PROVISIONAL 상태·CAT·DoS캡(Codex 반영)."""

import pytest

from core.incident import (
    CaseManager,
    IncidentState,
    InMemoryIncidentStore,
    _provisional_cat,
)
from core.models import Alert, Severity


def _alert(
    *,
    aid: str = "a1",
    actor_id: str | None = "APT-X",
    advanced: bool = False,
    techs: list[str] | None = None,
) -> Alert:
    return Alert(
        id=aid,
        scenario_id="S2",
        title="t",
        asset_id="GNSS",
        mission_phase="ingress",
        severity_baseline=Severity.MEDIUM,
        signals=["sig"],
        mitre={"tactics": ["c2"], "techniques": techs or ["T1071"]},
        actor_id=actor_id,
        kill_chain_advanced=advanced,
    )


def _mgr() -> CaseManager:
    return CaseManager(InMemoryIncidentStore())


class TestBindingAndState:
    def test_open_and_advance_to_analysis(self) -> None:
        """첫 alert → open→ANALYSIS. 동일 actor 다수 → 한 case, member 누적."""
        mgr = _mgr()
        c1 = mgr.observe_alert(_alert(aid="a1"), Severity.MEDIUM)
        assert c1 is not None
        assert c1.state == IncidentState.ANALYSIS  # NEW→ANALYSIS 한 번에
        assert c1.actor_id == "APT-X"
        c2 = mgr.observe_alert(_alert(aid="a2"), Severity.MEDIUM)
        assert c2 is not None and c2.case_id == c1.case_id
        assert c2.member_alert_ids == ["a1", "a2"]

    def test_report_never_reaches_containment(self) -> None:
        """report 경로는 고심각도·advanced 라도 CONTAINMENT 불가(Codex C1/M5)."""
        mgr = _mgr()
        case = None
        for i in range(5):
            case = mgr.observe_alert(_alert(aid=f"a{i}", advanced=True), Severity.HIGH)
        assert case is not None
        assert case.state == IncidentState.ANALYSIS  # CONTAINMENT 아님
        assert case.provisional is True

    def test_severity_peak_monotonic(self) -> None:
        mgr = _mgr()
        mgr.observe_alert(_alert(aid="a1"), Severity.LOW)
        c = mgr.observe_alert(_alert(aid="a2"), Severity.HIGH)
        assert c is not None and c.severity_peak == Severity.HIGH
        c2 = mgr.observe_alert(_alert(aid="a3"), Severity.LOW)
        assert c2 is not None and c2.severity_peak == Severity.HIGH  # 후퇴 안 함


class TestBindingTrust:
    def test_empty_fingerprint_no_case(self) -> None:
        """빈 fingerprint(모든 차원 빈값) → case 미개설(빈 fp DoS 방지, Codex M7)."""
        mgr = _mgr()
        empty = Alert(
            id="e1",
            scenario_id="S",
            title="t",
            severity_baseline=Severity.INFO,
            actor_id=None,
        )
        assert mgr.observe_alert(empty, Severity.INFO) is None

    def test_fingerprint_binding_without_actor_id(self) -> None:
        """actor_id 없어도 fingerprint 로 봉합(위생 alert 대응, Codex M7)."""
        mgr = _mgr()
        c = mgr.observe_alert(_alert(actor_id=None), Severity.MEDIUM)
        assert c is not None and c.actor_id.startswith("fp:")

    def test_whitespace_actor_id_no_malformed_case(self) -> None:
        """공백 explicit actor_id("   ") → case:빈 생성 안 함(Codex M)."""
        mgr = _mgr()
        c = mgr.observe_alert(_alert(actor_id="   "), Severity.MEDIUM)
        assert c is None or c.actor_id != ""


class TestDoSCap:
    def test_store_cap_evicts_lru(self) -> None:
        """캡 초과 → LRU eviction(fingerprint 변조 폭주 봉인, Codex H3)."""
        store = InMemoryIncidentStore(cap=3)
        mgr = CaseManager(store)
        # 서로 다른 fingerprint 5개(technique 변조) → 캡 3 유지
        for i in range(5):
            mgr.observe_alert(
                _alert(aid=f"a{i}", actor_id=None, techs=[f"T{1000 + i}"]),
                Severity.LOW,
            )
        assert store.open_count() == 3


class TestCat:
    def test_recon_cat6(self) -> None:
        assert _provisional_cat(1) == "CAT6"
        assert _provisional_cat(2) == "CAT6"

    def test_default_cat8_investigating(self) -> None:
        assert _provisional_cat(0) == "CAT8"
        assert _provisional_cat(11) == "CAT8"  # 권위 CAT1 은 report 아님

    def test_recon_alert_reaches_cat6(self) -> None:
        """정찰 tactic alert → CoverageMatrix order≤2 → CAT6 실제 도달(Codex Low)."""
        mgr = _mgr()
        recon = Alert(
            id="r1",
            scenario_id="S1",
            title="t",
            severity_baseline=Severity.LOW,
            signals=["sig"],
            mitre={"tactics": ["Reconnaissance"], "techniques": ["T1590"]},
            actor_id="APT-R",
        )
        c = mgr.observe_alert(recon, Severity.LOW)
        assert c is not None and c.cat == "CAT6"


class TestEndToEnd:
    @pytest.mark.asyncio
    async def test_report_exposes_incident_case(self) -> None:
        from agents.graph import build_soc_graph

        graph = build_soc_graph()
        state = await graph.ainvoke({"alert": _alert(aid="e2e", actor_id=None)})
        report = state["report"]
        assert report.incident_case is not None
        assert report.incident_case.state in (
            IncidentState.NEW,
            IncidentState.ANALYSIS,
        )
