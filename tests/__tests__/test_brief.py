"""Commander Brief(BLUF) — 결정론 합성·정직성 세탁 금지·fail-safe 분기."""

from core.brief import CommanderBriefBuilder
from core.models import (
    Alert,
    CommanderBrief,
    DecisionAdvantage,
    IncidentCase,
    IncidentState,
    IntentAssessment,
    KillWebResilience,
    MissionContinuity,
    Severity,
    SOCReport,
    Verdict,
)


def _alert(**kw: object) -> Alert:
    base: dict[str, object] = {
        "id": "a1",
        "scenario_id": "S2",
        "title": "t",
        "severity_baseline": Severity.HIGH,
    }
    base.update(kw)
    return Alert.model_validate(base)


def _report(**kw: object) -> SOCReport:
    base: dict[str, object] = {
        "alert_id": "a1",
        "scenario_id": "S2",
        "title": "t",
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
        "recommended_action": "response",
    }
    base.update(kw)
    return SOCReport.model_validate(base)


def _case(provisional: bool, cat: str = "CAT4") -> IncidentCase:
    return IncidentCase(
        case_id="c1",
        actor_id="APT-X",
        state=IncidentState.ANALYSIS,
        cat=cat,
        severity_peak=Severity.HIGH,
        provisional=provisional,
    )


def _build(report: SOCReport, alert: Alert | None = None) -> CommanderBrief:
    return CommanderBriefBuilder().build(report, alert or _alert())


class TestConfidence:
    def test_provisional_not_laundered(self) -> None:
        """provisional case → confidence provisional + BLUF '(미확증)'(세탁 금지)."""
        b = _build(_report(incident_case=_case(provisional=True)))
        assert b.confidence == "provisional"
        assert "(미확증)" in b.bluf
        assert any("미확증" in c for c in b.caveats)

    def test_authoritative(self) -> None:
        b = _build(_report(incident_case=_case(provisional=False)))
        assert b.confidence == "authoritative"
        assert "(미확증)" not in b.bluf

    def test_no_case_unknown(self) -> None:
        b = _build(_report())
        assert b.confidence == "unknown"
        assert any("확신도 판정 불가" in c for c in b.caveats)

    def test_none_provisional_not_laundered_to_authoritative(self) -> None:
        """방어 — provisional None 이면 authoritative 세탁 금지·unknown(Codex High)."""
        case = _case(provisional=True).model_copy(update={"provisional": None})
        b = _build(_report(incident_case=case))
        assert b.confidence == "unknown"


class TestNoLaundering:
    def test_decision_advantage_unknown_not_margin(self) -> None:
        """da verdict unknown → BLUF 에 그대로 unknown(margin 위장 금지)."""
        da = DecisionAdvantage(
            verdict="unknown",
            basis=[
                "적-OODA 직접비교 아님",
                "적 진행 cadence 측정 불가(양의 델타 없음)",
            ],
        )
        b = _build(_report(decision_advantage=da))
        assert "결심여유 unknown" in b.bluf
        assert "margin" not in b.bluf
        assert any("측정 불가" in c for c in b.caveats)  # basis 전체 승계

    def test_killweb_breadth_caveat_propagated(self) -> None:
        """kill_web '기법 수 ≠ 독립 센서' 주석 승계(SPOF-free 위장 금지)."""
        kw = KillWebResilience(
            coverage_breadth_ratio=0.8,
            rationale=["기법 수 ≠ 독립 센서/로그원 — breadth 지표(SPOF 미증명)"],
        )
        b = _build(_report(kill_web_resilience=kw))
        assert any("독립 센서" in c for c in b.caveats)

    def test_da_comparison_caveat_always(self) -> None:
        da = DecisionAdvantage(verdict="margin", basis=["적-OODA 직접비교 아님"])
        b = _build(_report(decision_advantage=da))
        assert any("직접비교 아님" in c for c in b.caveats)


class TestFailSafeSplit:
    def test_no_intent_all_decision_required(self) -> None:
        b = _build(_report())
        assert b.decision_required and not b.routine

    def test_degraded_intent_decision_required(self) -> None:
        """intent_available=False(degraded)도 전부 decision_required(Codex High)."""
        ia = IntentAssessment(decision_class="surfaced", intent_available=False)
        b = _build(_report(intent_assessment=ia))
        assert b.decision_required and not b.routine

    def test_routine_soc_when_available(self) -> None:
        ia = IntentAssessment(
            decision_class="routine_soc",
            intent_available=True,
            matched=["delegate_cat:CAT6"],
        )
        b = _build(_report(intent_assessment=ia))
        assert b.routine and not b.decision_required

    def test_commander_decision(self) -> None:
        ia = IntentAssessment(
            priority="main_effort",
            decision_class="commander_decision",
            intent_available=True,
            matched=["main_effort:SAT"],
        )
        b = _build(_report(intent_assessment=ia), _alert(asset_id="SAT"))
        assert b.decision_required and not b.routine
        assert b.bluf.startswith("[결심필요]")
        assert "[주력]" in b.bluf

    def test_surfaced_is_decision_required(self) -> None:
        ia = IntentAssessment(decision_class="surfaced", intent_available=True)
        b = _build(_report(intent_assessment=ia))
        assert b.decision_required and not b.routine


class TestSynthesis:
    def test_key_facts_fixed_order(self) -> None:
        r = _report(
            incident_case=_case(provisional=False),
            mission_continuity=MissionContinuity(
                asset_id="x", level="MINIMAL", capability_lost="ISR"
            ),
        )
        b = _build(r)
        assert b.key_facts[0].startswith("판정")
        assert any("CAT4" in f for f in b.key_facts)
        assert any("임무 지속성 MINIMAL" in f for f in b.key_facts)

    def test_ooda_inherited(self) -> None:
        da = DecisionAdvantage(verdict="margin", ooda={"observe": ["signals"]})
        b = _build(_report(decision_advantage=da))
        assert b.ooda == {"observe": ["signals"]}

    def test_pure_no_mutation(self) -> None:
        """빌더는 순수 — report/alert 변이 없음(합성만)."""
        r = _report(incident_case=_case(provisional=True))
        alert = _alert()
        _build(r, alert)
        assert r.verdict == Verdict.TRUE_POSITIVE and r.commander_brief is None
        assert alert.id == "a1"
