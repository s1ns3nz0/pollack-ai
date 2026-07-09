"""Dashboard snapshot builder tests."""

from _pytest.monkeypatch import MonkeyPatch

from core.dashboard import TopologyPolicy, build_dashboard_snapshot
from core.exceptions import PolicyError
from core.models import (
    Alert,
    ApprovalResult,
    CampaignMatch,
    CommanderBrief,
    MissionContinuity,
    ResponseResult,
    Severity,
    SOCReport,
    SOCState,
    StagedDefense,
    Verdict,
)


def _state(
    *,
    approval: ApprovalResult | None = None,
    response_hitl: str | None = "HITL_REQUIRED",
    report_hitl: str | None = "HITL_REQUIRED",
    campaign_next_expected: str = "S117-BLOS-SATCOM-MITM",
    hunt_candidates: list[str] | None = None,
    staged_defenses: list[StagedDefense] | None = None,
) -> SOCState:
    alert = Alert(
        id="alert-001",
        scenario_id="S24-DATALINK-C2-TAKEOVER",
        title="비인가 C2 링크 장악",
        severity_baseline=Severity.HIGH,
        asset_id="C2_LINK",
        actor_id="RED-01",
        mitre={"tactic": "CommandAndControl", "technique": "T1071"},
        signals=["operator command anomaly"],
    )
    continuity = MissionContinuity(
        asset_id="C2_LINK",
        level="MINIMAL",
        capability_lost="실시간 지상 지휘통제",
        fallback="자율 페일세이프 모드 + 대체 링크 시도",
        sustains=False,
    )
    report = SOCReport(
        alert_id=alert.id,
        scenario_id=alert.scenario_id,
        title=alert.title,
        severity=Severity.HIGH,
        verdict=Verdict.TRUE_POSITIVE,
        action_taken="HITL 승인 대기",
        hitl=report_hitl,
        mitre={"tactic": "CommandAndControl", "technique": "T1071"},
        mission_continuity=continuity,
        hunt_candidates=hunt_candidates or [],
        staged_defenses=staged_defenses or [],
        campaign_matches=[
            CampaignMatch(
                chain_id="C2",
                name="C2 takeover",
                matched=2,
                total=4,
                next_expected=campaign_next_expected,
                severity="critical",
            )
        ],
        commander_brief=CommanderBrief(
            bluf="[결심필요] C2_LINK TRUE_POSITIVE/HIGH 임무 MINIMAL",
            confidence="authoritative",
            decision_required=["지휘관 결심: C2_LINK"],
            key_facts=["임무 지속성 MINIMAL"],
            caveats=["결심 여유 lower-bound"],
        ),
    )
    state: SOCState = {
        "alert": alert,
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
        "response": ResponseResult(
            hitl=response_hitl,
            mission_continuity=continuity,
            cacao_steps=[{"name": "대체 링크 전환"}, {"name": "RTB 준비"}],
        ),
        "report": report,
        "trace": ["triage", "investigation", "validation", "approval", "response"],
    }
    if approval is not None:
        state["approval"] = approval
    return state


def test_snapshot_summary_and_story_are_decision_first() -> None:
    """Snapshot exposes story summary before alert details."""
    snap = build_dashboard_snapshot(
        _state(
            approval=ApprovalResult(
                required=True,
                approved=False,
                note="승인 대기",
            )
        ),
        step=3,
        mode="replay",
    )

    assert snap.schema_version == "dashboard.snapshot.v1"
    assert snap.summary.active_story_count == 1
    assert snap.summary.max_mission_impact == "MINIMAL"
    assert snap.summary.hitl_pending_count == 1
    assert snap.stories[0].story_id == "RED-01"
    assert snap.stories[0].alerts[0].alert_id == "alert-001"


def test_snapshot_uses_commander_brief_for_bluf() -> None:
    """BLUF card preserves commander brief language and caveats."""
    snap = build_dashboard_snapshot(_state())

    assert snap.bluf.confidence == "authoritative"
    assert "C2_LINK" in snap.bluf.situation
    assert snap.bluf.caveats == ["결심 여유 lower-bound"]


def test_navigator_marks_current_predicted_and_gap() -> None:
    """Navigator exposes tactic states for the selected story."""
    snap = build_dashboard_snapshot(
        _state(
            staged_defenses=[
                StagedDefense(
                    technique="T1071",
                    status="gap",
                    tactic="CommandAndControl",
                    probability=0.8,
                )
            ]
        )
    )
    by_tactic = {cell.tactic: cell for cell in snap.navigator}

    assert by_tactic["CommandAndControl"].current is True
    assert by_tactic["CommandAndControl"].observed is True
    assert any(cell.predicted for cell in snap.navigator)
    assert by_tactic["CommandAndControl"].gap is True


def test_hitl_required_without_approval_stays_required() -> None:
    """Authoritative HITL signals stay required without creating pending state."""
    snap = build_dashboard_snapshot(_state(approval=None))

    assert snap.stories[0].hitl_status == "REQUIRED"
    assert snap.bluf.hitl_badge == "REQUIRED"
    assert snap.summary.hitl_pending_count == 0


def test_explicit_not_required_hitl_remains_not_required() -> None:
    """Explicit negative HITL signals do not create a required state."""
    snap = build_dashboard_snapshot(
        _state(
            approval=None,
            response_hitl="NOT_REQUIRED",
            report_hitl="NOT_REQUIRED",
        )
    )

    assert snap.stories[0].hitl_status == "NOT_REQUIRED"
    assert snap.summary.hitl_pending_count == 0
    assert snap.bluf.hitl_badge == "NOT_REQUIRED"


def test_navigator_uses_scenario_tactic_map_for_campaign_prediction(
    monkeypatch: MonkeyPatch,
) -> None:
    """Campaign next_expected resolves predicted tactic from authoritative map."""
    monkeypatch.setattr(
        "core.dashboard.scenario_tactic_map",
        lambda path=None: {"S117-BLOS-SATCOM-MITM": "Collection"},
    )

    snap = build_dashboard_snapshot(_state())
    by_tactic = {cell.tactic: cell for cell in snap.navigator}

    assert by_tactic["Collection"].predicted is True
    assert by_tactic["CommandAndControl"].predicted is False


def test_blank_staged_defense_tactic_falls_back_to_campaign_prediction(
    monkeypatch: MonkeyPatch,
) -> None:
    """Blank staged defense tactics do not suppress campaign prediction."""
    monkeypatch.setattr(
        "core.dashboard.scenario_tactic_map",
        lambda path=None: {"S117-BLOS-SATCOM-MITM": "Collection"},
    )

    snap = build_dashboard_snapshot(
        _state(
            staged_defenses=[
                StagedDefense(
                    technique="T1071",
                    status="gap",
                    tactic="",
                    probability=0.8,
                )
            ]
        )
    )
    by_tactic = {cell.tactic: cell for cell in snap.navigator}

    assert by_tactic["Collection"].predicted is True


def test_hunt_candidates_do_not_mark_predicted_tactic(
    monkeypatch: MonkeyPatch,
) -> None:
    """Technique-only hunt candidates do not drive navigator predicted tactic."""
    monkeypatch.setattr("core.dashboard.scenario_tactic_map", lambda path=None: {})

    snap = build_dashboard_snapshot(
        _state(campaign_next_expected="", hunt_candidates=["T1071"])
    )

    assert all(cell.predicted is False for cell in snap.navigator)


def test_topology_highlights_degraded_asset_node() -> None:
    """C2_LINK mission continuity maps to datalink topology node."""
    snap = build_dashboard_snapshot(_state(), topology=TopologyPolicy.from_yaml())
    nodes = {node.id: node for node in snap.topology.nodes}

    assert nodes["datalink-los"].active is True
    assert nodes["datalink-los"].status == "MINIMAL"


def test_coverage_load_failure_degrades_navigator_without_aborting(
    monkeypatch: MonkeyPatch,
) -> None:
    """Coverage policy failures degrade navigator and preserve snapshot output."""
    monkeypatch.setattr(
        "core.dashboard._coverage_cells",
        lambda: (_ for _ in ()).throw(PolicyError("attack coverage load failed")),
    )

    snap = build_dashboard_snapshot(_state(), topology=TopologyPolicy.from_yaml())

    assert snap.navigator == []
    assert any(
        "coverage overlay unavailable" in caveat.lower() for caveat in snap.bluf.caveats
    )
