"""Dashboard snapshot builder tests."""

from core.dashboard import TopologyPolicy, build_dashboard_snapshot
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
    Verdict,
)


def _state() -> SOCState:
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
        hitl="HITL_REQUIRED",
        mitre={"tactic": "CommandAndControl", "technique": "T1071"},
        mission_continuity=continuity,
        campaign_matches=[
            CampaignMatch(
                chain_id="C2",
                name="C2 takeover",
                matched=2,
                total=4,
                next_expected="S117-BLOS-SATCOM-MITM",
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
    return {
        "alert": alert,
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
        "approval": ApprovalResult(required=True, approved=False, note="승인 대기"),
        "response": ResponseResult(
            hitl="HITL_REQUIRED",
            mission_continuity=continuity,
            cacao_steps=[{"name": "대체 링크 전환"}, {"name": "RTB 준비"}],
        ),
        "report": report,
        "trace": ["triage", "investigation", "validation", "approval", "response"],
    }


def test_snapshot_summary_and_story_are_decision_first() -> None:
    """Snapshot exposes story summary before alert details."""
    snap = build_dashboard_snapshot(_state(), step=3, mode="replay")

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
    snap = build_dashboard_snapshot(_state())
    by_tactic = {cell.tactic: cell for cell in snap.navigator}

    assert by_tactic["CommandAndControl"].current is True
    assert by_tactic["CommandAndControl"].observed is True
    assert any(cell.predicted for cell in snap.navigator)
    assert by_tactic["CommandAndControl"].gap is True


def test_topology_highlights_degraded_asset_node() -> None:
    """C2_LINK mission continuity maps to datalink topology node."""
    snap = build_dashboard_snapshot(_state(), topology=TopologyPolicy.from_yaml())
    nodes = {node.id: node for node in snap.topology.nodes}

    assert nodes["datalink-los"].active is True
    assert nodes["datalink-los"].status == "MINIMAL"
