from __future__ import annotations

from core.active_hunt import ActiveHuntPlanner, ActiveHuntPolicy
from core.models import Alert, AttackPrediction, MissionRisk
from tools.coverage import Archetype, CoverageMatrix, TacticCoverage


def _coverage() -> CoverageMatrix:
    tactics = [
        TacticCoverage(name="InitialAccess", order=3, covered=["T1133"]),
        TacticCoverage(name="Discovery", order=8, covered=["T0842"]),
        TacticCoverage(name="LateralMovement", order=9, covered=["T1563"]),
        TacticCoverage(name="CommandAndControl", order=11, covered=["T1071"]),
        TacticCoverage(name="Exfiltration", order=12, covered=["T1041"]),
        TacticCoverage(name="Impact", order=15, covered=["T1485"]),
    ]
    return CoverageMatrix(tactics, {"A": Archetype(id="A")})


def _alert(tactic: str = "CommandAndControl") -> Alert:
    return Alert(
        id="a1",
        scenario_id="S2-C2-HIJACK",
        title="C2 hijack",
        asset_id="UAV-1",
        asset_tier="T2-Important",
        mission_phase="ISR",
        severity_baseline="m",
        mitre={"techniques": ["T1071"], "tactics": [tactic]},
        signals=["지상국 미발신 명령 수신"],
        iocs=[],
        cves=[],
        sbom_components=[],
    )


def _risk(score: int, key: bool = False) -> MissionRisk:
    return MissionRisk(
        asset_id="UAV-1",
        mission_phase="ISR",
        score=score,
        is_key_terrain=key,
        dependents=[],
        factors={"score": score},
        rationale=[f"score={score}"],
    )


def test_policy_defaults_load() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    assert policy.limits.max_queries_per_alert == 5
    assert policy.limits.row_limit == 20
    assert policy.windows.forward_default_minutes == 30
    assert policy.windows.backward_force_hours == 72


def test_cpcon_threshold_controls_backward_hunt() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    cov = _coverage()
    assert policy.should_backward_hunt(_alert("Discovery"), None, 8, 5, cov) is False
    assert policy.should_backward_hunt(_alert("Discovery"), None, 8, 2, cov) is True


def test_key_terrain_and_mission_risk_lower_backward_threshold() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    cov = _coverage()
    alert = _alert("Discovery").model_copy(update={"key_terrain": True})
    assert policy.should_backward_hunt(alert, _risk(8, key=True), 8, 5, cov) is True


def test_force_tactic_always_runs_backward_hunt() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    cov = _coverage()
    assert policy.should_backward_hunt(_alert("Impact"), None, 15, 5, cov) is True


def test_forward_planner_uses_registered_template_only() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    planner = ActiveHuntPlanner(policy, _coverage())
    plan = planner.plan(
        _alert("InitialAccess"),
        [
            AttackPrediction(
                next_technique="T1133",
                probability=0.9,
                support_count=3,
                basis_actor_id="actor-1",
            )
        ],
        None,
        cpcon_level=5,
    )
    queries = plan.queries
    assert [q.technique for q in queries] == ["T1133"]
    assert queries[0].direction == "forward"
    assert "UAVGcsAccess_CL" in queries[0].kql
    assert "{start}" not in queries[0].kql
    assert "{end}" not in queries[0].kql


def test_missing_template_becomes_unavailable_finding() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    planner = ActiveHuntPlanner(policy, _coverage())
    plan = planner.plan(
        _alert("InitialAccess"),
        [
            AttackPrediction(
                next_technique="T9999",
                probability=0.9,
                support_count=3,
                basis_actor_id="actor-1",
            )
        ],
        None,
        cpcon_level=5,
    )
    finding = plan.unavailable_findings[0]
    assert finding.direction == "forward"
    assert finding.technique == "T9999"
    assert finding.query_id == "query_unavailable"
    assert finding.error == "query template unavailable"
