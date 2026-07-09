from __future__ import annotations

from pathlib import Path

import pytest

from core.active_hunt import ActiveHuntPlanner, ActiveHuntPolicy
from core.exceptions import PolicyError
from core.models import Alert, AttackPrediction, MissionRisk
from tools.coverage import Archetype, CoverageMatrix, TacticCoverage


def _coverage() -> CoverageMatrix:
    tactics = [
        TacticCoverage(
            name="InitialAccess",
            order=3,
            covered=["T1133"],
            planned=["T1190"],
        ),
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
        time_generated="2026-07-09T12:00:00Z",
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


def test_forward_planner_uses_time_generated_for_exact_window() -> None:
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
    query = plan.queries[0]
    assert "2026-07-09T12:00:00Z" in query.kql
    assert "2026-07-09T12:30:00Z" in query.kql
    assert query.time_window == "2026-07-09T12:00:00Z..2026-07-09T12:30:00Z"


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


def test_backward_planner_records_untemplated_previous_techniques() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    planner = ActiveHuntPlanner(policy, _coverage())
    plan = planner.plan(
        _alert("CommandAndControl"),
        [],
        None,
        cpcon_level=5,
    )
    assert any(
        query.direction == "backward" and query.technique == "T1133"
        for query in plan.queries
    )
    finding = next(
        finding
        for finding in plan.unavailable_findings
        if finding.direction == "backward" and finding.technique == "T1190"
    )
    assert finding.tactic == "InitialAccess"
    assert finding.query_id == "query_unavailable"
    assert finding.error == "query template unavailable"


def test_backward_planner_uses_default_lookback_window() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    planner = ActiveHuntPlanner(policy, _coverage())
    plan = planner.plan(
        _alert("CommandAndControl"),
        [],
        None,
        cpcon_level=5,
    )
    query = next(query for query in plan.queries if query.direction == "backward")
    assert "2026-07-08T12:00:00Z" in query.kql
    assert "2026-07-09T12:00:00Z" in query.kql
    assert query.time_window == "2026-07-08T12:00:00Z..2026-07-09T12:00:00Z"


def test_backward_planner_uses_forced_impact_lookback_window() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    planner = ActiveHuntPlanner(policy, _coverage())
    plan = planner.plan(
        _alert("Impact"),
        [],
        None,
        cpcon_level=5,
    )
    query = next(query for query in plan.queries if query.direction == "backward")
    assert "2026-07-06T12:00:00Z" in query.kql
    assert "2026-07-09T12:00:00Z" in query.kql
    assert query.time_window == "2026-07-06T12:00:00Z..2026-07-09T12:00:00Z"


def test_policy_loader_rejects_non_mapping_query_entries(tmp_path: Path) -> None:
    policy_path = tmp_path / "active-hunt.yaml"
    policy_path.write_text(
        """
version: 0.1
queries:
  bad_query:
    - not
    - a
    - mapping
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="active hunt queries 항목 구조 오류"):
        ActiveHuntPolicy.from_yaml(policy_path)
