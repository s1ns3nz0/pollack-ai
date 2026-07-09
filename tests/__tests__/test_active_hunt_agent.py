"""ActiveHuntAgent tests."""

from __future__ import annotations

from agents.active_hunt_agent import ActiveHuntAgent
from core.active_hunt import ActiveHuntPlanner, ActiveHuntPolicy
from core.models import (
    Alert,
    AttackPrediction,
    InvestigationResult,
    MissionRisk,
    Severity,
)
from core.settings import Settings
from tools.coverage import Archetype, CoverageMatrix, TacticCoverage
from tools.sentinel_query_tool import SentinelQueryResult


class _FakeClient:
    def __init__(self, result: SentinelQueryResult | Exception) -> None:
        self.result = result
        self.queries: list[str] = []

    async def aquery(self, kql: str, timeout_seconds: float) -> SentinelQueryResult:
        del timeout_seconds
        self.queries.append(kql)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _coverage() -> CoverageMatrix:
    return CoverageMatrix(
        [
            TacticCoverage(name="InitialAccess", order=3, covered=["T1133"]),
            TacticCoverage(name="CommandAndControl", order=11, covered=["T1071"]),
        ],
        {"A": Archetype(id="A")},
    )


def _state(
    predictions: list[AttackPrediction] | None = None,
) -> dict[str, object]:
    alert = Alert(
        id="a1",
        scenario_id="S2-C2-HIJACK",
        title="C2 hijack",
        time_generated="2026-07-09T12:00:00Z",
        asset_id="UAV-1",
        asset_tier="T2-Important",
        mission_phase="ISR",
        severity_baseline=Severity.MEDIUM,
        mitre={"techniques": ["T1071"], "tactics": ["CommandAndControl"]},
        signals=["지상국 미발신 명령 수신"],
        iocs=[],
        cves=[],
        sbom_components=[],
    )
    inv = InvestigationResult(
        predictions=predictions
        or [
            AttackPrediction(
                next_technique="T1133",
                probability=0.9,
                support_count=3,
                basis_actor_id="actor-1",
            )
        ]
    )
    return {
        "alert": alert,
        "investigation": inv,
        "mission_risk": MissionRisk(asset_id="UAV-1", score=0, factors={}),
    }


async def test_agent_returns_matched_finding_and_unavailable_findings() -> None:
    client = _FakeClient(
        SentinelQueryResult(rows=[{"ClientIp": "203.0.113.66"}], row_count=1)
    )
    agent = ActiveHuntAgent(
        Settings(active_hunt_enabled=True),
        ActiveHuntPlanner(ActiveHuntPolicy.from_yaml(), _coverage()),
        client,
        cpcon_level=5,
    )

    out = await agent.run(
        _state(
            [
                AttackPrediction(
                    next_technique="T1133",
                    probability=0.9,
                    support_count=3,
                    basis_actor_id="actor-1",
                ),
                AttackPrediction(
                    next_technique="T9999",
                    probability=0.4,
                    support_count=1,
                    basis_actor_id="actor-1",
                ),
            ]
        )  # type: ignore[arg-type]
    )

    findings = out["active_hunt_findings"]
    assert findings[0].query_id == "query_unavailable"
    assert findings[0].error == "query template unavailable"
    assert findings[1].matched is True
    assert findings[1].row_count == 1
    assert findings[1].sample == [{"ClientIp": "203.0.113.66"}]
    assert out["trace"] == ["active_hunt"]


async def test_agent_returns_no_result_finding() -> None:
    client = _FakeClient(SentinelQueryResult(rows=[], row_count=0))
    agent = ActiveHuntAgent(
        Settings(active_hunt_enabled=True),
        ActiveHuntPlanner(ActiveHuntPolicy.from_yaml(), _coverage()),
        client,
        cpcon_level=5,
    )

    out = await agent.run(_state())  # type: ignore[arg-type]

    finding = out["active_hunt_findings"][0]
    assert finding.matched is False
    assert finding.row_count == 0
    assert finding.error == ""


async def test_agent_carries_query_result_error_into_finding() -> None:
    client = _FakeClient(
        SentinelQueryResult(
            rows=[{"ClientIp": "203.0.113.66"}],
            row_count=1,
            error="partial query failure",
        )
    )
    agent = ActiveHuntAgent(
        Settings(active_hunt_enabled=True),
        ActiveHuntPlanner(ActiveHuntPolicy.from_yaml(), _coverage()),
        client,
        cpcon_level=5,
    )

    out = await agent.run(_state())  # type: ignore[arg-type]

    finding = out["active_hunt_findings"][0]
    assert finding.matched is True
    assert finding.error == "partial query failure"


async def test_agent_converts_query_exception_to_error_finding() -> None:
    client = _FakeClient(RuntimeError("boom"))
    agent = ActiveHuntAgent(
        Settings(active_hunt_enabled=True),
        ActiveHuntPlanner(ActiveHuntPolicy.from_yaml(), _coverage()),
        client,
        cpcon_level=5,
    )

    out = await agent.run(_state())  # type: ignore[arg-type]

    finding = out["active_hunt_findings"][0]
    assert finding.matched is False
    assert finding.error == "boom"
