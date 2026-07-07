"""COA report 노출 테스트 — 현재+예측 단계 방어 옵션이 report 에 실림."""

import pytest

from agents.report_agent import ReportAgent
from core.actors import (
    ActorReadGate,
    InMemoryActorStore,
    Sha256ActorSigner,
)
from core.coa import CoaMatrix, CoaPlanner
from core.models import (
    ActorProfile,
    ActorTtpStat,
    Alert,
    AttackPrediction,
    InvestigationResult,
    Severity,
    SOCState,
    Verdict,
)
from core.settings import Settings
from core.severity import SeverityEngine
from tools.coverage import CoverageMatrix


async def _actor_read(store: InMemoryActorStore, tactics: list[str]) -> ActorReadGate:
    signer = Sha256ActorSigner()
    p = ActorProfile(
        actor_id="APT-C",
        is_explicit=True,
        ttp_stats=[
            ActorTtpStat(tactic=t, technique=f"T{i}", count=1, last_seen="t")
            for i, t in enumerate(tactics)
        ],
    )
    p.content_hash = p.fingerprint()
    p.signature = signer.sign(p.content_hash)
    await store.awrite(p)
    return ActorReadGate(store)


def _planner() -> CoaPlanner:
    return CoaPlanner(CoverageMatrix.from_yaml(), CoaMatrix.from_yaml())


class TestCoaReport:
    @pytest.mark.asyncio
    async def test_coa_options_exposed(self) -> None:
        """actor C2 단계 도달 → report.coa_options 에 current COA 노출."""
        store = InMemoryActorStore()
        read = await _actor_read(store, ["CommandAndControl"])
        agent = ReportAgent(
            Settings(), SeverityEngine(), actor_read=read, coa_planner=_planner()
        )
        state: SOCState = {
            "alert": Alert(
                id="a1",
                scenario_id="S2",
                title="t",
                severity_baseline=Severity.HIGH,
                signals=["sig"],
                mitre={"tactics": ["CommandAndControl"]},
                actor_id="APT-C",
            ),
            "severity": Severity.HIGH,
            "verdict": Verdict.TRUE_POSITIVE,
        }

        out = await agent.run(state)

        coa = out["report"].coa_options
        assert coa
        assert any(o.stage == "current" for o in coa)
        assert any(o.status == "available" for o in coa)

    @pytest.mark.asyncio
    async def test_predicted_coa_from_investigation(self) -> None:
        """investigation.predictions → predicted 단계 COA 노출."""
        store = InMemoryActorStore()
        read = await _actor_read(store, ["Execution"])
        agent = ReportAgent(
            Settings(), SeverityEngine(), actor_read=read, coa_planner=_planner()
        )
        state: SOCState = {
            "alert": Alert(
                id="a1",
                scenario_id="S2",
                title="t",
                severity_baseline=Severity.HIGH,
                signals=["sig"],
                mitre={"tactics": ["Execution"]},
                actor_id="APT-C",
            ),
            "severity": Severity.HIGH,
            "verdict": Verdict.TRUE_POSITIVE,
            "investigation": InvestigationResult(
                predictions=[
                    AttackPrediction(
                        next_technique="T1590",  # Reconnaissance
                        probability=0.8,
                        support_count=3,
                        basis_actor_id="APT-C",
                    )
                ]
            ),
        }

        out = await agent.run(state)

        assert any(o.stage == "predicted" for o in out["report"].coa_options)

    @pytest.mark.asyncio
    async def test_no_planner_no_coa(self) -> None:
        """planner 미주입 시 coa_options 빈 리스트(하위호환)."""
        agent = ReportAgent(Settings(), SeverityEngine())
        state: SOCState = {
            "alert": Alert(
                id="a1",
                scenario_id="S2",
                title="t",
                severity_baseline=Severity.HIGH,
                signals=["sig"],
                mitre={"tactics": ["Impact"]},
            ),
            "severity": Severity.HIGH,
            "verdict": Verdict.TRUE_POSITIVE,
        }

        out = await agent.run(state)

        assert out["report"].coa_options == []
