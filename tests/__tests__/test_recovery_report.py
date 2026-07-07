"""RecoveryPlan report 노출 테스트 — 정탐 확정 시 축출/복구 절차 제시."""

import pytest

from agents.report_agent import ReportAgent
from core.models import Alert, Severity, SOCState, Verdict
from core.recovery import RecoveryMatrix, RecoveryPlanner
from core.settings import Settings
from core.severity import SeverityEngine
from tools.coverage import CoverageMatrix


def _planner() -> RecoveryPlanner:
    return RecoveryPlanner(CoverageMatrix.from_yaml(), RecoveryMatrix.from_yaml())


def _state(verdict: Verdict, tactics: list[str]) -> SOCState:
    return {
        "alert": Alert(
            id="a1",
            scenario_id="S2",
            title="t",
            severity_baseline=Severity.HIGH,
            signals=["sig"],
            mitre={"tactics": tactics},
        ),
        "severity": Severity.HIGH,
        "verdict": verdict,
    }


class TestRecoveryReport:
    @pytest.mark.asyncio
    async def test_tp_exposes_recovery_plan(self) -> None:
        """정탐 확정 + C2 도달 → report.recovery_plan 노출."""
        agent = ReportAgent(Settings(), SeverityEngine(), recovery_planner=_planner())

        out = await agent.run(_state(Verdict.TRUE_POSITIVE, ["CommandAndControl"]))

        plan = out["report"].recovery_plan
        assert plan is not None
        assert plan.tactic == "CommandAndControl"
        assert plan.evict_steps and plan.restore_steps

    @pytest.mark.asyncio
    async def test_fp_no_recovery_plan(self) -> None:
        """오탐은 recovery 불필요 — 플랜 None."""
        agent = ReportAgent(Settings(), SeverityEngine(), recovery_planner=_planner())

        out = await agent.run(_state(Verdict.FALSE_POSITIVE, ["CommandAndControl"]))

        assert out["report"].recovery_plan is None

    @pytest.mark.asyncio
    async def test_no_planner_none(self) -> None:
        """planner 미주입 시 None(하위호환)."""
        agent = ReportAgent(Settings(), SeverityEngine())

        out = await agent.run(_state(Verdict.TRUE_POSITIVE, ["Impact"]))

        assert out["report"].recovery_plan is None
