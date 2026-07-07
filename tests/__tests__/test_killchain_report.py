"""kill chain report 노출 테스트 — 후반단계 도달 시 guardrail flag + metric."""

import pytest

from agents.report_agent import ReportAgent
from app.metrics import metrics
from core.models import Alert, Severity, SOCState, Verdict
from core.settings import Settings
from core.severity import SeverityEngine


def _state(*, advanced: bool) -> SOCState:
    return {
        "alert": Alert(
            id="a1",
            scenario_id="S2",
            title="t",
            severity_baseline=Severity.MEDIUM,
            signals=["sig"],
            kill_chain_advanced=advanced,
        ),
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
    }


class TestKillChainReport:
    @pytest.mark.asyncio
    async def test_advanced_adds_guardrail_flag(self) -> None:
        """후반단계 도달 시 guardrail_flags 에 kill chain 노출."""
        agent = ReportAgent(Settings(), SeverityEngine())

        out = await agent.run(_state(advanced=True))

        assert any("kill chain" in f.lower() for f in out["report"].guardrail_flags)

    @pytest.mark.asyncio
    async def test_advanced_increments_metric(self) -> None:
        """후반단계 도달 시 soc_killchain_advanced_total 증가."""
        agent = ReportAgent(Settings(), SeverityEngine())
        before = metrics().killchain_advanced_total

        await agent.run(_state(advanced=True))

        assert metrics().killchain_advanced_total == before + 1

    @pytest.mark.asyncio
    async def test_not_advanced_no_flag(self) -> None:
        """미도달이면 kill chain flag 없음."""
        agent = ReportAgent(Settings(), SeverityEngine())

        out = await agent.run(_state(advanced=False))

        assert not any("kill chain" in f.lower() for f in out["report"].guardrail_flags)
