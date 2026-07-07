"""MissionContinuity report 노출 테스트 — 정탐 자산 손상 → 지속성 제시 + ABORT 계측."""

import pytest

from agents.report_agent import ReportAgent
from app.metrics import metrics
from core.degradation import DegradationAssessor, DegradationMatrix
from core.models import Alert, Severity, SOCState, Verdict
from core.settings import Settings
from core.severity import SeverityEngine


def _assessor() -> DegradationAssessor:
    return DegradationAssessor(DegradationMatrix.from_yaml())


def _state(verdict: Verdict, asset: str) -> SOCState:
    return {
        "alert": Alert(
            id="a1",
            scenario_id="S1",
            title="t",
            asset_id=asset,
            severity_baseline=Severity.HIGH,
            signals=["sig"],
        ),
        "severity": Severity.HIGH,
        "verdict": verdict,
    }


class TestDegradationReport:
    @pytest.mark.asyncio
    async def test_tp_exposes_continuity(self) -> None:
        """정탐 + GNSS 손상 → mission_continuity 노출(SUSTAINED)."""
        agent = ReportAgent(Settings(), SeverityEngine(), degradation=_assessor())

        out = await agent.run(_state(Verdict.TRUE_POSITIVE, "GNSS"))

        mc = out["report"].mission_continuity
        assert mc is not None
        assert mc.level == "SUSTAINED"
        assert mc.fallback

    @pytest.mark.asyncio
    async def test_abort_increments_metric(self) -> None:
        """ABORT 등급(AUTOPILOT) → soc_mission_abort_total 증가."""
        agent = ReportAgent(Settings(), SeverityEngine(), degradation=_assessor())
        before = metrics().mission_abort_total

        await agent.run(_state(Verdict.TRUE_POSITIVE, "AUTOPILOT"))

        assert metrics().mission_abort_total == before + 1

    @pytest.mark.asyncio
    async def test_sustained_no_abort_metric(self) -> None:
        """SUSTAINED 는 abort 카운터 불변."""
        agent = ReportAgent(Settings(), SeverityEngine(), degradation=_assessor())
        before = metrics().mission_abort_total

        await agent.run(_state(Verdict.TRUE_POSITIVE, "GNSS"))

        assert metrics().mission_abort_total == before

    @pytest.mark.asyncio
    async def test_no_assessor_none(self) -> None:
        """assessor 미주입 시 None(하위호환)."""
        agent = ReportAgent(Settings(), SeverityEngine())

        out = await agent.run(_state(Verdict.TRUE_POSITIVE, "GNSS"))

        assert out["report"].mission_continuity is None
