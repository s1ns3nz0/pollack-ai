"""STRIDE report 노출 테스트 — 공격 위협 유형 분류가 report 에 실림."""

import pytest

from agents.report_agent import ReportAgent
from core.models import Alert, Severity, SOCState, Verdict
from core.settings import Settings
from core.severity import SeverityEngine
from core.stride import StrideClassifier, StrideModel


def _classifier() -> StrideClassifier:
    return StrideClassifier(StrideModel.from_yaml())


def _state(stride: list[str]) -> SOCState:
    return {
        "alert": Alert(
            id="a1",
            scenario_id="S2",
            title="t",
            severity_baseline=Severity.HIGH,
            signals=["sig"],
            mitre={"tactics": ["CommandAndControl"], "stride": stride},
        ),
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
    }


class TestStrideReport:
    @pytest.mark.asyncio
    async def test_stride_threats_exposed(self) -> None:
        """공격 STRIDE 태그 → report.stride_threats 노출 + 완화책."""
        agent = ReportAgent(Settings(), SeverityEngine(), stride=_classifier())

        out = await agent.run(_state(["S", "E"]))

        threats = out["report"].stride_threats
        codes = {t.code for t in threats}
        assert codes == {"S", "E"}
        assert all(t.mitigation for t in threats)

    @pytest.mark.asyncio
    async def test_no_classifier_empty(self) -> None:
        """classifier 미주입 시 빈 리스트(하위호환)."""
        agent = ReportAgent(Settings(), SeverityEngine())

        out = await agent.run(_state(["T"]))

        assert out["report"].stride_threats == []
