"""IoA 그래프 report 배선 — SOCReport.ioa_graph 채움(시각화용, 읽기전용).

빌더 자체 로직은 test_ioa_graph.py 커버. 여기선 report_agent 배선만 검증.
"""

import pytest

from agents.report_agent import ReportAgent
from core.models import (
    Alert,
    AttackPrediction,
    CausalChain,
    CausalStep,
    InvestigationResult,
    Severity,
    SOCState,
    Verdict,
)
from core.settings import Settings
from core.severity import SeverityEngine


class _StubReasoner:
    """인과 체인 스텁 — profile·inv 없이 causal-only 리포트 구성용."""

    async def build_chain(
        self, alert: Alert, inv: InvestigationResult | None
    ) -> CausalChain:
        return CausalChain(
            steps=[
                CausalStep(
                    signal="GPS_GLITCH", effect="GNSS_LOSS", mitre_technique="T1059"
                )
            ]
        )


def _alert() -> Alert:
    return Alert(
        id="a1",
        scenario_id="S1",
        title="t",
        severity_baseline=Severity.MEDIUM,
        signals=["sig"],
    )


def _state(inv: InvestigationResult | None) -> SOCState:
    state: SOCState = {
        "alert": _alert(),
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
    }
    if inv is not None:
        state["investigation"] = inv
    return state


class TestIoaGraphReport:
    @pytest.mark.asyncio
    async def test_predictions_populate_ioa_graph(self) -> None:
        """예측이 있는 investigation → report.ioa_graph 에 노드 존재."""
        inv = InvestigationResult(
            predictions=[
                AttackPrediction(
                    next_technique="T1059",
                    probability=0.7,
                    support_count=3,
                    basis_actor_id="team-red",
                )
            ]
        )
        out = await ReportAgent(Settings(), SeverityEngine()).run(_state(inv))
        ioa = out["report"].ioa_graph
        assert isinstance(ioa, dict)
        assert ioa["nodes"]  # 비어있지 않음
        # Cytoscape 형태: 각 노드는 data.id/label/type 보유
        for node in ioa["nodes"]:
            data = node["data"]
            assert "id" in data and "label" in data and "type" in data
        assert any(n["data"]["type"] == "prediction" for n in ioa["nodes"])

    @pytest.mark.asyncio
    async def test_no_graph_data_yields_none(self) -> None:
        """investigation 은 있으나 그래프 데이터(예측) 없음 → ioa_graph None."""
        out = await ReportAgent(Settings(), SeverityEngine()).run(
            _state(InvestigationResult())
        )
        assert out["report"].ioa_graph is None

    @pytest.mark.asyncio
    async def test_no_profile_no_investigation_yields_none(self) -> None:
        """profile·investigation 둘 다 없음 → 빌드 생략, ioa_graph None."""
        out = await ReportAgent(Settings(), SeverityEngine()).run(_state(None))
        assert out["report"].ioa_graph is None

    @pytest.mark.asyncio
    async def test_causal_only_populates_ioa_graph(self) -> None:
        """profile·inv 없이 causal 만 있어도 IoA 그래프 생성(Codex diff Medium)."""
        agent = ReportAgent(Settings(), SeverityEngine(), reasoner=_StubReasoner())
        out = await agent.run(_state(None))
        ioa = out["report"].ioa_graph
        assert isinstance(ioa, dict)
        assert ioa["nodes"]
        assert any(n["data"]["type"] == "effect" for n in ioa["nodes"])
