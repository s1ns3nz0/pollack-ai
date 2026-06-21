"""시뮬 텔레메트리 → 탐지 → 6-에이전트 SOC 브리지.

telemetry-tap NDJSON 스트림을 받아 GpsSpoofDetector 로 이상을 잡고, 탐지 시
`Alert` 를 만들어 SOC 그래프(`build_soc_graph`)에 투입한 결과를 `BridgeEvent` 로
돌려준다. retriever/llm 을 주입하면 실 RAG/LLM, 미주입이면 결정론(오프라인 테스트).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import cast

from pydantic import BaseModel

from agents.graph import build_soc_graph
from agents.investigation_agent import ContextRetriever
from core.llm import LLMClient
from core.models import Alert, SOCReport, SOCState
from sim_bridge.detector import GpsSpoofDetector
from sim_bridge.models import TelemetryRecord


class BridgeEvent(BaseModel):
    """탐지 1건 + SOC 처리 결과."""

    alert: Alert
    report: SOCReport
    severity_rationale: list[str]
    similar_cases: list[str]
    summary: str
    guardrail_flags: list[str]


class SimBridge:
    """telemetry-tap → 탐지 → SOC 파이프라인 연결."""

    def __init__(
        self,
        retriever: ContextRetriever | None = None,
        llm: LLMClient | None = None,
        detector: GpsSpoofDetector | None = None,
    ) -> None:
        self._retriever = retriever
        self._llm = llm
        self._detector = detector or GpsSpoofDetector()

    async def process(self, record: TelemetryRecord) -> BridgeEvent | None:
        """레코드 1건 처리. 탐지 시 SOC 실행 후 BridgeEvent, 아니면 None."""
        alert = self._detector.observe(record)
        if alert is None:
            return None
        graph = build_soc_graph(retriever=self._retriever, llm=self._llm)
        state = cast(SOCState, await graph.ainvoke({"alert": alert}))
        inv = state["investigation"]
        return BridgeEvent(
            alert=alert,
            report=state["report"],
            severity_rationale=state["severity_rationale"],
            similar_cases=[c.source for c in inv.similar_cases],
            summary=inv.summary,
            guardrail_flags=state.get("guardrail_flags", []),
        )

    async def run_stream(
        self, records: AsyncIterator[TelemetryRecord]
    ) -> AsyncIterator[BridgeEvent]:
        """텔레메트리 스트림을 처리하며 탐지 이벤트를 순차 방출."""
        async for record in records:
            event = await self.process(record)
            if event is not None:
                yield event
