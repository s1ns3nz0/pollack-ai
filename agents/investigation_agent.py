"""[2] Investigation Agent — RAG 유사사례 검색 + 신호 상관 + 출처 검증.

RAG 는 `RagflowRetrievalTool`(또는 동일 시그니처의 리트리버)로 주입한다. 검색
컨텍스트는 출처 가드레일(신뢰 출처 `kb/` 만 채택) 통과분만 사용한다.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agents.base import BaseSOCAgent
from core.models import InvestigationResult, RetrievedChunk, SOCState
from core.settings import Settings


@runtime_checkable
class ContextRetriever(Protocol):
    """Investigation 이 의존하는 RAG 리트리버 계약."""

    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        """질의에 대한 컨텍스트 청크를 반환한다."""
        ...


class InvestigationAgent(BaseSOCAgent):
    """RAG 유사사례 + 신호 상관 분석 Agent."""

    def __init__(self, settings: Settings, retriever: ContextRetriever | None) -> None:
        super().__init__(settings)
        self._retriever = retriever

    async def run(self, state: SOCState) -> SOCState:
        """유사사례 검색 + 출처 검증.

        Args:
            state: `alert` 를 포함한 현재 상태.

        Returns:
            investigation 결과 + (미신뢰 컨텍스트 격리 시) 가드레일 플래그.
        """
        alert = state["alert"]
        query = f"{alert.scenario_id} {alert.title} {' '.join(alert.signals)}"

        chunks: list[RetrievedChunk] = []
        if self._retriever is not None:
            chunks = await self._retriever.aretrieve(query, k=5)

        trusted = [c for c in chunks if c.source.startswith("kb/")]
        dropped = len(chunks) - len(trusted)
        self._logger.info(
            "investigation: alert=%s hits=%d trusted=%d",
            alert.id,
            len(chunks),
            len(trusted),
        )

        result: SOCState = {
            "investigation": InvestigationResult(
                matched_signals=alert.signals,
                mitre=alert.mitre,
                similar_cases=trusted,
                summary=f"{alert.title} 상관분석: 신뢰 사례 {len(trusted)}건",
            ),
            "trace": ["investigation"],
        }
        if dropped:
            result["guardrail_flags"] = [f"미신뢰 컨텍스트 {dropped}건 격리"]
        return result
