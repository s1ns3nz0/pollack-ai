"""[2] Investigation Agent — RAG 유사사례 검색 + 신호 상관 + 출처 검증.

RAG 는 `RagflowRetrievalTool`(또는 동일 시그니처의 리트리버)로 주입한다. 검색
컨텍스트는 출처 가드레일(신뢰 출처 `kb/` 만 채택) 통과분만 사용한다. LLM 이 주입되면
신뢰 컨텍스트를 근거로 상관분석 요약을 생성하고, 실패/미주입 시 결정론적 요약으로
폴백한다(파이프라인 안전).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agents.base import BaseSOCAgent
from core.exceptions import LLMError, SOCPlatformError
from core.llm import LLMClient
from core.models import InvestigationResult, RetrievedChunk, SOCState
from core.settings import Settings

_SUMMARY_SYSTEM = (
    "당신은 UAV 보안관제(SOC) 분석가다. 주어진 경보와 신뢰 지식베이스 컨텍스트만"
    " 근거로, 의심 공격과 핵심 근거를 3문장 이내 한국어로 요약하라. 컨텍스트에 없는"
    " 내용은 지어내지 마라."
)


@runtime_checkable
class ContextRetriever(Protocol):
    """Investigation 이 의존하는 RAG 리트리버 계약."""

    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        """질의에 대한 컨텍스트 청크를 반환한다."""
        ...


class InvestigationAgent(BaseSOCAgent):
    """RAG 유사사례 + 신호 상관 분석 Agent."""

    def __init__(
        self,
        settings: Settings,
        retriever: ContextRetriever | None,
        llm: LLMClient | None = None,
    ) -> None:
        super().__init__(settings)
        self._retriever = retriever
        self._llm = llm

    async def run(self, state: SOCState) -> SOCState:
        """유사사례 검색 + 출처 검증 + (LLM) 상관분석 요약.

        Args:
            state: `alert` 를 포함한 현재 상태.

        Returns:
            investigation 결과 + (미신뢰 컨텍스트 격리 시) 가드레일 플래그.
        """
        alert = state["alert"]
        query = f"{alert.scenario_id} {alert.title} {' '.join(alert.signals)}"

        chunks: list[RetrievedChunk] = []
        rag_degraded = False
        if self._retriever is not None:
            try:
                chunks = await self._retriever.aretrieve(query, k=5)
            except SOCPlatformError as exc:
                # RAG 장애가 SOC 전체를 막지 않도록 빈 컨텍스트로 강등(대응 계속).
                rag_degraded = True
                self._logger.warning(
                    "investigation RAG 검색 실패, 빈 컨텍스트로 계속: %s", exc
                )

        trusted = [c for c in chunks if c.source.startswith("kb/")]
        dropped = len(chunks) - len(trusted)
        summary = await self._summarize(alert.title, alert.signals, trusted)
        self._logger.info(
            "investigation: alert=%s hits=%d trusted=%d degraded=%s",
            alert.id,
            len(chunks),
            len(trusted),
            rag_degraded,
        )

        result: SOCState = {
            "investigation": InvestigationResult(
                matched_signals=alert.signals,
                mitre=alert.mitre,
                similar_cases=trusted,
                summary=summary,
            ),
            "trace": ["investigation"],
        }
        flags: list[str] = []
        if rag_degraded:
            flags.append("RAG 검색 불가 — 빈 컨텍스트로 강등(대응 계속)")
        if dropped:
            flags.append(f"미신뢰 컨텍스트 {dropped}건 격리")
        if flags:
            result["guardrail_flags"] = flags
        return result

    async def _summarize(
        self, title: str, signals: list[str], trusted: list[RetrievedChunk]
    ) -> str:
        """LLM 으로 상관분석 요약 생성. 미주입/오류 시 결정론적 폴백."""
        fallback = f"{title} 상관분석: 신뢰 사례 {len(trusted)}건"
        if self._llm is None:
            return fallback
        context = "\n\n".join(f"[{c.source}] {c.text[:500]}" for c in trusted[:5])
        user = (
            f"경보: {title}\n탐지 신호: {', '.join(signals)}\n\n"
            f"신뢰 컨텍스트:\n{context if context else '(없음)'}"
        )
        try:
            return await self._llm.acomplete(_SUMMARY_SYSTEM, user)
        except LLMError as exc:
            self._logger.warning("investigation 요약 LLM 실패, 폴백: %s", exc)
            return fallback
