"""에이전트 파이프라인 구조 변형 — Baseline/Parallel/Router/Supervisor.

단일 build_soc_graph 의 훅(investigation 주입 / router 분기)으로 변형을 표현한다.
비교 실험(benchmarks/run_structure_comparison.py) 전용이며, 프로덕션 경로는 Baseline.
"""

from __future__ import annotations

import asyncio
from typing import Any

from langgraph.graph.state import CompiledStateGraph

from agents.graph import build_soc_graph
from agents.investigation_agent import (
    ContextRetriever,
    InvestigationAgent,
    ThreatIntelTool,
)
from core.llm import LLMClient
from core.models import SOCState
from core.settings import Settings, get_settings


class ParallelInvestigationAgent(InvestigationAgent):
    """독립 하위작업(TI)을 RAG→LLM요약 사슬과 동시 실행 후 병합."""

    async def run(self, state: SOCState) -> SOCState:
        alert = state["alert"]
        rag_task = asyncio.create_task(self._rag_and_summarize(alert))
        ti_task = asyncio.create_task(self._lookup_ti(alert.iocs))
        (trusted, summary, dropped, rag_degraded), ti_findings = await asyncio.gather(
            rag_task, ti_task
        )
        confidence = self._confidence_with_ti(trusted, rag_degraded, ti_findings)
        return self._assemble(
            alert,
            trusted,
            summary,
            confidence,
            ti_findings,
            rag_degraded,
            dropped,
        )


class SupervisorInvestigationAgent(InvestigationAgent):
    """결정-무관 LLM 요약을 모호한 경우에만 호출하는 적응형 변형."""

    async def run(self, state: SOCState) -> SOCState:
        alert = state["alert"]
        trusted, dropped, rag_degraded = await self._retrieve_trusted(alert)
        ti_findings = await self._lookup_ti(alert.iocs)
        confidence = self._confidence_with_ti(trusted, rag_degraded, ti_findings)
        decisive = bool(trusted) or confidence >= 0.5
        if decisive:
            summary = (
                f"{alert.title} 상관분석: 신뢰 사례 {len(trusted)}건 "
                "(LLM 요약 생략 — 근거 충분)"
            )
        else:
            summary = await self._summarize(alert.title, alert.signals, trusted)
        return self._assemble(
            alert,
            trusted,
            summary,
            confidence,
            ti_findings,
            rag_degraded,
            dropped,
        )


def router_skip_ruleless(state: SOCState) -> str:
    """매칭 탐지룰이 없는 경보는 investigation 을 스킵하고 오탐 종결."""
    alert = state["alert"]
    has_rule = bool(
        alert.expected_detection.get("sigma_rule")
        or alert.expected_detection.get("sentinel_rule")
    )
    return "investigate" if has_rule else "skip"


def build_baseline(**kw: Any) -> CompiledStateGraph[SOCState]:
    """구조 0 — 현재 순차 DAG."""
    return build_soc_graph(**kw)


def build_parallel(
    *,
    settings: Settings | None = None,
    retriever: ContextRetriever | None = None,
    llm: LLMClient | None = None,
    ti: ThreatIntelTool | None = None,
    **kw: Any,
) -> CompiledStateGraph[SOCState]:
    """구조 1 — TI 를 RAG+LLM 과 동시 실행."""
    s = settings or get_settings()
    inv = ParallelInvestigationAgent(s, retriever, llm, ti)
    return build_soc_graph(
        settings=s,
        retriever=retriever,
        llm=llm,
        ti=ti,
        investigation=inv,
        **kw,
    )


def build_router(**kw: Any) -> CompiledStateGraph[SOCState]:
    """구조 2 — ruleless 경보 조기탈출(investigation 스킵)."""
    return build_soc_graph(router=router_skip_ruleless, **kw)


def build_supervisor(
    *,
    settings: Settings | None = None,
    retriever: ContextRetriever | None = None,
    llm: LLMClient | None = None,
    ti: ThreatIntelTool | None = None,
    **kw: Any,
) -> CompiledStateGraph[SOCState]:
    """구조 3 — 적응형: 결정-무관 LLM 요약을 모호 케이스에만."""
    s = settings or get_settings()
    inv = SupervisorInvestigationAgent(s, retriever, llm, ti)
    return build_soc_graph(
        settings=s,
        retriever=retriever,
        llm=llm,
        ti=ti,
        investigation=inv,
        **kw,
    )
