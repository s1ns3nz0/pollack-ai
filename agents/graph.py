"""6-에이전트 SOC 그래프 조립 (LangGraph).

    Triage → Investigation → Validation ─┬─(정탐)→ Response ─┐
                                         └─(오탐)→ RuleUpdate ┴→ Report → END

심각도 엔진은 Triage 내부에 삽입되어 등급을 산정하고, 이후 Validation 라우팅과
Response/Report 의 HITL·자동대응·OSCAL 수준을 좌우한다.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from time import perf_counter
from typing import Any, cast

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from agents.approval_agent import ApprovalAgent
from agents.investigation_agent import ContextRetriever, InvestigationAgent
from agents.report_agent import ReportAgent
from agents.response_agent import ResponseAgent
from agents.rule_update_agent import RuleUpdateAgent
from agents.triage_agent import TriageAgent
from agents.validation_agent import (
    Judge,
    ValidationAgent,
    default_judge,
    route_after_validation,
)
from core.llm import LLMClient
from core.models import SOCState
from core.settings import Settings, get_settings
from core.severity import SeverityEngine

# LangGraph 노드 시그니처(에이전트 .run 과 동일: 비동기 SOCState→SOCState).
_NodeFn = Callable[[SOCState], Coroutine[Any, Any, SOCState]]


def _timed(name: str, fn: _NodeFn) -> _NodeFn:
    """노드 실행 시간을 측정해 `node_timings` 에 기록하는 래퍼.

    KPI(MTTT=triage, MTTC=response, Report Latency=report) 산출의 원천 데이터를
    파이프라인 변경 없이 노드 경계에서 수집한다.

    Args:
        name: 노드 이름(타이밍 라벨).
        fn: 감쌀 에이전트 노드 실행 함수.

    Returns:
        실행 후 `node_timings`(노드명·소요 ms)를 부분 상태에 더해 반환하는 함수.
    """

    async def wrapper(state: SOCState) -> SOCState:
        start = perf_counter()
        result = dict(await fn(state))
        result["node_timings"] = [
            {"node": name, "elapsed_ms": round((perf_counter() - start) * 1000, 2)}
        ]
        return cast(SOCState, result)

    return wrapper


def build_soc_graph(
    *,
    settings: Settings | None = None,
    engine: SeverityEngine | None = None,
    retriever: ContextRetriever | None = None,
    llm: LLMClient | None = None,
    judge: Judge = default_judge,
    hitl: bool = False,
) -> CompiledStateGraph[SOCState]:
    """6-에이전트 SOC 파이프라인을 조립해 컴파일된 그래프를 반환한다.

    Args:
        settings: 전역 설정(미지정 시 환경에서 로드).
        engine: 심각도 엔진(미지정 시 정책 파일에서 생성).
        retriever: RAG 리트리버(미지정 시 Investigation 은 빈 컨텍스트).
        llm: 요약용 LLM(미지정 시 Investigation 요약은 결정론적 폴백).
        judge: Validation 판정기(기본은 결정론적 — 판정권을 LLM 에 주지 않음).
        hitl: True 면 고위험 정탐에 운용자 승인 대기(interrupt) 노드 삽입 +
            checkpointer 동반. 호출 시 `config={"configurable":{"thread_id":...}}` 필요.

    Returns:
        컴파일된 LangGraph(`ainvoke({"alert": ...})` 로 실행).
    """
    settings = settings or get_settings()
    engine = engine or SeverityEngine()

    triage = TriageAgent(settings, engine)
    investigation = InvestigationAgent(settings, retriever, llm)
    validation = ValidationAgent(settings, judge)
    response = ResponseAgent(settings, engine)
    rule_update = RuleUpdateAgent(settings)
    report = ReportAgent(settings, engine)

    graph: StateGraph[SOCState] = StateGraph(SOCState)
    # 노드는 KPI 타이밍 래퍼(_timed)로 감싸 등록. add_node 오버로드는 바운드 메서드는
    # 받지만 동일 시그니처의 Callable 별칭은 거부하므로 arg-type 만 무시(런타임 동일).
    nodes: list[tuple[str, _NodeFn]] = [
        ("triage", triage.run),
        ("investigation", investigation.run),
        ("validation", validation.run),
        ("response", response.run),
        ("rule_update", rule_update.run),
        ("report", report.run),
    ]
    for _name, _fn in nodes:
        graph.add_node(_name, _timed(_name, _fn))  # type: ignore[call-overload]

    graph.set_entry_point("triage")
    graph.add_edge("triage", "investigation")
    graph.add_edge("investigation", "validation")
    # HITL on: 정탐 → approval(고위험 시 운용자 승인 대기) → response
    tp_target = "approval" if hitl else "response"
    if hitl:
        graph.add_node(
            "approval",
            _timed("approval", ApprovalAgent(settings).run),  # type: ignore[call-overload]
        )
        graph.add_edge("approval", "response")
    graph.add_conditional_edges(
        "validation",
        route_after_validation,
        {"true_positive": tp_target, "false_positive": "rule_update"},
    )
    graph.add_edge("response", "report")
    graph.add_edge("rule_update", "report")
    graph.add_edge("report", END)

    if hitl:
        # interrupt 재개를 위해 checkpointer 필요. 호출 시 thread_id config 지정.
        return graph.compile(checkpointer=MemorySaver())
    return graph.compile()
