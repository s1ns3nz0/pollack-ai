"""6-에이전트 SOC 그래프 조립 (LangGraph).

    Triage → Investigation → Validation ─┬─(정탐)→ Response ─┐
                                         └─(오탐)→ RuleUpdate ┴→ Report → END

심각도 엔진은 Triage 내부에 삽입되어 등급을 산정하고, 이후 Validation 라우팅과
Response/Report 의 HITL·자동대응·OSCAL 수준을 좌우한다.
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

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
from core.models import SOCState
from core.settings import Settings, get_settings
from core.severity import SeverityEngine


def build_soc_graph(
    *,
    settings: Settings | None = None,
    engine: SeverityEngine | None = None,
    retriever: ContextRetriever | None = None,
    judge: Judge = default_judge,
) -> CompiledStateGraph[SOCState]:
    """6-에이전트 SOC 파이프라인을 조립해 컴파일된 그래프를 반환한다.

    Args:
        settings: 전역 설정(미지정 시 환경에서 로드).
        engine: 심각도 엔진(미지정 시 정책 파일에서 생성).
        retriever: RAG 리트리버(미지정 시 Investigation 은 빈 컨텍스트).
        judge: Validation 판정기.

    Returns:
        컴파일된 LangGraph(`ainvoke({"alert": ...})` 로 실행).
    """
    settings = settings or get_settings()
    engine = engine or SeverityEngine()

    triage = TriageAgent(settings, engine)
    investigation = InvestigationAgent(settings, retriever)
    validation = ValidationAgent(settings, judge)
    response = ResponseAgent(settings, engine)
    rule_update = RuleUpdateAgent(settings)
    report = ReportAgent(settings, engine)

    graph: StateGraph[SOCState] = StateGraph(SOCState)
    graph.add_node("triage", triage.run)
    graph.add_node("investigation", investigation.run)
    graph.add_node("validation", validation.run)
    graph.add_node("response", response.run)
    graph.add_node("rule_update", rule_update.run)
    graph.add_node("report", report.run)

    graph.set_entry_point("triage")
    graph.add_edge("triage", "investigation")
    graph.add_edge("investigation", "validation")
    graph.add_conditional_edges(
        "validation",
        route_after_validation,
        {"true_positive": "response", "false_positive": "rule_update"},
    )
    graph.add_edge("response", "report")
    graph.add_edge("rule_update", "report")
    graph.add_edge("report", END)
    return graph.compile()
