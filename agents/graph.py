"""6-에이전트 SOC 그래프 조립 (LangGraph).

    Triage → Investigation → Validation ─┬─(정탐)→ Response ─┐
                                         └─(오탐)→ RuleUpdate ┴→ Report → END

심각도 엔진은 Triage 내부에 삽입되어 등급을 산정하고, 이후 Validation 라우팅과
Response/Report 의 HITL·자동대응·OSCAL 수준을 좌우한다.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from pathlib import Path
from time import perf_counter
from typing import Any, cast

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from agents.approval_agent import ApprovalAgent
from agents.investigation_agent import (
    AirspaceProvider,
    ContextRetriever,
    GnssJamProvider,
    InvestigationAgent,
    SandboxDetonator,
    ThreatIntelTool,
    VulnContext,
)
from agents.judges.base import Judge as ScoreJudge
from agents.judges.experience_judge import ExperienceJudge
from agents.judges.llm_judge import LlmJudge
from agents.judges.signal_judge import SignalJudge
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
from core.actors import ActorReadGate, ActorWriteGate, InMemoryActorStore
from core.causal import CausalReasoner
from core.coa import CoaMatrix, CoaPlanner
from core.degradation import DegradationAssessor, DegradationMatrix
from core.exceptions import SOCPlatformError
from core.experience import MemoryReadGate
from core.killchain import KillChainProgressor
from core.lineage import LineageCollector
from core.llm import LLMClient
from core.models import SOCState
from core.predictor import PredictionMatcher, SequencePredictor
from core.recovery import RecoveryMatrix, RecoveryPlanner
from core.settings import Settings, get_settings
from core.severity import SeverityEngine
from core.staging import DefenseStager
from core.stride import StrideClassifier, StrideModel
from tools.coverage import CoverageMatrix
from tools.rule_publisher import RulePublisher

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


_GRAPH_DATA = Path(__file__).resolve().parents[1] / "data" / "mitre_attack_graph.yaml"


def _default_retriever(settings: Settings) -> ContextRetriever | None:
    """설정에 따라 기본 검색기를 구성한다.

    RAGFlow 설정이 있으면 평면 RAG 를, `graph_rag_enabled` 이고 그래프 씨앗이 있으면
    GraphRAG 를 포함한다. 둘이면 `CompositeRetriever` 로 합치고, 하나면 그것을, 아무것도
    없으면 None(=RAG 생략)을 반환한다.
    """
    pieces: list[ContextRetriever] = []
    if settings.ragflow_api_token.get_secret_value() and settings.ragflow_dataset_id:
        from tools.ragflow_tool import RagflowRetrievalTool

        pieces.append(RagflowRetrievalTool(settings=settings))
    if settings.graph_rag_enabled and _GRAPH_DATA.is_file():
        from tools.graph_retriever import GraphRetriever

        pieces.append(GraphRetriever.from_yaml(_GRAPH_DATA))
    if not pieces:
        return None
    if len(pieces) == 1:
        return pieces[0]
    from tools.graph_retriever import CompositeRetriever

    return CompositeRetriever(pieces)


def _default_experience(settings: Settings) -> MemoryReadGate | None:
    """경험메모리 데이터셋이 있으면 RAGFlow 백엔드 읽기 게이트를 구성(없으면 None)."""
    if not (
        settings.ragflow_api_token.get_secret_value()
        and settings.ragflow_exp_dataset_id
    ):
        return None
    from tools.ragflow_experience import RagflowExperienceStore

    return MemoryReadGate(RagflowExperienceStore(settings))


def _default_gnss_jam(settings: Settings) -> GnssJamProvider | None:
    """GPSJam 어댑터를 구성한다(엔드포인트 없으면 None)."""
    if not settings.gpsjam_endpoint:
        return None
    from tools.gnss_jam_tool import GpsJamRetriever

    return GpsJamRetriever(settings)


def _default_airspace(settings: Settings) -> AirspaceProvider | None:
    """OpenSky 어댑터를 구성한다(베이스 URL 없으면 None)."""
    if not settings.opensky_base_url:
        return None
    from tools.airspace_tool import OpenSkyRetriever

    return OpenSkyRetriever(settings)


def build_soc_graph(
    *,
    settings: Settings | None = None,
    engine: SeverityEngine | None = None,
    retriever: ContextRetriever | None = None,
    llm: LLMClient | None = None,
    ti: ThreatIntelTool | None = None,
    experience: MemoryReadGate | None = None,
    sandbox: SandboxDetonator | None = None,
    vuln: VulnContext | None = None,
    rule_publisher: RulePublisher | None = None,
    gnss_jam: GnssJamProvider | None = None,
    airspace: AirspaceProvider | None = None,
    actor_read: ActorReadGate | None = None,
    actor_write: ActorWriteGate | None = None,
    ragas: object | None = None,
    predictor: object | None = None,
    reasoner: CausalReasoner | None = None,
    lineage: LineageCollector | None = None,
    judge: Judge = default_judge,
    ensemble_judges: list[ScoreJudge] | None = None,
    llm_judge_enabled: bool = False,
    hitl: bool = False,
) -> CompiledStateGraph[SOCState]:
    """6-에이전트 SOC 파이프라인을 조립해 컴파일된 그래프를 반환한다.

    Args:
        settings: 전역 설정(미지정 시 환경에서 로드).
        engine: 심각도 엔진(미지정 시 정책 파일에서 생성).
        retriever: RAG 리트리버(미지정 시 설정 있으면 RAGFlow 자동 배선, 없으면 생략).
        llm: 요약용 LLM(미지정 시 Investigation 요약은 결정론적 폴백).
        ti: 외부 위협 인텔 도구(미지정 시 IOC 보강 생략).
        experience: 경험메모리 읽기 게이트(미지정 시 exp 데이터셋 있으면 자동 배선).
        sandbox: 샌드박스 디토네이터(미지정 시 해시 IOC 분석 생략).
        vuln: 취약점 컨텍스트(미지정 시 CVE 보강 생략).
        rule_publisher: Watch List PR 발행기(미지정 시 RuleUpdate 는 proposed 만 산출).
        judge: Validation 판정기(기본은 결정론적 — 판정권을 LLM 에 주지 않음).
        hitl: True 면 고위험 정탐에 운용자 승인 대기(interrupt) 노드 삽입 +
            checkpointer 동반. 호출 시 `config={"configurable":{"thread_id":...}}` 필요.

    Returns:
        컴파일된 LangGraph(`ainvoke({"alert": ...})` 로 실행).
    """
    settings = settings or get_settings()
    engine = engine or SeverityEngine()
    # 명시 주입이 없고 설정이 있으면 RAGFlow 검색기/경험저장소를 기본 배선(opt-in).
    if retriever is None:
        retriever = _default_retriever(settings)
    if experience is None:
        experience = _default_experience(settings)
    if gnss_jam is None:
        gnss_jam = _default_gnss_jam(settings)
    if airspace is None:
        airspace = _default_airspace(settings)

    # spec C1: predictor 미주입 시 인메모리 SequencePredictor 자동 배선.
    if predictor is None:
        predictor = SequencePredictor(
            min_support=settings.predict_min_support,
            min_probability=settings.predict_min_probability,
            top_k=settings.predict_top_k,
        )
    # actor write/read 미주입 시 한 쌍 인메모리 생성(테스트/로컬 데모).
    # 예측 폐루프: 게이트에 predictor(TP 적립 시 발행) + metrics 훅 배선.
    if actor_read is None and actor_write is None:
        from app.metrics import metrics as _metrics

        _store = InMemoryActorStore()
        actor_read = ActorReadGate(_store)
        actor_write = ActorWriteGate(
            _store,
            predictor=predictor,  # type: ignore[arg-type]
            on_settle=lambda hit: _metrics().record_prediction(hit=hit),
        )
    # 예측 폐루프: 읽기 전용 pending 대조기 — triage 진입 전 alert enrich.
    matcher = PredictionMatcher(actor_read) if actor_read is not None else None
    # kill chain: 읽기 전용 진행도 산정기 — actor 누적 후반단계 도달 시 격상 플래그.
    progressor = KillChainProgressor(actor_read) if actor_read is not None else None
    # spec A1: causal-rules.yaml 존재 시 reasoner 자동 배선.
    if reasoner is None:
        rules_path = Path(settings.causal_rules_path)
        if rules_path.exists():
            reasoner = CausalReasoner(
                rules_path, llm=llm, explain=settings.causal_llm_explain
            )
    # spec D1: ragas opt-in.
    if ragas is None and settings.ragas_enabled:
        from tools.ragas_evaluator import RagasEvaluator

        ragas = RagasEvaluator(settings)
    triage = TriageAgent(settings, engine, actor_read=actor_read)
    investigation = InvestigationAgent(
        settings,
        retriever,
        llm,
        ti,
        experience,
        sandbox,
        vuln,
        gnss_jam=gnss_jam,
        airspace=airspace,
        actor_read=actor_read,
        ragas=ragas,  # type: ignore[arg-type]
        predictor=predictor,  # type: ignore[arg-type]
    )
    # spec B1: ensemble_judges 명시 주입 우선. 없고 llm_judge_enabled 일 때만 자동 배선.
    if ensemble_judges is None and llm_judge_enabled:
        ensemble_judges = [SignalJudge(), LlmJudge(llm), ExperienceJudge()]
    validation = ValidationAgent(settings, judge, ensemble_judges=ensemble_judges)
    response = ResponseAgent(settings, engine)
    rule_update = RuleUpdateAgent(settings, rule_publisher)
    # spec D-1: lineage opt-in.
    if lineage is None and settings.lineage_enabled:
        lineage = LineageCollector(settings)
    # 예측 폐루프: coverage 매트릭스 있으면 선제 스테이징 자동 배선.
    # COA matrix: coverage + coa-matrix.yaml 있으면 COA 플래너 자동 배선.
    try:
        stager: DefenseStager | None = DefenseStager()
    except SOCPlatformError:
        stager = None
    try:
        coa_planner: CoaPlanner | None = CoaPlanner(
            CoverageMatrix.from_yaml(), CoaMatrix.from_yaml()
        )
    except SOCPlatformError:
        coa_planner = None
    # recovery: coverage + recovery-matrix.yaml 있으면 축출/복구 플래너 자동 배선.
    try:
        recovery_planner: RecoveryPlanner | None = RecoveryPlanner(
            CoverageMatrix.from_yaml(), RecoveryMatrix.from_yaml()
        )
    except SOCPlatformError:
        recovery_planner = None
    # graceful degradation: degradation-matrix.yaml 있으면 임무지속성 평가기 배선.
    try:
        degradation: DegradationAssessor | None = DegradationAssessor(
            DegradationMatrix.from_yaml()
        )
    except SOCPlatformError:
        degradation = None
    # UAV STRIDE: stride-model.yaml 있으면 위협 분류기 배선.
    try:
        stride: StrideClassifier | None = StrideClassifier(StrideModel.from_yaml())
    except SOCPlatformError:
        stride = None
    report = ReportAgent(
        settings,
        engine,
        reasoner=reasoner,
        actor_read=actor_read,
        lineage=lineage,
        stager=stager,
        coa_planner=coa_planner,
        recovery_planner=recovery_planner,
        degradation=degradation,
        stride=stride,
    )

    graph: StateGraph[SOCState] = StateGraph(SOCState)

    # 노드는 KPI 타이밍 래퍼(_timed)로 감싸 등록. add_node 오버로드는 바운드 메서드는
    # 받지만 동일 시그니처의 Callable 별칭은 거부하므로 arg-type 만 무시(런타임 동일).
    async def _triage_with_match(state: SOCState) -> SOCState:
        """triage 진입 전 읽기전용 enrich — 예측 적중 + kill chain 진행도.

        matcher(예측 pending 대조) → progressor(actor 누적 진행도)를 순차 적용해
        prediction_match·kill_chain_advanced 플래그를 alert 에 반영한다(둘 다 정책
        dynamics 격상 입력). enrich 로 alert 가 바뀌면 상태에 실어 downstream 공유.
        """
        alert = state["alert"]
        changed = False
        if matcher is not None:
            alert = await matcher.enrich(alert)
            changed = changed or alert.prediction_match
        if progressor is not None:
            alert = await progressor.enrich(alert)
            changed = changed or alert.kill_chain_advanced
        if changed:
            state = cast(SOCState, {**state, "alert": alert})
        out = dict(await triage.run(state))
        if changed:
            out["alert"] = alert
        return cast(SOCState, out)

    nodes: list[tuple[str, _NodeFn]] = [
        ("triage", _triage_with_match),
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
