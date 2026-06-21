"""공유 데이터 모델.

RAG 검색 결과(`RetrievedChunk`)와 6-에이전트 SOC 파이프라인의 상태/산출물
모델을 정의한다. LangGraph 상태(`SOCState`)는 TypedDict 로, 단계별 산출물은
pydantic 모델로 둔다.
"""

from __future__ import annotations

from enum import StrEnum
import operator
from typing import Annotated, TypedDict

from pydantic import BaseModel, Field


class RetrievedChunk(BaseModel):
    """RAG 지식베이스에서 검색된 컨텍스트 청크 한 건.

    Attributes:
        text: 청크 본문 텍스트.
        source: 출처 식별자. `kb/<문서명>` 형식으로 정규화되어 Investigation
            단계의 출처 가드레일(신뢰 출처 `kb/` 만 채택)을 통과한다.
        score: 질의-청크 유사도 점수(0.0~1.0).
    """

    text: str = Field(..., description="청크 본문 텍스트.")
    source: str = Field(..., description="출처 식별자. `kb/<문서명>` 형식.")
    score: float = Field(..., description="질의-청크 유사도 점수.")


class Severity(StrEnum):
    """심각도 등급(정책 엔진 산정값)."""

    HIGH = "h"
    MEDIUM = "m"
    LOW = "l"
    INFO = "i"


class Verdict(StrEnum):
    """오탐/정탐 판정."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"


class Alert(BaseModel):
    """SOC 파이프라인 입력 경보(시나리오에서 파생).

    `llm_suggested_severity` 는 적대적으로 주입될 수 있는 제안 등급이며 신뢰하지
    않는다(Triage 가드레일용 — S5 RAG 포이즈닝 방어).
    """

    id: str
    scenario_id: str
    title: str
    asset_id: str = ""
    asset_tier: str = ""
    mission_phase: str = ""
    posture: str = "normal"
    severity_baseline: Severity
    mitre: dict[str, object] = Field(default_factory=dict)
    signals: list[str] = Field(default_factory=list)
    expected_detection: dict[str, object] = Field(default_factory=dict)
    defense_playbook: dict[str, object] = Field(default_factory=dict)
    ground_truth: Verdict = Verdict.TRUE_POSITIVE
    llm_suggested_severity: Severity | None = None
    # dynamics 런타임 신호(탐지 파이프라인이 채움; 없으면 정적 산정과 동일)
    dwelling_min: int = 0
    lateral_correlation: bool = False
    no_effect_sustained: bool = False


class InvestigationResult(BaseModel):
    """Investigation 산출물(유사사례 + 신호 상관)."""

    matched_signals: list[str] = Field(default_factory=list)
    mitre: dict[str, object] = Field(default_factory=dict)
    similar_cases: list[RetrievedChunk] = Field(default_factory=list)
    summary: str = ""


class ResponseResult(BaseModel):
    """Response 산출물(정탐 경로)."""

    playbook_id: str | None = None
    actions: list[str] = Field(default_factory=list)
    failover: str | None = None
    auto_response: str | None = None
    hitl: str | None = None


class ApprovalResult(BaseModel):
    """HITL 승인 결과(고위험 자동대응 전 운용자 개입)."""

    required: bool
    approved: bool
    note: str = ""


class RuleUpdateResult(BaseModel):
    """Rule Update 산출물(오탐 경로 — 탐지룰 수정 제안 stub)."""

    target_rule: str
    proposal: str
    pr_status: str
    reason: str


class SOCReport(BaseModel):
    """최종 리포트."""

    alert_id: str
    scenario_id: str
    title: str
    severity: Severity
    verdict: Verdict
    action_taken: str
    mitre: dict[str, object] = Field(default_factory=dict)
    guardrail_flags: list[str] = Field(default_factory=list)
    hitl: str | None = None


class OscalEvidence(BaseModel):
    """OSCAL 증거(등급별 차등). 실제 OSCAL 모델은 인프라 lane."""

    evidence_level: str
    alert_id: str
    scenario_id: str
    severity: Severity | None = None
    verdict: Verdict | None = None
    mitre: dict[str, object] = Field(default_factory=dict)
    control_refs: list[str] = Field(default_factory=list)
    pipeline_trace: list[str] = Field(default_factory=list)
    investigation: InvestigationResult | None = None
    response: ResponseResult | None = None
    severity_rationale: list[str] | None = None


class SOCState(TypedDict, total=False):
    """LangGraph 파이프라인 상태. 단계별로 누적된다.

    `trace`/`guardrail_flags` 는 리듀서(`operator.add`)로 노드마다 append 된다.
    """

    alert: Alert
    severity: Severity
    severity_rationale: list[str]
    priority: int
    investigation: InvestigationResult
    verdict: Verdict
    approval: ApprovalResult
    response: ResponseResult
    rule_update: RuleUpdateResult
    report: SOCReport
    oscal_evidence: OscalEvidence
    trace: Annotated[list[str], operator.add]
    guardrail_flags: Annotated[list[str], operator.add]
