"""공유 데이터 모델.

RAG 검색 결과(`RetrievedChunk`)와 6-에이전트 SOC 파이프라인의 상태/산출물
모델을 정의한다. LangGraph 상태(`SOCState`)는 TypedDict 로, 단계별 산출물은
pydantic 모델로 둔다.
"""

from __future__ import annotations

from enum import StrEnum
import hashlib
import json
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


class TiVerdict(StrEnum):
    """위협 인텔리전스 IOC 평판 판정."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class ThreatIntelFinding(BaseModel):
    """외부 위협 인텔(TI) IOC 조회 결과 한 건.

    Attributes:
        indicator: 조회한 IOC(해시/IP/도메인 등).
        verdict: 평판 판정.
        source: TI 출처(예: VirusTotal, stub).
        detail: 사람이 읽을 부가 설명.
    """

    indicator: str
    verdict: TiVerdict
    source: str = ""
    detail: str = ""


class SandboxReport(BaseModel):
    """샌드박스 디토네이션/분석 결과 한 건(파일·펌웨어 행위 분석).

    Attributes:
        artifact: 분석 대상 식별자(해시 또는 샘플 ID).
        verdict: 행위 기반 판정(TI 와 동일 척도 재사용).
        score: 위협 점수(0~100).
        signatures: 관측된 악성 행위 시그니처 이름.
        extracted_iocs: 분석에서 추출된 IOC(C2 IP/도메인 등 — TI 로 되먹임 가능).
        source: 분석 출처(예: hybrid-analysis, stub).
    """

    artifact: str
    verdict: TiVerdict
    score: int = 0
    signatures: list[str] = Field(default_factory=list)
    extracted_iocs: list[str] = Field(default_factory=list)
    source: str = ""


class VulnFinding(BaseModel):
    """취약점(CVE) 컨텍스트 한 건(악용 여부 + 심각도).

    Attributes:
        cve: CVE 식별자(예: CVE-2024-1234).
        known_exploited: CISA KEV 등재 여부(실제 악용 중 = 최우선).
        cvss_score: CVSS 기반 점수(0.0~10.0).
        severity: 심각도 등급(NVD: CRITICAL/HIGH/MEDIUM/LOW).
        source: 출처(예: cisa-kev, nvd).
    """

    cve: str
    known_exploited: bool = False
    cvss_score: float = 0.0
    severity: str = ""
    source: str = ""


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


class Provenance(StrEnum):
    """경험메모리(`exp/`) 레코드의 출처 신뢰 등급.

    신뢰 순위: `ENV_VERIFIED` > `REDGT_OFFLINE` > `AUTO`. 억제/완화 학습은 상위
    등급(`ENV_VERIFIED`/`REDGT_OFFLINE`)만 채택한다(포이즈닝 방어).
    """

    ENV_VERIFIED = "env_verified"  # 시뮬 환경 관측으로 검증(풀자동 최상위 신뢰)
    REDGT_OFFLINE = "redgt_offline"  # 예선·개발 단계 자체 Red(PyRIT) 정답
    AUTO = "auto"  # 시스템 추론(최저 신뢰 — 탐지부스트에만 사용)


class EnvVerdict(StrEnum):
    """시뮬 환경 관측으로 확정된 결과 라벨.

    억제(suppression) 학습은 `CONFIRMED_FP` 만 근거로 삼고, `INCONCLUSIVE` 는
    메모리에 적립하지 않는다(적이 노리는 회색지대 배제).
    """

    CONFIRMED_TP = "confirmed_tp"  # 물리 효과 관측 → 정탐 확정(탐지 학습, 안전)
    CONFIRMED_FP = "confirmed_fp"  # 충분한 윈도우 내 무효과 → 오탐 확정(억제 학습)
    INCONCLUSIVE = "inconclusive"  # 애매(짧은 윈도우/단발 트랜지언트) → 적립 보류


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
    iocs: list[str] = Field(default_factory=list)  # 외부 TI 조회용 지표(해시/IP/도메인)
    expected_detection: dict[str, object] = Field(default_factory=dict)
    defense_playbook: dict[str, object] = Field(default_factory=dict)
    ground_truth: Verdict = Verdict.TRUE_POSITIVE
    llm_suggested_severity: Severity | None = None
    # dynamics 런타임 신호(탐지 파이프라인이 채움; 없으면 정적 산정과 동일)
    dwelling_min: int = 0
    lateral_correlation: bool = False
    no_effect_sustained: bool = False


class InvestigationResult(BaseModel):
    """Investigation 산출물(유사사례 + 신호 상관).

    Attributes:
        confidence: 분석 결론 신뢰도(0.0~1.0). 신뢰 컨텍스트 수·검색 점수 기반의
            결정론적 산정(LLM 자체평가 아님 — KPI 검증 가능성 확보).
    """

    matched_signals: list[str] = Field(default_factory=list)
    mitre: dict[str, object] = Field(default_factory=dict)
    similar_cases: list[RetrievedChunk] = Field(default_factory=list)
    summary: str = ""
    confidence: float = 0.0
    ti_findings: list[ThreatIntelFinding] = Field(default_factory=list)
    experience_corroboration: int = Field(
        default=0,
        description="exp/ 에서 회상된 신뢰 과거 정탐 수(judge 자문 — 하한 불변).",
    )
    suppression_corroboration: int = Field(
        default=0,
        description=(
            "exp/ 에서 회상된 *동일 신호패턴* 신뢰 과거 오탐 수(맥락 FP 억제 자문). "
            "신뢰 출처(env_verified/redgt_offline)만, 좁은 시그니처 매칭만 집계."
        ),
    )
    sandbox_reports: list[SandboxReport] = Field(
        default_factory=list,
        description="해시 IOC 디토네이션 결과(악성 시 confidence 보강·IOC 추출).",
    )


class JudgeFeatures(BaseModel):
    """`signal_judge` 결정론 피처 스냅샷(경험메모리 적립용).

    LLM 산문 대신 판정에 실제로 쓰인 결정론 신호만 보존한다 → 검색 시 재오염
    (프롬프트 인젝션) 표면을 제거한다(S5 방어 확장).
    """

    has_signal: bool
    has_rule: bool
    corroborated: bool
    confidence: float


class ExperienceRecord(BaseModel):
    """경험메모리(`exp/`) 레코드 한 건.

    확정된 운영 경험만 적립한다(원시 LLM 텍스트 금지). 모든 레코드는 출처
    등급(`provenance`)과 환경검증 결과(`env_verdict`)를 보유하며, `fingerprint()`
    로 의미 동일 레코드를 중복 제거한다.

    Attributes:
        provenance: 출처 신뢰 등급(env_verified > redgt_offline > auto).
        env_verdict: 시뮬 환경 관측으로 확정된 결과(억제 학습은 confirmed_fp 만).
        content_hash: `fingerprint()` 결과 캐시(쓰기 게이트가 중복제거에 사용).
        signature: 쓰기 게이트가 부여하는 변조탐지 서명(읽기 측 신뢰 검증용).
    """

    scenario_id: str
    signals: list[str] = Field(default_factory=list)
    asset_id: str = ""
    asset_tier: str = ""
    verdict: Verdict
    severity: Severity
    judge_features: JudgeFeatures
    playbook_id: str | None = None
    env_verdict: EnvVerdict
    provenance: Provenance
    ts: str = ""
    content_hash: str = ""
    signature: str = ""

    def fingerprint(self) -> str:
        """의미 동일성 해시(ts/provenance/해시 제외)를 SHA-256 으로 산정한다.

        중복 제거 키로 쓴다. 타임스탬프·출처등급·해시 자체는 제외해, 동일한 경험이
        시점/출처만 달리 재관측돼도 같은 지문을 갖게 한다.

        Returns:
            정규화된 핵심 내용의 16진 SHA-256 다이제스트.
        """
        payload = {
            "scenario_id": self.scenario_id,
            "signals": sorted(self.signals),
            "asset_id": self.asset_id,
            "asset_tier": self.asset_tier,
            "verdict": self.verdict.value,
            "severity": self.severity.value,
            "env_verdict": self.env_verdict.value,
            "judge_features": self.judge_features.model_dump(),
        }
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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

    `trace`/`guardrail_flags`/`node_timings` 는 리듀서(`operator.add`)로 노드마다
    append 된다. `node_timings` 는 노드별 소요시간(ms)으로 KPI(MTTT·MTTC·Report
    Latency) 산출의 원천이다.
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
    node_timings: Annotated[list[dict[str, object]], operator.add]
