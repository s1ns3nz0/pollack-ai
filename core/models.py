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


class GnssJamFinding(BaseModel):
    """GPSJam.org 셀 한 건. level 은 0(no signal loss)~3(severe).

    Attributes:
        cell: "lat_int,lon_int" 1° 그리드 키 (소스 그대로).
        level: 0..3 정수 jam 심각도.
        as_of: ISO8601 date — gpsjam 은 일 단위 집계.
        source: 출처 식별자(예: gpsjam, stub).
    """

    cell: str
    level: int = Field(ge=0, le=3)
    as_of: str
    source: str = "gpsjam"


class AirspaceFinding(BaseModel):
    """OpenSky 항적 한 건(경보 좌표 인근 비행체).

    Attributes:
        icao24: 트랜스폰더 ICAO24 (16진).
        callsign: 비행 콜사인(빈값 가능).
        lat: 비행체 위도(deg).
        lon: 비행체 경도(deg).
        distance_km: 경보 좌표 대비 거리(km).
        hostile: 적대 판정(callsign 화이트리스트 외 / 빈값 + 공중).
        on_ground: 지상 여부.
        source: 출처 식별자(예: opensky, stub).
    """

    icao24: str
    callsign: str = ""
    lat: float
    lon: float
    distance_km: float = 0.0
    hostile: bool = False
    on_ground: bool = False
    source: str = "opensky"


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
    cves: list[str] = Field(default_factory=list)  # 취약점 컨텍스트 조회용 CVE 식별자
    expected_detection: dict[str, object] = Field(default_factory=dict)
    defense_playbook: dict[str, object] = Field(default_factory=dict)
    ground_truth: Verdict = Verdict.TRUE_POSITIVE
    llm_suggested_severity: Severity | None = None
    # dynamics 런타임 신호(탐지 파이프라인이 채움; 없으면 정적 산정과 동일)
    dwelling_min: int = 0
    lateral_correlation: bool = False
    no_effect_sustained: bool = False
    # 예측 폐루프: 이 alert 의 technique 이 해당 actor 의 pending 예측과 일치.
    # PredictionMatcher(읽기 전용 대조)가 채움 — 정책 dynamics 격상 입력.
    prediction_match: bool = False
    # 지리 컨텍스트(외부 GNSS/Airspace 도구 조회용; 없으면 asset-tiers.yaml fallback)
    lat: float | None = None
    lon: float | None = None
    # 공격자 식별 — 신뢰 주입 경계(sim_bridge/운영진/신뢰 inbound webhook 만 채움).
    # 외부 입력(Sentinel alert 본문, RAG, LLM)에서 들어온 값은 hotpath 진입 시 strip.
    actor_id: str | None = None


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
    vuln_findings: list[VulnFinding] = Field(
        default_factory=list,
        description="경보 CVE 취약점 컨텍스트(KEV 악용 시 confidence 보강).",
    )
    gnss_jam_findings: list[GnssJamFinding] = Field(
        default_factory=list,
        description="외부 GPSJam 회상(S1 시나리오 + level≥2 시 confidence 보강).",
    )
    airspace_findings: list[AirspaceFinding] = Field(
        default_factory=list,
        description="외부 OpenSky 항적 회상(hostile + 근접 시 confidence 보강).",
    )
    predictions: list[AttackPrediction] = Field(
        default_factory=list,
        description="spec C1: actor.kill_chain n-gram 기반 다음 기법 예측 후보.",
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


class ActorPlaybookScore(BaseModel):
    """ActorProfile 의 PB 효과 점수 한 건(spec B-1).

    호출자가 신호→점수 매핑 책임. avg_effect = sum_effect / count.
    """

    playbook_id: str
    count: int = Field(default=0, ge=0)
    sum_effect: float = Field(default=0.0, ge=0.0)
    avg_effect: float = Field(default=0.0, ge=0.0, le=1.0)
    last_seen: str = ""


class ActorTtpStat(BaseModel):
    """ActorProfile 의 TTP 빈도 통계 한 건(spec #2)."""

    tactic: str
    technique: str
    count: int = Field(ge=0)
    last_seen: str


class ActorIocPattern(BaseModel):
    """ActorProfile 의 IOC 패턴 한 건(spec #2)."""

    kind: str  # "ip_24" | "asn" | "domain" | "user_agent" | "session_pattern"
    value: str
    count: int = Field(ge=0)
    last_seen: str


class ActorKillChainStep(BaseModel):
    """ActorProfile.kill_chain 의 시간순 단계 한 건(spec #2)."""

    ts: str
    alert_id: str
    scenario_id: str
    technique: str


class PendingPrediction(BaseModel):
    """발행돼 아직 적중/만료 판정 전인 예측 한 건(예측 폐루프).

    ActorProfile 에 적립돼 후속 알람과 대조된다. 적중(hit)이면 정책 dynamics
    격상 근거, 동일 actor 알람 TTL 경과 시 miss 로 만료 — 적중률 자가채점 입력.

    Attributes:
        technique: 예측된 다음 MITRE technique.
        probability: 발행 시점 조건부 확률.
        source_alert_id: 예측을 발생시킨 alert id.
        issued_at: 발행 ISO8601(없으면 빈값 — 결정론 테스트 허용).
        status: "pending" | "hit" | "miss".
        age_alerts: 발행 이후 경과한 동일 actor 알람 수(TTL 판정 기준).
    """

    technique: str
    probability: float = Field(ge=0.0, le=1.0)
    source_alert_id: str
    issued_at: str = ""
    status: str = "pending"
    age_alerts: int = Field(default=0, ge=0)


class ActorProfile(BaseModel):
    """공격자 동적 프로필(spec #2).

    `actors/` 데이터셋 단위 레코드. explicit (운영자/시스템 부여) vs auto
    (fingerprint 클러스터) 출처에 따라 priority 가중 적용 여부가 갈린다.

    Attributes:
        is_explicit: True = explicit actor_id, False = fingerprint 기반.
        content_hash: `fingerprint()` 결과(서명 기준).
        signature: 변조 탐지 서명(읽기 게이트가 검증).
    """

    actor_id: str  # explicit 또는 `fp:<sha256-16>`
    is_explicit: bool = False
    first_seen: str = ""
    last_seen: str = ""
    alert_count: int = Field(default=0, ge=0)
    ttp_stats: list[ActorTtpStat] = Field(default_factory=list)
    ioc_patterns: list[ActorIocPattern] = Field(default_factory=list)
    kill_chain: list[ActorKillChainStep] = Field(default_factory=list)
    pb_scores: dict[str, ActorPlaybookScore] = Field(
        default_factory=dict,
        description="spec B-1: playbook_id → 효과 점수 누적. 호출자 책임으로 갱신.",
    )
    pending_predictions: list[PendingPrediction] = Field(
        default_factory=list,
        description="예측 폐루프: 발행 후 미판정 예측. 쓰기 게이트만 갱신.",
    )
    prediction_hits: int = Field(default=0, ge=0)
    prediction_misses: int = Field(default=0, ge=0)
    content_hash: str = ""
    signature: str = ""

    def fingerprint(self) -> str:
        """정규화된 핵심 내용의 SHA-256 — 서명·검증 기준."""
        payload = {
            "actor_id": self.actor_id,
            "is_explicit": self.is_explicit,
            "alert_count": self.alert_count,
            "ttp": sorted(
                [s.model_dump() for s in self.ttp_stats],
                key=lambda d: (d["tactic"], d["technique"]),
            ),
            "ioc": sorted(
                [p.model_dump() for p in self.ioc_patterns],
                key=lambda d: (d["kind"], d["value"]),
            ),
            "chain": [s.model_dump() for s in self.kill_chain],
            # spec B-1: pb_scores 포함 (정렬 keys 로 결정론).
            "pb_scores": {k: v.model_dump() for k, v in sorted(self.pb_scores.items())},
            # 예측 폐루프: pending + hit/miss 카운터 포함 — 변조 시 서명 불일치.
            "pending_predictions": [p.model_dump() for p in self.pending_predictions],
            "prediction_hits": self.prediction_hits,
            "prediction_misses": self.prediction_misses,
        }
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class FeedSnapshot(BaseModel):
    """위협 피드 스냅샷 한 건(spec T1).

    Attributes:
        source: "attack" | "atlas" | "embed3d" | "kev".
        version: 피드 자체 version 필드 또는 fetched_at.
        techniques: T-id 목록 (KEV 면 빈 목록).
        cves: KEV 만 비어있지 않음.
        fetched_at: ISO8601.
        raw_hash: SHA-256 — 변경 추적.
    """

    source: str
    version: str = ""
    techniques: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    fetched_at: str = ""
    raw_hash: str = ""


class LandscapeDiff(BaseModel):
    """피드 비교 diff 한 건(spec T1)."""

    source: str
    added: list[str] = Field(default_factory=list)
    changed: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    kev_new: list[str] = Field(default_factory=list)


class WorkerReport(BaseModel):
    """주기 워커 사이클 결과(spec T1)."""

    cycle_at: str = ""
    diffs: list[LandscapeDiff] = Field(default_factory=list)
    auto_applied: int = 0
    pr_urls: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class RagasResult(BaseModel):
    """RAGAS 분석 품질 측정 한 건(spec D1).

    Investigation 의 summary + similar_cases 에 대한 faithfulness/relevancy 측정.
    핫패스 외 비동기로 수행 — KPI 누적용. Prometheus 게이지로도 노출된다.
    """

    faithfulness: float = Field(ge=0.0, le=1.0)
    answer_relevancy: float = Field(ge=0.0, le=1.0)
    context_relevancy: float = Field(ge=0.0, le=1.0)
    evaluated_at: str = ""
    n_contexts: int = Field(default=0, ge=0)
    source: str = "ragas"


class AttackPrediction(BaseModel):
    """공격 시퀀스 예측 한 건(spec C1).

    ActorProfile.kill_chain n-gram 빈도 기반 다음 기법 후보.
    """

    next_technique: str
    probability: float = Field(ge=0.0, le=1.0)
    support_count: int = Field(ge=0)
    basis_actor_id: str


class StagedDefense(BaseModel):
    """예측 TTP 에 대한 선제 방어 스테이징 한 건(예측 폐루프).

    coverage 매트릭스 조회 결과에 따라:
    - staged     : 기존 탐지룰 보유 → 감시 강화 후보(즉시 대응 가능).
    - accelerate : 룰 planned 상태 → 배치 가속 후보.
    - gap        : 미커버 → archetype 대응전략을 노트로 노출(헌트+보완 대상).

    Attributes:
        technique: 예측된 MITRE technique.
        status: "staged" | "accelerate" | "gap".
        tactic: 매트릭스상 소속 전술(미상이면 빈값).
        probability: 예측 발행 시점 조건부 확률.
        note: gap 이면 archetype 대응전략, 그 외 빈값.
    """

    technique: str
    status: str
    tactic: str = ""
    probability: float = Field(default=0.0, ge=0.0, le=1.0)
    note: str = ""


class CausalStep(BaseModel):
    """인과 체인의 한 단계(spec A1).

    Attributes:
        signal: 입력 신호(예: GPS_GLITCH_FLAG).
        effect: 결과 효과(예: GNSS_INTEGRITY_LOSS).
        next_step: 다음 단계 식별자. 빈값이면 체인 끝.
        mitre_technique: 매핑 ATT&CK technique(있으면).
        explanation: LLM 생성 자연어(선택, 빈값 가능).
    """

    signal: str
    effect: str
    next_step: str = ""
    mitre_technique: str = ""
    explanation: str = ""


class CausalChain(BaseModel):
    """매칭된 인과 룰의 결정론 체인(spec A1)."""

    steps: list[CausalStep] = Field(default_factory=list)
    basis_rules: list[str] = Field(default_factory=list)


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


class WatchlistUpdate(BaseModel):
    """탐지룰(KQL) 대신 Watch List 만 변경하는 오탐 개선 제안.

    원칙: KQL 은 절대 건드리지 않는다. KQL 이 읽는 Watch List 값만 추가/수정한다.

    Attributes:
        watchlist: 대상 Watch List 이름(예: GNSS_Exception_List).
        search_key: Watch List 의 SearchKey 컬럼(예: ZoneId).
        update_type: 유형 — "A"(화이트리스트) | "B"(예외) | "C"(임계값).
        action: "add"(신규 행 추가) | "modify"(기존 값 수정).
        entry: 추가/수정할 행(컬럼명→값).
        reason: 사람이 읽을 변경 근거.
    """

    watchlist: str
    search_key: str
    update_type: str
    action: str
    entry: dict[str, str] = Field(default_factory=dict)
    reason: str = ""


class RulePullRequest(BaseModel):
    """Watch List 변경을 외부 룰 저장소에 올리는 GitHub PR 페이로드.

    Attributes:
        repo: 대상 저장소(owner/name — 예: s1ns3nz0/dah-sentinel-content).
        branch: 작업 브랜치.
        path: 변경할 Watch List 파일 경로.
        title: PR 제목.
        body: PR 본문.
        base_branch: PR 의 베이스 브랜치(머지 대상).
        watchlist_update: 발행기가 CSV 에 적용할 Watch List 변경 내용.
        status: proposed | opened | failed.
        url: 생성된 PR URL(미생성 시 빈 문자열).
    """

    repo: str
    branch: str
    path: str
    title: str
    body: str = ""
    base_branch: str = "main"
    watchlist_update: WatchlistUpdate | None = None
    status: str = "proposed"
    url: str = ""


class RuleUpdateResult(BaseModel):
    """Rule Update 산출물(오탐 경로 — Watch List 전용 수정 제안).

    Attributes:
        watchlist_update: Watch List 변경 제안(remediation 정보 없으면 None).
        pull_request: 외부 룰 저장소 PR 페이로드(변경 없으면 None).
    """

    target_rule: str
    proposal: str
    pr_status: str
    reason: str
    watchlist_update: WatchlistUpdate | None = None
    pull_request: RulePullRequest | None = None


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
    hunt_candidates: list[str] = Field(
        default_factory=list,
        description="spec C1: SequencePredictor 예측 → 헌트 후보 technique 목록.",
    )
    staged_defenses: list[StagedDefense] = Field(
        default_factory=list,
        description="예측 폐루프: 예측 TTP 선제 스테이징 판정(staged/accelerate/gap).",
    )
    causal_summary: CausalChain | None = Field(
        default=None, description="spec A1: 결정론 인과 체인 요약."
    )


class LineageSnapshot(BaseModel):
    """방산 재현성 라인리지 스냅샷(spec D-1).

    Report 노드가 일괄 수집. 방산 컴플라이언스(NIST SP 800-53 AU/CM/SI) 감사 추적.
    시크릿은 pydantic SecretStr 자동 마스킹 후 fingerprint 해싱 — 원본 노출 방지.
    """

    captured_at: str
    code_version: str = "unknown"
    llm_provider: str = ""
    llm_model: str = ""
    policy_hashes: dict[str, str] = Field(default_factory=dict)
    settings_fingerprint: str = ""
    ensemble_weights: dict[str, float] = Field(default_factory=dict)
    total_latency_ms: float = Field(default=0.0, ge=0.0)
    node_latencies: dict[str, float] = Field(default_factory=dict)


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
    causal_chain: CausalChain | None = Field(
        default=None, description="spec A1: OSCAL evidence 임베드용."
    )
    lineage: LineageSnapshot | None = Field(
        default=None, description="spec D-1: 방산 재현성 라인리지 임베드."
    )


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
    ensemble: object  # EnsembleResult (avoid import cycle)
    approval: ApprovalResult
    response: ResponseResult
    rule_update: RuleUpdateResult
    report: SOCReport
    oscal_evidence: OscalEvidence
    trace: Annotated[list[str], operator.add]
    guardrail_flags: Annotated[list[str], operator.add]
    node_timings: Annotated[list[dict[str, object]], operator.add]
