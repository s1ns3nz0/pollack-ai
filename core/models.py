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
from typing import Annotated, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field


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


class SbomComponent(BaseModel):
    """SBOM 컴포넌트 한 건(관측된 UAV 펌웨어/라이브러리/모델).

    Attributes:
        name: 컴포넌트 식별자.
        version: 관측 버전.
        hash: 관측 서명 해시(승인 해시와 대조).
        cves: 컴포넌트가 선언한 CVE 목록(vuln_tool 로 악용여부 조회).
    """

    name: str
    version: str = ""
    hash: str = ""
    cves: list[str] = Field(default_factory=list)


class SbomFinding(BaseModel):
    """SBOM 검증 위험 한 건(공급망 무결성).

    Attributes:
        component: 대상 컴포넌트명.
        issue: "unregistered"(미승인) | "tampered"(해시 불일치) | "vulnerable"(악용).
        detail: 사람이 읽을 위험 상세.
        cve: vulnerable 이면 해당 CVE(그 외 빈값).
    """

    component: str
    issue: str
    detail: str = ""
    cve: str = ""


class AibomComponent(BaseModel):
    """AIBOM 컴포넌트 한 건 — 플랫폼이 쓰는 AI 자산(모델/데이터셋/어댑터).

    Attributes:
        name: 컴포넌트 식별자(예: "qwen2.5:14b").
        component_type: 유형(chat_llm|embedding|ragflow|graphrag|ragas|dataset).
        version: 선언 버전/태그.
        digest: 선언 무결성 digest(있으면 승인값과 대조). 없으면 검증 불가.
        source: 출처(레지스트리/URL/제공자).
        model_card: 모델카드 참조(경로/URL). 모델유형인데 빈값이면 문서화 갭.
    """

    name: str
    component_type: str = ""
    version: str = ""
    digest: str = ""
    source: str = ""
    model_card: str = ""


class AibomFinding(BaseModel):
    """AIBOM 거버넌스 위험 한 건(AI 공급망·출처).

    Attributes:
        component: 대상 컴포넌트명(coverage_gap 은 기대 유형명).
        component_type: 컴포넌트 유형.
        issue: "unregistered"|"untrusted_source"|"unpinned"|"version_mismatch"|
            "tampered"|"integrity_unverifiable"|"coverage_gap"|"policy_unavailable"|
            "missing_model_card".
        detail: 사람이 읽을 위험 상세.
    """

    component: str
    component_type: str = ""
    issue: str
    detail: str = ""


class ZtAttestation(BaseModel):
    """ZTMM 통제 매핑 한 건 — self-attested(측정 아님, 근거 강제).

    Attributes:
        name: 기둥/교차역량 이름(예: Identity).
        kind: "pillar"(5 기둥) | "cross_cutting"(3 교차역량).
        declared: 선언 성숙도(traditional/initial/advanced/optimal).
        effective: 근거 검증 후 실효 성숙도(근거 없는 고등급은 initial 로 cap).
        control_ref: 실제 구현 참조(감사용). evidence: 근거 유형.
    """

    name: str
    kind: str = "pillar"
    declared: str = "traditional"
    effective: str = "traditional"
    control_ref: str = ""
    evidence: str = "self_attested"


class ZtMapping(BaseModel):
    """ZTMM self-attested 통제 매핑 결과(단일 overall 없음 — 기둥별 matrix).

    Attributes:
        capabilities: 기둥/교차역량별 매핑 목록.
        minimum_declared: 선언 최저 성숙도(보수적 rollup — "overall" 아님).
        minimum_effective: 근거검증 후 최저(사슬 최약 링크).
        findings: 거버넌스 위험(근거 없는 고등급 주장 등).
        measurement_status: 항상 "not_measured"(self-attested 명시 — overclaim 방지).
        assessment_basis: "self_attested_policy_yaml".
    """

    capabilities: list[ZtAttestation] = Field(default_factory=list)
    minimum_declared: str = "traditional"
    minimum_effective: str = "traditional"
    findings: list[str] = Field(default_factory=list)
    # Literal 고정 — downstream 이 "measured" 로 위장 못하게(overclaim 봉쇄, Codex H).
    measurement_status: Literal["not_measured"] = "not_measured"
    assessment_basis: Literal["self_attested_policy_yaml"] = "self_attested_policy_yaml"


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
    sbom_components: list[SbomComponent] = Field(
        default_factory=list,
        description="공급망 검증용 관측 SBOM 컴포넌트(펌웨어 변조 시나리오 등).",
    )
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
    # kill chain: 이 actor 가 누적으로 후반 단계(C2 이후)에 도달.
    # KillChainProgressor(읽기 전용)가 채움 — 진행 중 캠페인 판단 → dynamics 격상.
    kill_chain_advanced: bool = False
    # deception: 이 alert 이 decoy 자산/canary 토큰을 건드림.
    # DecoyDetector(읽기 전용)가 채움 — dynamics 격상 입력. TP 승격은 아님(untrusted).
    decoy_hit: bool = False
    # MBCRA: 이 alert 의 자산이 현 임무단계의 사이버 핵심지형(key terrain).
    # KeyTerrainDetector(읽기 전용)가 채움 — dynamics 격상 입력(JP 3-12 KT-C).
    key_terrain: bool = False
    # 지리 컨텍스트(외부 GNSS/Airspace 도구 조회용; 없으면 asset-tiers.yaml fallback)
    lat: float | None = None
    lon: float | None = None
    # 공격자 식별 — 신뢰 주입 경계(sim_bridge/운영진/신뢰 inbound webhook 만 채움).
    # 외부 입력(Sentinel alert 본문, RAG, LLM)에서 들어온 값은 hotpath 진입 시 strip.
    actor_id: str | None = None


# 파이프라인 내부/게이트/신뢰생산자만 채우는 필드 — untrusted wire 는 물리적 제외.
# 위조 시 격상(대부분) 또는 억제(no_effect_sustained·ground_truth) 벡터. 신규 enrich
# 필드는 여기 추가하거나 UntrustedAlertPayload 에 추가 — drift 가드 테스트가 강제한다.
_INTERNAL_ONLY_FIELDS: frozenset[str] = frozenset(
    {
        "actor_id",
        "prediction_match",
        "kill_chain_advanced",
        "decoy_hit",
        "key_terrain",
        "dwelling_min",
        "lateral_correlation",
        "no_effect_sustained",
        "ground_truth",  # default_judge 판정 우회(Critical)
        "expected_detection",  # RuleUpdateAgent watchlist/PR 권한(High)
        "posture",  # severity 권한·하향금지 lock — 방어측 조건(CPCON provider 담당)
        "defense_playbook",  # response 행동·HITL 프롬프트 지시
    }
)


class UntrustedAlertPayload(BaseModel):
    """untrusted `/alert` HTTP 입력의 구조적 신뢰경계(whitelist wire 모델).

    외부 생산자가 채울 수 있는 **위협 서술 필드만** 노출한다. 파이프라인 내부/게이트가
    산출하는 `_INTERNAL_ONLY_FIELDS` 는 이 모델에 물리적으로 없어 위조가 불가능하다
    (`extra="ignore"` 로 위조 키는 조용히 드롭 — 가용성 위해 forbid 대신). 신뢰 생산자
    (sim_bridge/outcome_probe/correlation)는 `Alert` 를 직접 생성하므로 무영향.

    두 신뢰 부류(Codex diff 반영):
      - SOC-계산 필드(내부전용 12): 파이프라인/게이트 산출 → wire 제외(위조=격상/억제).
      - 탐지소스 필드(wire 허용): severity_baseline/signals/mitre 는 탐지가 주는 값 —
        소스만큼만 신뢰. baseline 은 severity 엔진 시작점일 뿐, 내부 modifier
        (asset/key_terrain/dynamics)가 baseline 무관 격상하고 최종 판정은 baseline
        아닌 환경검증(env_verdict)이 결정 → 위조 저-baseline 실공격도 억제 불가
        (test_forged_low_baseline_still_escalates). 엔진 필수입력이라 내부화 불가.
    """

    model_config = ConfigDict(extra="ignore")

    id: str
    scenario_id: str
    title: str
    asset_id: str = ""
    asset_tier: str = ""
    mission_phase: str = ""
    severity_baseline: Severity
    mitre: dict[str, object] = Field(default_factory=dict)
    signals: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    sbom_components: list[SbomComponent] = Field(default_factory=list)
    llm_suggested_severity: Severity | None = None
    lat: float | None = None
    lon: float | None = None

    def to_alert(self) -> Alert:
        """서술 필드만으로 내부 Alert 구성(내부전용 필드는 Alert 기본값 유지)."""
        return Alert(**self.model_dump())


def has_forged_internal_fields(payload: object) -> list[str]:
    """payload(dict)에 내부전용 키가 실려있으면 그 목록 반환(위조 시도 telemetry용)."""
    if not isinstance(payload, dict):
        return []
    return sorted(k for k in payload if k in _INTERNAL_ONLY_FIELDS)


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


class EngageGoal(StrEnum):
    """MITRE Engage 교전 목표(3 코어). Prepare 정적/Affect 권고전용은 제외."""

    NONE = "none"
    EXPOSE = "expose"  # 접촉 성립·수집 개시
    ELICIT = "elicit"  # 적을 끌어냄(추가 TTP 노출)
    UNDERSTAND = "understand"  # 적 충분히 특성화(종단)


class ActorEngagement(BaseModel):
    """actor 별 MITRE Engage 교전 상태(폐루프).

    canary 접촉(신뢰 관측이 유발한 CONFIRMED_TP)에서만 전진한다 — untrusted
    decoy_hit 은 전진시키지 않는다(포이즈닝 면역). 전진은 alert_id 멱등 처리해
    replay 이중계상을 막는다.

    Attributes:
        state: 현재 Engage 목표.
        rounds: 신뢰 교전 라운드 수(멱등 처리된 canary 접촉 수).
        adversary_cost: kill-chain 지연 대리지표 — Σ(교전 시점 stage-order).
        last_activity: 마지막 권고 engagement 활동(EngagePlanner 산출).
        seen_alert_ids: 이미 전진에 반영한 alert_id(멱등키, 슬라이딩 cap).
    """

    state: EngageGoal = EngageGoal.NONE
    rounds: int = Field(default=0, ge=0)
    adversary_cost: int = Field(default=0, ge=0)
    last_activity: str = ""
    seen_alert_ids: list[str] = Field(default_factory=list)


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
    engagement: ActorEngagement = Field(
        default_factory=ActorEngagement,
        description="MITRE Engage 교전 상태(폐루프). 신뢰 canary→TP 경로만 전진.",
    )
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
        # Engage 교전 상태 — 변조 시 서명 불일치. 단 기본값(미교전)일 땐 payload 에서
        # 생략해 레거시(engagement 이전) 서명 프로필과 해시 호환 유지(마이그레이션).
        if self.engagement != ActorEngagement():
            payload["engagement"] = self.engagement.model_dump()
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


class CoaOption(BaseModel):
    """Courses of Action 한 셀 — (kill chain 단계, 7D 방어) 방어 옵션(교리 COA matrix).

    Attributes:
        tactic: kill chain 단계(tactic 이름).
        defense: 7D 방어 축(Discover/Detect/Deny/Disrupt/Degrade/Deceive/Destroy).
        status: "available"(우리 자산으로 실행 가능) | "gap"(방어 공백).
        action: 구체 UAV 방어 행동 서술(gap 이면 빈값).
        d3fend_id: 매핑된 D3FEND technique id(gap 이면 빈값).
        stage: "current"(actor 도달 단계) | "predicted"(예측 다음 단계) — 대응/선제.
    """

    tactic: str
    defense: str
    status: str
    action: str = ""
    d3fend_id: str = ""
    stage: str = "current"
    # Deceive 셀 한정 — 현 actor 의 Engage 교전 상태·권고활동·adversary_cost 주입.
    engage: str = ""


class MissionRisk(BaseModel):
    """임무 기반 사이버 위험평가(MBCRA) 결과 한 건 — METT-TC 융합(DoD).

    정적 asset tier 를 넘어 "이 자산이 현 임무단계의 핵심지형인가 + 무엇이 이것에
    의존하는가 + 적 진행도·체류·태세" 를 결정론 융합해 임무위험 점수를 산출한다.

    Attributes:
        asset_id: 평가 대상 자산.
        mission_phase: 현 임무 단계.
        score: 융합 위험 점수(높을수록 임무 위협 큼).
        is_key_terrain: 현 단계에서 핵심지형 여부.
        dependents: 이 자산 손상 시 영향받는(의존) 자산 목록.
        factors: METT-TC 요소별 기여(라벨→기여값).
        rationale: 산정 근거 문자열.
    """

    asset_id: str = ""
    mission_phase: str = ""
    score: int = 0
    is_key_terrain: bool = False
    dependents: list[str] = Field(default_factory=list)
    factors: dict[str, int] = Field(default_factory=dict)
    rationale: list[str] = Field(default_factory=list)


class PoamItem(BaseModel):
    """POA&M(Plan of Action & Milestones) 한 건 — 미충족 통제 갭(RMF/cATO).

    Attributes:
        control_id: NIST 800-53 통제 식별자(예: CA-8, SI-4, SR-4).
        family: 통제 패밀리 명.
        severity: "high" | "medium" | "low".
        source: 근거 신호("bas"|"slo"|"sbom").
        gap: 갭 서술(사람이 읽는 미충족 사유).
        status: "open"(미해결) — 자동 검증 파이프라인에서 지속 추적.
    """

    control_id: str
    family: str = ""
    severity: str = "medium"
    source: str = ""
    gap: str = ""
    status: str = "open"


class CatoStatus(BaseModel):
    """지속 인가(cATO) 상태 — POA&M 집계 + 인가 판정(결정론).

    Attributes:
        authorization: "authorized"(갭 없음)|"conditional"(중/저 갭)|"at_risk"(고위험).
        poam: 미충족 통제 목록.
        controls_evaluated: 평가한 통제 수.
        rationale: 판정 근거.
    """

    authorization: str = "authorized"
    poam: list[PoamItem] = Field(default_factory=list)
    controls_evaluated: int = 0
    rationale: list[str] = Field(default_factory=list)


class HuntHypothesis(BaseModel):
    """Tier3 위협 헌팅 가설 한 건 — 선제 hunt 백로그 항목(DoD SOC Tier3).

    예측/campaign/coverage-gap 신호를 융합한 *분석가 hunt 리드*(자문·읽기전용).
    staged_defenses(방어 준비)·hunt_candidates(legacy 예측나열)와 구분된 표면.

    Attributes:
        focus: 헌팅 대상(MITRE technique 또는 campaign 시나리오 id).
        source: "prediction" | "campaign" | "coverage_gap".
        priority: 결정론 우선순위(높을수록 먼저 헌팅).
        tactic: 대상 tactic(정렬·스코프용, 미상 빈값).
        rationale: 왜 헌팅하는가.
        target_hint: 어디를 볼지(자산/tactic 컨텍스트).
    """

    focus: str
    source: str
    priority: int = 0
    tactic: str = ""
    rationale: str = ""
    target_hint: str = ""


class IncidentState(StrEnum):
    """NIST 800-61 인시던트 생명주기 상태."""

    NEW = "new"
    ANALYSIS = "analysis"
    CONTAINMENT = "containment"  # report 도달 불가 — 신뢰확증 후속
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    CLOSED = "closed"


class IncidentCase(BaseModel):
    """관리되는 Incident Case — actor 단위 지속 생명주기 엔티티(DoD SOC 정렬).

    Attributes:
        case_id: 봉합 키(`case:<actor_id>`).
        actor_id: 봉합 actor(explicit 또는 fingerprint).
        state: 현재 생명주기 상태.
        cat: CJCSM 6510 CAT 분류(report 산 잠정: CAT6/CAT8).
        severity_peak: 관측 최고 심각도(provisional·informational — 권위 판정 비구동).
        kill_chain_stage: 관측 최고 kill-chain order.
        member_alert_ids: 소속 alert id(슬라이딩 cap).
        provisional: report 산 미확증 여부(True=신뢰확증 전).
        opened_at/updated_at: 타임스탬프.
    """

    case_id: str
    actor_id: str
    state: IncidentState = IncidentState.NEW
    cat: str = "CAT8"
    severity_peak: Severity = Severity.INFO
    kill_chain_stage: int = 0
    member_alert_ids: list[str] = Field(default_factory=list)
    provisional: bool = True
    reopen_count: int = Field(default=0, ge=0)  # 재범(CLOSED 재확정) 횟수
    report_sla_min: int = 0  # CJCSM 6510 CAT별 보고 SLA(분)
    report_due_at: str = ""  # 상급 보고 데드라인(opened_at + SLA, ISO)
    opened_at: str = ""
    updated_at: str = ""


class IncidentDirective(BaseModel):
    """Incident Commander 지시(자문·읽기전용) — 생명주기 오케스트레이션.

    Case 신호를 읽어 산출하는 결정론 권고. COA·hunt 와 동일하게 자문뿐 — 자동
    에스컬레이션/태스킹 실행 없음. HITL/tier3 하드게이트는 권위 신호에만 걸린다.

    Attributes:
        escalation: 에스컬레이션 등급(low/medium/high).
        hitl_required: 인적 개입 필수 여부(권위 신호에만 True — 포이즈닝 봉인).
        assigned_tier: 태스킹 대상 티어(tier2/tier3).
        recommended_action: 현재 state 기반 권고 조치.
        report_overdue: 상급 보고(CJCSM 6510 지휘체계) 시한 초과 여부(now 미가용 False).
        cisa_reportable: CIRCIA 연방(CISA) 72h 보고 대상 여부(권위·중대 case 만).
        cisa_report_overdue: CISA 연방 72h 시한 초과 여부(상급 보고와 별 경로).
        provisional: 원본 case 미확증 여부 — 지시 신뢰도 명시.
        rationale: 판단 근거 목록(감사·설명용).
    """

    escalation: str = "low"
    hitl_required: bool = False
    assigned_tier: str = "tier2"
    recommended_action: str = ""
    report_overdue: bool = False
    cisa_reportable: bool = False
    cisa_report_overdue: bool = False
    provisional: bool = True
    rationale: list[str] = Field(default_factory=list)


class DiamondEvent(BaseModel):
    """침입분석 다이아몬드 한 건 — 4 정점(Adversary·Capability·Infrastructure·Victim).

    actor_fingerprint 를 침입분석 다이아몬드(교리)로 정형화한다. 정점 간 피벗으로
    "같은 인프라/능력을 쓰는 다른 사건" 을 상관한다.

    Attributes:
        adversary: 공격자 식별(actor_id 또는 fingerprint).
        capabilities: 능력 정점 — MITRE technique 목록.
        infrastructure: 인프라 정점 — IOC 값(ip_24/도메인 등).
        victim: 피해 정점 — 대상 자산 id.
        victim_tier: 피해 자산 tier.
        mission_phase: 메타피처 — 임무 단계.
    """

    adversary: str = ""
    capabilities: list[str] = Field(default_factory=list)
    infrastructure: list[str] = Field(default_factory=list)
    victim: str = ""
    victim_tier: str = ""
    mission_phase: str = ""


class DiamondPivot(BaseModel):
    """정점 공유 피벗 결과 한 건 — 같은 정점값을 쓰는 사건 상관.

    Attributes:
        vertex: 정점 종류("capability"|"infrastructure"|"victim").
        value: 공유된 정점 값.
        adversaries: 이 정점을 공유한 공격자 집합(정렬).
        count: 공유 사건 수.
    """

    vertex: str
    value: str
    adversaries: list[str] = Field(default_factory=list)
    count: int = 0


class BdaReport(BaseModel):
    """사이버 교전피해평가(BDA) 한 건 — 교전 후 피해·임무영향·복구권고(JP 3-60).

    방어 효과(effect: 1=완전차단·0=완전실패)의 역을 기능피해로 환산하고, 복구 성공
    여부와 임무 지속성으로 재교전(복구) 필요성을 판정한다.

    Attributes:
        damage_level: "none"|"light"|"moderate"|"severe" — 기능피해 등급.
        effect: 방어 효과(0~1). 낮을수록 피해 큼.
        mission_impact: 임무영향 서술(MissionContinuity 연계).
        restore_recommended: 복구/재교전 권고 여부(복구 미완·잔존 시 True).
        confidence: "high"|"low" — 관측 충분도 기반 평가 확신도.
        rationale: 산정 근거.
    """

    damage_level: str = "none"
    effect: float = 1.0
    mission_impact: str = ""
    restore_recommended: bool = False
    confidence: str = "low"
    rationale: list[str] = Field(default_factory=list)


class CampaignMatch(BaseModel):
    """진행 중 캠페인 체인 매칭 한 건(2층 상관 — 시나리오 시퀀스).

    Attributes:
        chain_id: 캠페인 체인 id(C1~C7).
        name: 캠페인명(공격 흐름).
        matched: 관측된 시퀀스 단계 수(prefix subsequence 매칭).
        total: 캠페인 전체 시퀀스 길이.
        next_expected: 다음 예상 시나리오 id(완료 시 빈값).
        severity: 캠페인 심각도(critical/high).
    """

    chain_id: str
    name: str = ""
    matched: int = 0
    total: int = 0
    next_expected: str = ""
    severity: str = ""


class StrideThreat(BaseModel):
    """UAV STRIDE 위협 분류 한 건(2025 IET UAV STRIDE 모델).

    Attributes:
        code: STRIDE 코드(S/T/R/I/D/E).
        name: 위협 유형명(Spoofing/Tampering/…).
        mitigation: 완화책(D3FEND/COA 연계).
    """

    code: str
    name: str
    mitigation: str = ""


class MissionContinuity(BaseModel):
    """자산 손상 시 임무 지속성 판정 한 건(graceful degradation).

    DoD mission assurance: 손상된 능력으로라도 임무를 계속할 수 있는지 + 대체 경로.

    Attributes:
        asset_id: 손상 자산 id.
        level: SUSTAINED(저하 지속) | MINIMAL(핵심 안전능력만) | ABORT(임무 불가).
        capability_lost: 손실된 능력 서술.
        fallback: 대체 능력·경로(페일오버).
        sustains: 임무 완수 가능 여부(SUSTAINED=True).
    """

    asset_id: str
    level: str
    capability_lost: str = ""
    fallback: str = ""
    sustains: bool = False


class RecoveryStep(BaseModel):
    """축출/복구 절차 한 단계(D3FEND Evict/Restore).

    Attributes:
        action: 구체 UAV 절차 서술.
        d3fend_id: 매핑된 D3FEND technique id.
    """

    action: str
    d3fend_id: str = ""


class RecoveryPlan(BaseModel):
    """정탐 후 공격자 축출 → 시스템 복구 → 검증 순차 플랜(D3FEND Evict/Restore).

    실행권은 defense_playbook 이 갖는다 — 이 플랜은 결정론 절차 제시. 검증 단계는
    outcome_probe 의 reoccurred(재발) 관측과 연계: 축출 후 재발 = 축출 실패.

    Attributes:
        tactic: 대상 kill chain 단계(tactic 이름).
        evict_steps: 공격자 축출 단계(자격증명/세션/접근 축출).
        restore_steps: 시스템 복구 단계(재이미징/페일오버/백업 전환).
        verify: 재감염 검증 절차(reoccurred 관측 시 축출 실패 대응).
    """

    tactic: str
    evict_steps: list[RecoveryStep] = Field(default_factory=list)
    restore_steps: list[RecoveryStep] = Field(default_factory=list)
    verify: str = ""


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
    hunt_hypotheses: list[HuntHypothesis] = Field(
        default_factory=list,
        description="Tier3 위협 헌팅 백로그 — 예측/campaign/gap 융합 우선순위 리드.",
    )
    staged_defenses: list[StagedDefense] = Field(
        default_factory=list,
        description="예측 폐루프: 예측 TTP 선제 스테이징 판정(staged/accelerate/gap).",
    )
    coa_options: list[CoaOption] = Field(
        default_factory=list,
        description="COA matrix: 현재+예측 단계 7D 방어 옵션(교리 courses of action).",
    )
    recovery_plan: RecoveryPlan | None = Field(
        default=None,
        description="정탐 확정 시 공격자 축출→복구→검증 절차(D3FEND Evict/Restore).",
    )
    mission_continuity: MissionContinuity | None = Field(
        default=None,
        description="graceful degradation: 손상 자산 임무 지속성 등급 + 대체경로.",
    )
    stride_threats: list[StrideThreat] = Field(
        default_factory=list,
        description="UAV STRIDE 모델: 이 공격의 위협 유형 분류 + 완화책.",
    )
    sbom_findings: list[SbomFinding] = Field(
        default_factory=list,
        description="공급망 검증: 미등록/변조/취약 컴포넌트(SBOM 무결성).",
    )
    campaign_matches: list[CampaignMatch] = Field(
        default_factory=list,
        description="캠페인 체인(2층 상관): actor 시나리오 시퀀스 → 진행 중 캠페인.",
    )
    causal_summary: CausalChain | None = Field(
        default=None, description="spec A1: 결정론 인과 체인 요약."
    )
    mission_risk: MissionRisk | None = Field(
        default=None,
        description="MBCRA: METT-TC 융합 임무위험(사이버 핵심지형·의존·적진행도).",
    )
    diamond: DiamondEvent | None = Field(
        default=None,
        description="침입분석 다이아몬드 4정점(actor·능력·인프라·피해).",
    )
    incident_case: IncidentCase | None = Field(
        default=None,
        description="Incident Case(생명주기·CAT) — actor 봉합 사건(provisional).",
    )
    incident_directive: IncidentDirective | None = Field(
        default=None,
        description="Incident Commander 지시(에스컬레이션·티어·HITL) — 자문.",
    )
    aibom_findings: list[AibomFinding] = Field(
        default_factory=list,
        description="AIBOM 거버넌스 위험(AI 공급망·출처) — 정적 posture(캐시).",
    )
    zt_mapping: ZtMapping | None = Field(
        default=None,
        description="ZTMM self-attested 통제 매핑(측정 아님) — 정적 거버넌스(캐시).",
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
