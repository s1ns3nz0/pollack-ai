"""Alert — detection→analysis 계약(wire 스키마) + 신뢰경계.

**계약 파일**: detection(센티넬 룰, 별 레포 dah-sentinel-content)이 산출하고 analysis
파이프라인이 소비하는 입력 경보. models.py(거대 단일 파일)에서 분리해 Alert 변경(드문
계약 변경)이 analysis 모델 편집과 충돌하지 않게 한다. 변경 시 CODEOWNERS 양측 리뷰 +
docs/CONTRACT-detection-analysis.md 갱신.

트러스트 경계: UntrustedAlertPayload(외부 HTTP wire 화이트리스트) 는 `_INTERNAL_ONLY_
FIELDS`(파이프라인/게이트 산출 12필드)를 물리적으로 갖지 않아 위조 불가.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from core.primitives import SbomComponent, Severity, Verdict


class Alert(BaseModel):
    """SOC 파이프라인 입력 경보(시나리오에서 파생).

    `llm_suggested_severity` 는 적대적으로 주입될 수 있는 제안 등급이며 신뢰하지
    않는다(Triage 가드레일용 — S5 RAG 포이즈닝 방어).
    """

    id: str
    scenario_id: str
    title: str
    time_generated: str = ""
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
    time_generated: str = ""
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
        """서술 필드만으로 내부 Alert 구성(내부전용 필드는 Alert 기본값 유지).

        Returns:
            신뢰 경계를 통과한 내부 Alert 모델.
        """
        return Alert(**self.model_dump())


def has_forged_internal_fields(payload: object) -> list[str]:
    """payload(dict)에 내부전용 키가 실려있으면 그 목록 반환(위조 시도 telemetry용)."""
    if not isinstance(payload, dict):
        return []
    return sorted(k for k in payload if k in _INTERNAL_ONLY_FIELDS)
