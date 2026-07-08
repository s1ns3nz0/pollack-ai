"""애플리케이션 전역 설정. 환경변수 또는 `.env` 파일에서 로드.

하드코딩 금지 원칙에 따라 접속 정보·검색 파라미터를 모두 외부화한다. 팀 컨벤션대로
모든 설정은 이 단일 `Settings` 클래스에 모은다. 새 연동(Azure OpenAI/Sentinel 등)을
추가할 때도 별도 설정 클래스를 만들지 말고 이 클래스에 섹션으로 덧붙인다.

필드명은 동일 이름의 대문자 환경변수와 매핑된다(`ragflow_base_url` ← env
`RAGFLOW_BASE_URL`). API 토큰은 `SecretStr` 로 보관해 로그·표현식 노출을 방지한다.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """전역 설정. 환경변수/.env 에서 로드.

    크래시 없이 import 되도록 모든 필드에 기본값을 둔다. 실제 사용 시점(도구 호출
    등)에 필수 값(토큰/데이터셋) 존재 여부를 검증한다.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── RAGFlow (로컬 RAG) ──────────────────────────────
    ragflow_base_url: str = Field(
        default="http://127.0.0.1:9380",
        description="RAGFlow API 베이스 URL.",
    )
    ragflow_api_token: SecretStr = Field(
        default=SecretStr(""),
        description="RAGFlow API 토큰(Bearer).",
    )
    ragflow_dataset_id: str = Field(
        default="",
        description="검색 대상 지식베이스(dataset) ID.",
    )
    ragflow_exp_dataset_id: str = Field(
        default="",
        description="경험메모리(exp/) 적립·회상 대상 dataset ID. 비면 영속화 비활성.",
    )
    ragflow_similarity_threshold: float = Field(
        default=0.2,
        ge=0.0,
        le=1.0,
        description="검색 유사도 하한.",
    )
    ragflow_vector_weight: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        description="벡터 유사도 가중치(나머지는 BM25).",
    )
    ragflow_top_k: int = Field(default=1024, gt=0, description="벡터 후보 풀 크기.")
    graph_rag_enabled: bool = Field(
        default=False,
        description="True 면 GraphRAG(TTP 그래프) 검색기를 기본 배선에 합성.",
    )
    ragflow_timeout_seconds: float = Field(
        default=60.0,
        gt=0.0,
        description="검색 요청 타임아웃(초).",
    )

    # ── LLM (구현단계=Ollama, 추후 Azure OpenAI 로 교체) ──────────
    llm_provider: str = Field(
        default="ollama",
        description="LLM 제공자: ollama | azure (구현단계는 ollama).",
    )
    ollama_base_url: str = Field(
        default="http://192.168.64.1:11443",
        description="Ollama 서버 URL(전용 인스턴스).",
    )
    ollama_chat_model: str = Field(
        default="qwen2.5:14b",
        description="Ollama 챗 모델.",
    )
    llm_timeout_seconds: float = Field(
        default=120.0,
        gt=0.0,
        description="LLM 요청 타임아웃(초).",
    )

    # ── 외부 위협 인텔(TI) — 멀티소스 어댑터 ──────────────
    virustotal_api_key: SecretStr = Field(
        default=SecretStr(""),
        description="VirusTotal API 키(x-apikey). 비면 VT 어댑터 비활성.",
    )
    virustotal_base_url: str = Field(
        default="https://www.virustotal.com/api/v3",
        description="VirusTotal v3 API 베이스 URL.",
    )
    greynoise_api_key: SecretStr = Field(
        default=SecretStr(""),
        description="GreyNoise Community API 키. 비면 어댑터 비활성.",
    )
    greynoise_base_url: str = Field(
        default="https://api.greynoise.io/v3/community",
        description="GreyNoise Community API 베이스 URL.",
    )
    abuseipdb_api_key: SecretStr = Field(
        default=SecretStr(""),
        description="AbuseIPDB API 키(Key 헤더). 비면 어댑터 비활성.",
    )
    abuseipdb_base_url: str = Field(
        default="https://api.abuseipdb.com/api/v2",
        description="AbuseIPDB v2 API 베이스 URL.",
    )
    threatfox_api_key: SecretStr = Field(
        default=SecretStr(""),
        description="ThreatFox(abuse.ch) Auth-Key. 비면 어댑터 비활성.",
    )
    threatfox_base_url: str = Field(
        default="https://threatfox-api.abuse.ch/api/v1",
        description="ThreatFox API 베이스 URL.",
    )
    ti_timeout_seconds: float = Field(
        default=20.0,
        gt=0.0,
        description="TI 조회 요청 타임아웃(초).",
    )

    # ── 샌드박스 디토네이션 ──────────────
    hybridanalysis_api_key: SecretStr = Field(
        default=SecretStr(""),
        description="Hybrid Analysis(Falcon Sandbox) API 키. 비면 어댑터 비활성.",
    )
    hybridanalysis_base_url: str = Field(
        default="https://www.hybrid-analysis.com/api/v2",
        description="Hybrid Analysis v2 API 베이스 URL.",
    )
    sandbox_timeout_seconds: float = Field(
        default=30.0,
        gt=0.0,
        description="샌드박스 조회 요청 타임아웃(초).",
    )

    # ── 취약점 컨텍스트 (CISA KEV / NVD) ──────────────
    cisa_kev_url: str = Field(
        default=(
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json"
        ),
        description="CISA KEV 카탈로그 JSON 피드 URL(공개, 키 불요).",
    )
    nvd_api_key: SecretStr = Field(
        default=SecretStr(""),
        description="NVD API 키(선택 — 없으면 낮은 레이트리밋).",
    )
    nvd_base_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="NVD CVE API v2.0 베이스 URL.",
    )
    vuln_timeout_seconds: float = Field(
        default=20.0,
        gt=0.0,
        description="취약점 조회 요청 타임아웃(초).",
    )

    # ── 탐지룰 저장소 (Watch List 자동 갱신) ──────────────
    sentinel_content_repo: str = Field(
        default="s1ns3nz0/dah-sentinel-content",
        description="Watch List/룰 콘텐츠 저장소(owner/name).",
    )
    github_token: SecretStr = Field(
        default=SecretStr(""),
        description="GitHub PAT(Watch List PR 생성용). 비면 publisher 비활성.",
    )
    github_base_url: str = Field(
        default="https://api.github.com",
        description="GitHub API 베이스 URL.",
    )
    rule_branch_prefix: str = Field(
        default="fix/watchlist",
        description="Watch List PR 브랜치 접두(저장소 컨벤션: FP 개선=fix).",
    )
    rule_base_branch: str = Field(
        default="main",
        description="Watch List PR 의 베이스 브랜치(머지 대상).",
    )
    github_timeout_seconds: float = Field(
        default=20.0,
        gt=0.0,
        description="GitHub API 요청 타임아웃(초).",
    )

    # ── 외부 공역/GNSS 컨텍스트 (Airspace & GNSS spec #1) ──────────
    gpsjam_endpoint: str = Field(
        default="https://gpsjam.org/api/",
        description="GPSJam 공개 REST 엔드포인트. 비면 어댑터 비활성.",
    )
    gpsjam_timeout_seconds: float = Field(
        default=15.0, gt=0.0, description="GPSJam 호출 타임아웃(초)."
    )
    opensky_base_url: str = Field(
        default="https://opensky-network.org/api",
        description="OpenSky Network REST 베이스 URL.",
    )
    opensky_username: SecretStr = Field(
        default=SecretStr(""),
        description="OpenSky 사용자명(익명 = 400req/day).",
    )
    opensky_password: SecretStr = Field(
        default=SecretStr(""),
        description="OpenSky 비밀번호.",
    )
    opensky_timeout_seconds: float = Field(
        default=15.0, gt=0.0, description="OpenSky 호출 타임아웃(초)."
    )
    airspace_known_friends: list[str] = Field(
        default_factory=list,
        description="콜사인 화이트리스트 — 등록 자산(외 → hostile).",
    )
    airspace_bbox_deg: float = Field(
        default=0.1,
        gt=0.0,
        description="OpenSky BBox 반경(deg). 0.1 ≒ ±11km.",
    )

    # ── RAGAS 분석 품질 측정 (spec D1) ──────────────
    ragas_enabled: bool = Field(
        default=False, description="opt-in — 비동기 RAGAS 측정."
    )
    ragas_faithfulness_threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="faithfulness 임계(미달 시 가드 플래그).",
    )
    ragas_answer_relevancy_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    ragas_context_relevancy_threshold: float = Field(default=0.7, ge=0.0, le=1.0)

    # ── 공격 시퀀스 예측 (spec C1) ──────────────
    predict_min_support: int = Field(
        default=3, ge=1, description="n-gram 채택 최소 빈도."
    )
    predict_min_probability: float = Field(
        default=0.5, ge=0.0, le=1.0, description="조건부 확률 임계."
    )
    predict_top_k: int = Field(default=3, ge=1, description="후보 상위 K.")

    # ── 인과 추론 (spec A1) ──────────────
    causal_rules_path: str = Field(
        default="core/policy/causal-rules.yaml",
        description="결정론 인과 룰 yaml 경로.",
    )
    causal_llm_explain: bool = Field(
        default=False, description="LLM 으로 step.explanation 채울지(opt-in)."
    )

    # ── 위협 피드 (spec T1) ──────────────
    feed_refresh_hours: int = Field(default=24, ge=1, description="피드 갱신 주기.")
    feed_user_agent: str = Field(default="pollack-ai-threat-landscape/1.0")
    feed_added_cap: int = Field(default=100, ge=1, description="자동 적용 상한.")
    attack_feed_url: str = Field(
        default=(
            "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/"
            "enterprise-attack.json"
        )
    )
    atlas_feed_url: str = Field(
        default=(
            "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/"
            "dist/ATLAS.yaml"
        )
    )
    embed3d_feed_url: str = Field(default="")
    kev_feed_url: str = Field(
        default=(
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json"
        )
    )

    # ── Data Lineage (spec D-1) ──────────────
    lineage_enabled: bool = Field(
        default=False,
        description="opt-in — Report 노드가 라인리지 스냅샷을 OSCAL evidence 에 임베드.",
    )

    # ── CPCON 사이버 태세 (DoD CPCON / 국정원 위기경보) ──────────────
    cyber_posture_level: int = Field(
        default=5,
        ge=1,
        le=5,
        description=(
            "전역 사이버방어태세. DoD CPCON 5(정상)~1(심각) = 국정원 정상/관심/"
            "주의/경계/심각. 외부 태세 피드/운영자가 설정 → 전 alert 방어강도 하한."
        ),
    )

    @property
    def ragflow_retrieval_url(self) -> str:
        """RAGFlow 검색 엔드포인트 전체 URL."""
        return f"{self.ragflow_base_url.rstrip('/')}/api/v1/retrieval"

    @property
    def ollama_chat_url(self) -> str:
        """Ollama 챗 엔드포인트 전체 URL."""
        return f"{self.ollama_base_url.rstrip('/')}/api/chat"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """프로세스 단위로 캐시된 전역 설정 인스턴스를 반환한다.

    Returns:
        환경변수/.env 에서 로드된 `Settings`.
    """
    return Settings()
