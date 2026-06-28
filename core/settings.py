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
