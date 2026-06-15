"""애플리케이션 설정. 환경변수 또는 `.env` 파일에서 로드.

하드코딩 금지 원칙에 따라 RAGFlow 접속 정보·검색 파라미터를 모두 외부화한다.
API 토큰은 `SecretStr` 로 보관해 로그 노출을 방지한다.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class RagflowSettings(BaseSettings):
    """RAGFlow 지식베이스 연동 설정.

    필드는 동일 이름의 대문자 환경변수(`RAGFLOW_BASE_URL` 등) 또는 `.env` 에서
    읽는다. 토큰/데이터셋 ID 가 비어 있으면 도구 호출 시점에 검증한다.
    """

    model_config = SettingsConfigDict(
        env_prefix="RAGFLOW_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    base_url: str = Field(
        default="http://127.0.0.1:9380",
        description="RAGFlow API 베이스 URL.",
    )
    api_token: SecretStr = Field(
        default=SecretStr(""),
        description="RAGFlow API 토큰(Bearer).",
    )
    dataset_id: str = Field(
        default="",
        description="검색 대상 지식베이스(dataset) ID.",
    )
    similarity_threshold: float = Field(
        default=0.2,
        ge=0.0,
        le=1.0,
        description="검색 유사도 하한.",
    )
    vector_weight: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        description="벡터 유사도 가중치(나머지는 BM25).",
    )
    top_k: int = Field(default=1024, gt=0, description="벡터 후보 풀 크기.")
    timeout_seconds: float = Field(
        default=60.0,
        gt=0.0,
        description="검색 요청 타임아웃(초).",
    )

    @property
    def retrieval_url(self) -> str:
        """검색 엔드포인트 전체 URL."""
        return f"{self.base_url.rstrip('/')}/api/v1/retrieval"


@lru_cache(maxsize=1)
def get_ragflow_settings() -> RagflowSettings:
    """프로세스 단위로 캐시된 RAGFlow 설정 인스턴스를 반환한다.

    Returns:
        환경변수/.env 에서 로드된 `RagflowSettings`.
    """
    return RagflowSettings()
