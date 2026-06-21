"""LLM 클라이언트 — 요약/판정용 비결정 추론.

구현단계는 **Ollama(로컬, qwen2.5)** 로 실연동한다. 추후 Azure OpenAI(GPT-4o 등)로
교체하더라도 에이전트는 `LLMClient` Protocol 만 의존하므로 `get_llm_client()` 의
분기만 바꾸면 된다(swappable). 심각도 판정권은 LLM 이 아니라 정책 엔진이 가지므로,
LLM 은 보조(요약·후보 판정)에만 쓴다.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import httpx

from core.exceptions import LLMError
from core.settings import Settings, get_settings


@runtime_checkable
class LLMClient(Protocol):
    """에이전트가 의존하는 LLM 계약(요약/판정용)."""

    async def acomplete(self, system: str, user: str) -> str:
        """system/user 프롬프트로 1회 완성을 반환한다."""
        ...


class OllamaLLMClient:
    """Ollama 챗 API 기반 LLM 클라이언트(로컬)."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    def _make_client(self) -> httpx.AsyncClient:
        """비동기 HTTP 클라이언트 생성(테스트에서 주입 가능)."""
        return httpx.AsyncClient(timeout=self._settings.llm_timeout_seconds)

    async def acomplete(self, system: str, user: str) -> str:
        """Ollama 챗 모델로 완성을 생성한다.

        Args:
            system: 시스템 지시.
            user: 사용자 입력.

        Returns:
            모델 응답 텍스트.

        Raises:
            LLMError: 네트워크/응답 오류 시.
        """
        payload: dict[str, object] = {
            "model": self._settings.ollama_chat_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
        }
        try:
            async with self._make_client() as client:
                response = await client.post(
                    self._settings.ollama_chat_url, json=payload
                )
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            raise LLMError(f"Ollama 호출 오류: {exc}") from exc
        except ValueError as exc:
            raise LLMError("Ollama 응답 JSON 파싱 실패") from exc

        message = body.get("message") if isinstance(body, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise LLMError("Ollama 응답에 message.content 없음")
        return content.strip()


def get_llm_client(settings: Settings | None = None) -> LLMClient:
    """설정에 따라 LLM 클라이언트를 반환한다(구현단계=Ollama).

    Args:
        settings: 전역 설정(미지정 시 환경에서 로드).

    Returns:
        `LLMClient` 구현체.

    Raises:
        LLMError: 미지원 provider 일 때.
    """
    settings = settings or get_settings()
    if settings.llm_provider == "ollama":
        return OllamaLLMClient(settings)
    # TODO: provider == "azure" → AzureOpenAILLMClient (추후 교체)
    raise LLMError(f"미지원 LLM provider: {settings.llm_provider}")
