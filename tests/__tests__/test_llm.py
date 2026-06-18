"""OllamaLLMClient + Investigation LLM 요약 테스트.

httpx.MockTransport 로 Ollama 응답을 모킹한다(외부 호출 없음).
"""

import httpx
import pytest

from agents.investigation_agent import InvestigationAgent
from core.exceptions import LLMError
from core.llm import OllamaLLMClient, get_llm_client
from core.models import Alert, Severity, SOCState
from core.settings import Settings


def _settings() -> Settings:
    return Settings(
        ollama_base_url="http://test-ollama:11443", ollama_chat_model="qwen2.5:14b"
    )


def _alert() -> Alert:
    return Alert(
        id="A1",
        scenario_id="UAV-GPS-SPOOF-001",
        title="GPS 스푸핑",
        severity_baseline=Severity.HIGH,
        signals=["GNSS-INS 잔차 급증"],
    )


def _install(monkeypatch: pytest.MonkeyPatch, handler: object) -> None:
    transport = httpx.MockTransport(handler)  # type: ignore[arg-type]

    def make_client(self: OllamaLLMClient) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=transport, timeout=5.0)

    monkeypatch.setattr(OllamaLLMClient, "_make_client", make_client)


class TestOllamaLLMClient:
    """Ollama 클라이언트 동작."""

    @pytest.mark.asyncio
    async def test_acomplete_returns_content(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """정상 응답에서 message.content 를 반환."""

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/chat"
            return httpx.Response(200, json={"message": {"content": "  요약 결과  "}})

        client = OllamaLLMClient(_settings())
        _install(monkeypatch, handler)
        out = await client.acomplete("sys", "user")
        assert out == "요약 결과"

    @pytest.mark.asyncio
    async def test_http_error_raises_llm_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """HTTP 500 → LLMError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={})

        client = OllamaLLMClient(_settings())
        _install(monkeypatch, handler)
        with pytest.raises(LLMError):
            await client.acomplete("s", "u")

    def test_factory_returns_ollama(self) -> None:
        """provider=ollama → OllamaLLMClient."""
        assert isinstance(get_llm_client(_settings()), OllamaLLMClient)

    def test_factory_rejects_unknown_provider(self) -> None:
        """미지원 provider → LLMError."""
        with pytest.raises(LLMError):
            get_llm_client(Settings(llm_provider="unknown"))


class TestInvestigationWithLLM:
    """Investigation LLM 요약/폴백."""

    @pytest.mark.asyncio
    async def test_llm_summary_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """LLM 주입 시 LLM 생성 요약이 들어간다."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"message": {"content": "LLM 상관분석 요약"}}
            )

        _install(monkeypatch, handler)
        agent = InvestigationAgent(_settings(), None, OllamaLLMClient(_settings()))
        out = await agent.run({"alert": _alert()})
        assert out["investigation"].summary == "LLM 상관분석 요약"

    @pytest.mark.asyncio
    async def test_fallback_when_no_llm(self) -> None:
        """LLM 미주입 시 결정론적 요약으로 폴백."""
        agent = InvestigationAgent(_settings(), None, None)
        out: SOCState = await agent.run({"alert": _alert()})
        assert "상관분석" in out["investigation"].summary

    @pytest.mark.asyncio
    async def test_fallback_on_llm_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """LLM 오류 시 결정론적 요약으로 폴백(파이프라인 안전)."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={})

        _install(monkeypatch, handler)
        agent = InvestigationAgent(_settings(), None, OllamaLLMClient(_settings()))
        out = await agent.run({"alert": _alert()})
        assert "신뢰 사례" in out["investigation"].summary
