"""RagflowRetrievalTool 단위 테스트.

httpx.MockTransport 로 RAGFlow 응답을 모킹한다(외부 호출/추가 의존성 없음).
`_make_client` 를 monkeypatch 해서 MockTransport 를 주입한다.
"""

import json

import httpx
from pydantic import SecretStr
import pytest

from core.exceptions import RagflowQueryError
from core.models import RetrievedChunk
from core.settings import Settings
from tools.ragflow_tool import KbCategory, RagflowRetrievalTool

_SAMPLE_RESPONSE: dict[str, object] = {
    "code": 0,
    "data": {
        "chunks": [
            {
                "content": "GPS 재밍 시 satellites_used 급감, noise_per_ms 상승.",
                "document_keyword": "ieee_uav_attack_gps_signatures.md",
                "similarity": 0.83,
            },
            {
                "content": "스푸핑은 위성수 정상이나 eph/hdop 정밀도 저하.",
                "document_keyword": "incident_case_gps_jamming_vs_spoofing.md",
                "similarity": 0.77,
            },
        ]
    },
}


def _settings() -> Settings:
    return Settings(
        ragflow_base_url="http://test-ragflow:9380",
        ragflow_api_token=SecretStr("test-token"),
        ragflow_dataset_id="ds-test",
    )


def _install_transport(
    monkeypatch: pytest.MonkeyPatch,
    tool: RagflowRetrievalTool,
    handler: object,
) -> None:
    """tool._make_client 가 MockTransport 를 쓰도록 패치한다."""
    transport = httpx.MockTransport(handler)  # type: ignore[arg-type]

    def make_client(self: RagflowRetrievalTool) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=transport, timeout=5.0)

    monkeypatch.setattr(RagflowRetrievalTool, "_make_client", make_client)


class TestRagflowRetrievalTool:
    """RagflowRetrievalTool 동작 검증."""

    @pytest.mark.asyncio
    async def test_aretrieve_returns_normalized_chunks(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """정상 응답이 kb/ 출처로 정규화된 청크로 변환되는지 확인."""

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/v1/retrieval"
            assert request.headers["Authorization"] == "Bearer test-token"
            return httpx.Response(200, json=_SAMPLE_RESPONSE)

        tool = RagflowRetrievalTool(settings=_settings())
        _install_transport(monkeypatch, tool, handler)
        chunks = await tool.aretrieve("GPS 재밍")

        assert len(chunks) == 2
        assert all(isinstance(c, RetrievedChunk) for c in chunks)
        assert all(c.source.startswith("kb/") for c in chunks)
        assert chunks[0].score == pytest.approx(0.83)

    @pytest.mark.asyncio
    async def test_empty_token_raises(self) -> None:
        """토큰/데이터셋 미설정 시 RagflowQueryError 발생."""
        tool = RagflowRetrievalTool(
            settings=Settings(ragflow_api_token=SecretStr(""), ragflow_dataset_id="")
        )
        with pytest.raises(RagflowQueryError):
            await tool.aretrieve("x")

    @pytest.mark.asyncio
    async def test_http_error_raises_query_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """HTTP 500 응답이 RagflowQueryError 로 변환되는지 확인."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"message": "boom"})

        tool = RagflowRetrievalTool(settings=_settings())
        _install_transport(monkeypatch, tool, handler)
        with pytest.raises(RagflowQueryError):
            await tool.aretrieve("q")

    @pytest.mark.asyncio
    async def test_api_error_code_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """code!=0 응답이 RagflowQueryError 로 변환되는지 확인."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"code": 102, "message": "denied"})

        tool = RagflowRetrievalTool(settings=_settings())
        _install_transport(monkeypatch, tool, handler)
        with pytest.raises(RagflowQueryError):
            await tool.aretrieve("q")

    @pytest.mark.asyncio
    async def test_arun_returns_formatted_text(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """LangChain _arun 진입점이 출처 표기 텍스트를 반환하는지 확인."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_SAMPLE_RESPONSE)

        tool = RagflowRetrievalTool(settings=_settings())
        _install_transport(monkeypatch, tool, handler)
        text = await tool._arun("GPS 재밍")
        assert "kb/ieee_uav_attack_gps_signatures.md" in text

    @pytest.mark.asyncio
    async def test_category_adds_metadata_condition(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """category 지정 시 metadata_condition 필터가 요청에 포함되는지 확인."""
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured.update(json.loads(request.content))
            return httpx.Response(200, json=_SAMPLE_RESPONSE)

        tool = RagflowRetrievalTool(settings=_settings())
        _install_transport(monkeypatch, tool, handler)
        await tool.aretrieve("GPS", category=KbCategory.INCIDENT_CASES)

        cond = captured.get("metadata_condition")
        assert isinstance(cond, dict)
        assert cond["conditions"][0]["name"] == "category"
        assert cond["conditions"][0]["value"] == "incident_cases"

    @pytest.mark.asyncio
    async def test_no_category_omits_metadata_condition(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """category 미지정 시 metadata_condition 이 없어야(전체 검색) 한다."""
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured.update(json.loads(request.content))
            return httpx.Response(200, json=_SAMPLE_RESPONSE)

        tool = RagflowRetrievalTool(settings=_settings())
        _install_transport(monkeypatch, tool, handler)
        await tool.aretrieve("GPS")

        assert "metadata_condition" not in captured

    def test_sync_run_not_supported(self) -> None:
        """동기 _run 은 NotImplementedError 를 던진다."""
        tool = RagflowRetrievalTool(settings=_settings())
        with pytest.raises(NotImplementedError):
            tool._run("q")

    def test_is_langchain_basetool(self) -> None:
        """LangChain BaseTool 계약(name/description/args_schema) 충족."""
        tool = RagflowRetrievalTool(settings=_settings())
        assert tool.name == "ragflow_retrieval"
        assert tool.args_schema is not None
