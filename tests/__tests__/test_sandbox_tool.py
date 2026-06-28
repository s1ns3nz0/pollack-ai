"""샌드박스 어댑터 — StubSandbox / HybridAnalysisTool 판정·파싱·조회."""

import httpx
from pydantic import SecretStr
import pytest

from core.exceptions import SandboxError
from core.models import TiVerdict
from core.settings import Settings
from tools.sandbox_tool import HybridAnalysisTool, StubSandbox

_HASH = "a" * 64


def _client_factory(handler: object) -> object:
    def make() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]

    return make


class TestStubSandbox:
    """오프라인 결정론 디토네이션."""

    @pytest.mark.asyncio
    async def test_malicious_with_iocs(self) -> None:
        sb = StubSandbox(malicious=frozenset({_HASH}), extracted_iocs=["45.146.165.37"])
        report = await sb.adetonate(_HASH)
        assert report.verdict == TiVerdict.MALICIOUS
        assert report.score == 90
        assert report.signatures
        assert "45.146.165.37" in report.extracted_iocs  # TI 되먹임 가능

    @pytest.mark.asyncio
    async def test_unknown(self) -> None:
        report = await StubSandbox().adetonate("deadbeef")
        assert report.verdict == TiVerdict.UNKNOWN


class TestHybridAnalysisParse:
    """응답 검증·판정(미검증 외부 입력 가드)."""

    def test_malicious(self) -> None:
        body = {"verdict": "malicious", "threat_score": 95, "tags": ["trojan", "c2"]}
        report = HybridAnalysisTool.parse(_HASH, body)
        assert report.verdict == TiVerdict.MALICIOUS
        assert report.score == 95
        assert "trojan" in report.signatures

    def test_clean_and_suspicious(self) -> None:
        clean = HybridAnalysisTool.parse(_HASH, {"verdict": "whitelisted"})
        assert clean.verdict == TiVerdict.CLEAN
        susp = HybridAnalysisTool.parse(_HASH, {"verdict": "suspicious"})
        assert susp.verdict == TiVerdict.SUSPICIOUS

    def test_malformed_is_unknown(self) -> None:
        assert HybridAnalysisTool.parse(_HASH, {"x": 1}).verdict == TiVerdict.UNKNOWN
        assert HybridAnalysisTool.parse(_HASH, "bad").verdict == TiVerdict.UNKNOWN


class TestHybridAnalysisLookup:
    """실 조회 경로 — mock transport(네트워크 없음)."""

    @pytest.mark.asyncio
    async def test_malicious_response(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"verdict": "malicious", "threat_score": 88}
            )

        tool = HybridAnalysisTool(
            settings=Settings(hybridanalysis_api_key=SecretStr("k")),
            client_factory=_client_factory(handler),
        )
        report = await tool.adetonate(_HASH)
        assert report.verdict == TiVerdict.MALICIOUS
        assert report.source == "hybrid-analysis"

    @pytest.mark.asyncio
    async def test_404_is_unknown(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        tool = HybridAnalysisTool(
            settings=Settings(hybridanalysis_api_key=SecretStr("k")),
            client_factory=_client_factory(handler),
        )
        report = await tool.adetonate(_HASH)
        assert report.verdict == TiVerdict.UNKNOWN

    @pytest.mark.asyncio
    async def test_non_hash_is_unknown(self) -> None:
        tool = HybridAnalysisTool(
            settings=Settings(hybridanalysis_api_key=SecretStr("k"))
        )
        report = await tool.adetonate("not-a-hash")
        assert report.verdict == TiVerdict.UNKNOWN

    @pytest.mark.asyncio
    async def test_missing_key_raises(self) -> None:
        with pytest.raises(SandboxError):
            await HybridAnalysisTool(settings=Settings()).adetonate(_HASH)
