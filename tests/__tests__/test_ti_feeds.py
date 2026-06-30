"""TI 시작세트 어댑터 — GreyNoise / AbuseIPDB / ThreatFox 분류·파싱·조회."""

import httpx
from pydantic import SecretStr
import pytest

from core.exceptions import ThreatIntelError
from core.models import TiVerdict
from core.settings import Settings
from tools.ti_tool import (
    AbuseIpdbTool,
    GreyNoiseTool,
    HoneypotFeedTool,
    ThreatFoxTool,
)

_IP = "203.0.113.7"
_HASH = "a" * 64


def _client_factory(handler: object) -> object:
    def make() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]

    return make


def _json_handler(payload: object, status: int = 200) -> object:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=payload)

    return handler


class TestGreyNoise:
    """배경 스캔 노이즈 vs 표적 악성(FP 감축)."""

    def test_parse(self) -> None:
        assert (
            GreyNoiseTool.parse(_IP, {"classification": "malicious"}).verdict
            == TiVerdict.MALICIOUS
        )
        assert (
            GreyNoiseTool.parse(_IP, {"classification": "benign"}).verdict
            == TiVerdict.CLEAN
        )
        assert GreyNoiseTool.parse(_IP, {"noise": True}).verdict == TiVerdict.SUSPICIOUS
        assert GreyNoiseTool.parse(_IP, {}).verdict == TiVerdict.UNKNOWN

    @pytest.mark.asyncio
    async def test_lookup_and_ip_only(self) -> None:
        gn = GreyNoiseTool(
            settings=Settings(greynoise_api_key=SecretStr("k")),
            client_factory=_client_factory(
                _json_handler({"classification": "malicious"})
            ),
        )
        out = {f.indicator: f.verdict for f in await gn.alookup([_IP, _HASH])}
        assert out[_IP] == TiVerdict.MALICIOUS
        assert out[_HASH] == TiVerdict.UNKNOWN  # IP 전용 소스

    @pytest.mark.asyncio
    async def test_missing_key_raises(self) -> None:
        with pytest.raises(ThreatIntelError):
            await GreyNoiseTool(settings=Settings()).alookup([_IP])


class TestAbuseIpdb:
    """IP 악용 신뢰도(0~100)."""

    def test_parse(self) -> None:
        def score(n: int) -> TiVerdict:
            return AbuseIpdbTool.parse(
                _IP, {"data": {"abuseConfidenceScore": n}}
            ).verdict

        assert score(90) == TiVerdict.MALICIOUS
        assert score(50) == TiVerdict.SUSPICIOUS
        assert score(5) == TiVerdict.CLEAN
        assert AbuseIpdbTool.parse(_IP, {"oops": 1}).verdict == TiVerdict.UNKNOWN

    @pytest.mark.asyncio
    async def test_lookup_malicious(self) -> None:
        tool = AbuseIpdbTool(
            settings=Settings(abuseipdb_api_key=SecretStr("k")),
            client_factory=_client_factory(
                _json_handler({"data": {"abuseConfidenceScore": 95}})
            ),
        )
        out = await tool.alookup([_IP])
        assert out[0].verdict == TiVerdict.MALICIOUS

    @pytest.mark.asyncio
    async def test_missing_key_raises(self) -> None:
        with pytest.raises(ThreatIntelError):
            await AbuseIpdbTool(settings=Settings()).alookup([_IP])


class TestThreatFox:
    """악성 IOC DB 검색(해시/IP/도메인/URL)."""

    def test_parse(self) -> None:
        ok = {"query_status": "ok", "data": [{"confidence_level": 100}]}
        assert ThreatFoxTool.parse(_HASH, ok).verdict == TiVerdict.MALICIOUS
        mid = {"query_status": "ok", "data": [{"confidence_level": 50}]}
        assert ThreatFoxTool.parse(_HASH, mid).verdict == TiVerdict.SUSPICIOUS
        assert (
            ThreatFoxTool.parse(_HASH, {"query_status": "no_result"}).verdict
            == TiVerdict.UNKNOWN
        )
        assert ThreatFoxTool.parse(_HASH, "bad").verdict == TiVerdict.UNKNOWN

    @pytest.mark.asyncio
    async def test_lookup_malicious(self) -> None:
        tool = ThreatFoxTool(
            settings=Settings(threatfox_api_key=SecretStr("k")),
            client_factory=_client_factory(
                _json_handler(
                    {"query_status": "ok", "data": [{"confidence_level": 90}]}
                )
            ),
        )
        out = await tool.alookup([_HASH])
        assert out[0].verdict == TiVerdict.MALICIOUS

    @pytest.mark.asyncio
    async def test_missing_key_raises(self) -> None:
        with pytest.raises(ThreatIntelError):
            await ThreatFoxTool(settings=Settings()).alookup([_HASH])


class TestHoneypotFeed:
    """내부 데코이 피드 — 접촉 IOC = 고신뢰 악성(FP≈0)."""

    @pytest.mark.asyncio
    async def test_static_hit_is_malicious(self) -> None:
        feed = HoneypotFeedTool(hits={_IP})
        out = {f.indicator: f.verdict for f in await feed.alookup([_IP, "8.8.8.8"])}
        assert out[_IP] == TiVerdict.MALICIOUS
        assert out["8.8.8.8"] == TiVerdict.UNKNOWN  # 미접촉

    @pytest.mark.asyncio
    async def test_provider_merges_hits(self) -> None:
        async def provider() -> set[str]:
            return {_HASH}

        feed = HoneypotFeedTool(hits={_IP}, provider=provider)
        out = {f.indicator: f.verdict for f in await feed.alookup([_IP, _HASH])}
        assert out[_IP] == TiVerdict.MALICIOUS
        assert out[_HASH] == TiVerdict.MALICIOUS  # provider 로 합쳐짐

    @pytest.mark.asyncio
    async def test_provider_failure_degrades_to_static(self) -> None:
        async def failing() -> set[str]:
            raise ThreatIntelError("honeypot store down")

        feed = HoneypotFeedTool(hits={_IP}, provider=failing)
        out = await feed.alookup([_IP])
        assert out[0].verdict == TiVerdict.MALICIOUS  # 정적 집합으로 강등
