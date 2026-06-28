"""TI 어댑터 — CompositeThreatIntel 병합/graceful + VirusTotalTool 분류/파싱/조회."""

import httpx
from pydantic import SecretStr
import pytest

from core.exceptions import ThreatIntelError
from core.models import ThreatIntelFinding, TiVerdict
from core.settings import Settings
from tools.ti_tool import CompositeThreatIntel, VirusTotalTool

_HASH = "a" * 64


def _finding(indicator: str, verdict: TiVerdict, source: str) -> ThreatIntelFinding:
    return ThreatIntelFinding(indicator=indicator, verdict=verdict, source=source)


class _Source:
    """고정 결과를 반환하거나 실패하는 TI 소스 스텁."""

    def __init__(
        self, findings: list[ThreatIntelFinding], *, fail: bool = False
    ) -> None:
        self._findings = findings
        self._fail = fail

    async def alookup(self, indicators: list[str]) -> list[ThreatIntelFinding]:
        if self._fail:
            raise ThreatIntelError("source down")
        return self._findings


class TestComposite:
    """다소스 병합 — 지표별 최악 판정 + 출처 합침 + graceful."""

    @pytest.mark.asyncio
    async def test_worst_verdict_wins_and_sources_merged(self) -> None:
        """같은 IOC: SUSPICIOUS(a) + MALICIOUS(b) → MALICIOUS, source 'a,b'."""
        src_a = _Source([_finding("x", TiVerdict.SUSPICIOUS, "a")])
        src_b = _Source([_finding("x", TiVerdict.MALICIOUS, "b")])
        out = await CompositeThreatIntel([src_a, src_b]).alookup(["x"])
        assert len(out) == 1
        assert out[0].verdict == TiVerdict.MALICIOUS
        assert out[0].source == "a,b"

    @pytest.mark.asyncio
    async def test_failing_source_is_skipped(self) -> None:
        """한 소스가 실패해도 나머지로 계속(가용성)."""
        good = _Source([_finding("x", TiVerdict.MALICIOUS, "good")])
        bad = _Source([], fail=True)
        out = await CompositeThreatIntel([bad, good]).alookup(["x"])
        assert len(out) == 1
        assert out[0].verdict == TiVerdict.MALICIOUS

    @pytest.mark.asyncio
    async def test_empty_inputs(self) -> None:
        """빈 IOC 또는 소스 없음 → 빈 결과."""
        assert await CompositeThreatIntel([]).alookup(["x"]) == []
        src = _Source([_finding("x", TiVerdict.CLEAN, "a")])
        assert await CompositeThreatIntel([src]).alookup([]) == []


class TestVirusTotalClassify:
    """IOC 유형 분류 → VT 엔드포인트."""

    def test_classify(self) -> None:
        assert VirusTotalTool._classify(_HASH) == "files"
        assert VirusTotalTool._classify("8.8.8.8") == "ip_addresses"
        assert VirusTotalTool._classify("evil.example.com") == "domains"
        assert VirusTotalTool._classify("???not-ioc") is None


class TestVirusTotalParse:
    """응답 검증·판정(미검증 외부 입력 가드)."""

    def test_malicious(self) -> None:
        body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3}}}}
        assert VirusTotalTool.parse(_HASH, body).verdict == TiVerdict.MALICIOUS

    def test_suspicious(self) -> None:
        body = {
            "data": {
                "attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 2}}
            }
        }
        assert VirusTotalTool.parse(_HASH, body).verdict == TiVerdict.SUSPICIOUS

    def test_clean(self) -> None:
        body = {"data": {"attributes": {"last_analysis_stats": {"harmless": 70}}}}
        assert VirusTotalTool.parse(_HASH, body).verdict == TiVerdict.CLEAN

    def test_malformed_is_unknown(self) -> None:
        assert VirusTotalTool.parse(_HASH, {"oops": 1}).verdict == TiVerdict.UNKNOWN
        assert VirusTotalTool.parse(_HASH, "not-json").verdict == TiVerdict.UNKNOWN


def _settings_with_key() -> Settings:
    return Settings(virustotal_api_key=SecretStr("test-key"))


def _client_factory(handler: object) -> object:
    def make() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]

    return make


class TestVirusTotalLookup:
    """실 조회 경로 — mock transport 로 네트워크 없이 검증."""

    @pytest.mark.asyncio
    async def test_malicious_response(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}
                },
            )

        vt = VirusTotalTool(
            settings=_settings_with_key(), client_factory=_client_factory(handler)
        )
        out = await vt.alookup([_HASH])
        assert out[0].verdict == TiVerdict.MALICIOUS
        assert out[0].source == "virustotal"

    @pytest.mark.asyncio
    async def test_404_is_unknown(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        vt = VirusTotalTool(
            settings=_settings_with_key(), client_factory=_client_factory(handler)
        )
        out = await vt.alookup(["8.8.8.8"])
        assert out[0].verdict == TiVerdict.UNKNOWN

    @pytest.mark.asyncio
    async def test_missing_key_raises(self) -> None:
        """키 미설정 → ThreatIntelError(컴포지트가 건너뜀)."""
        vt = VirusTotalTool(settings=Settings(virustotal_api_key=SecretStr("")))
        with pytest.raises(ThreatIntelError):
            await vt.alookup([_HASH])
