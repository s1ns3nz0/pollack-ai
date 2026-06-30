"""취약점 어댑터 — StubVuln / CisaKevTool / NvdTool / CompositeVuln 검증."""

import httpx
from pydantic import SecretStr
import pytest

from core.exceptions import VulnLookupError
from core.models import VulnFinding
from core.settings import Settings
from tools.vuln_tool import CisaKevTool, CompositeVuln, NvdTool, StubVuln

_CVE = "CVE-2024-1234"


def _client_factory(handler: object) -> object:
    def make() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]

    return make


def _nvd_body(score: float, severity: str) -> dict[str, object]:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": score, "baseSeverity": severity}}
                        ]
                    }
                }
            }
        ]
    }


class TestStubVuln:
    @pytest.mark.asyncio
    async def test_exploited_and_score(self) -> None:
        sv = StubVuln(exploited=frozenset({_CVE}), scores={_CVE: 9.8})
        out = await sv.aenrich([_CVE, "CVE-2000-0"])
        by = {f.cve: f for f in out}
        assert by[_CVE].known_exploited is True
        assert by[_CVE].cvss_score == 9.8
        assert by[_CVE].severity == "CRITICAL"
        assert by["CVE-2000-0"].known_exploited is False


class TestCisaKev:
    @pytest.mark.asyncio
    async def test_known_exploited(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"vulnerabilities": [{"cveID": _CVE}]})

        kev = CisaKevTool(client_factory=_client_factory(handler))
        out = {
            f.cve: f.known_exploited for f in await kev.aenrich([_CVE, "CVE-2000-0"])
        }
        assert out[_CVE] is True
        assert out["CVE-2000-0"] is False

    @pytest.mark.asyncio
    async def test_fetch_failure_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        kev = CisaKevTool(client_factory=_client_factory(handler))
        with pytest.raises(VulnLookupError):
            await kev.aenrich([_CVE])


class TestNvd:
    def test_parse_v31(self) -> None:
        f = NvdTool.parse(_CVE, _nvd_body(7.5, "HIGH"))
        assert f.cvss_score == 7.5
        assert f.severity == "HIGH"

    def test_parse_malformed(self) -> None:
        assert NvdTool.parse(_CVE, {"x": 1}).cvss_score == 0.0

    @pytest.mark.asyncio
    async def test_lookup(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_nvd_body(9.8, "CRITICAL"))

        nvd = NvdTool(
            settings=Settings(nvd_api_key=SecretStr("k")),
            client_factory=_client_factory(handler),
        )
        out = await nvd.aenrich([_CVE])
        assert out[0].severity == "CRITICAL"


class _KevStub:
    async def aenrich(self, cves: list[str]) -> list[VulnFinding]:
        return [
            VulnFinding(cve=c, known_exploited=True, source="cisa-kev") for c in cves
        ]


class _NvdStub:
    async def aenrich(self, cves: list[str]) -> list[VulnFinding]:
        return [
            VulnFinding(cve=c, cvss_score=9.8, severity="CRITICAL", source="nvd")
            for c in cves
        ]


class _FailSource:
    async def aenrich(self, cves: list[str]) -> list[VulnFinding]:
        raise VulnLookupError("source down")


class TestCompositeVuln:
    @pytest.mark.asyncio
    async def test_merge_exploited_and_cvss(self) -> None:
        out = await CompositeVuln([_KevStub(), _NvdStub()]).aenrich([_CVE])
        assert len(out) == 1
        f = out[0]
        assert f.known_exploited is True
        assert f.cvss_score == 9.8
        assert f.severity == "CRITICAL"
        assert f.source == "cisa-kev,nvd"

    @pytest.mark.asyncio
    async def test_failing_source_skipped(self) -> None:
        out = await CompositeVuln([_FailSource(), _NvdStub()]).aenrich([_CVE])
        assert len(out) == 1
        assert out[0].cvss_score == 9.8

    @pytest.mark.asyncio
    async def test_empty(self) -> None:
        assert await CompositeVuln([]).aenrich([_CVE]) == []
        assert await CompositeVuln([_NvdStub()]).aenrich([]) == []
