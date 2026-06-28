"""취약점 배선 — Investigation 의 CVE 보강 + KEV 악용 부스트 검증."""

import pytest

from agents.investigation_agent import InvestigationAgent
from core.exceptions import VulnLookupError
from core.models import Alert, Severity, Verdict, VulnFinding
from core.settings import Settings
from tools.vuln_tool import StubVuln

_CVE = "CVE-2024-1234"


def _settings() -> Settings:
    return Settings()


def _alert(cves: list[str] | None = None) -> Alert:
    return Alert.model_validate(
        {
            "id": "A",
            "scenario_id": "UAV-FW-TAMPER-004",
            "title": "펌웨어 변조 의심",
            "asset_tier": "T1-Critical",
            "mission_phase": "on-station",
            "severity_baseline": Severity.HIGH,
            "signals": ["펌웨어 해시 변경"],
            "cves": cves or [],
            "expected_detection": {"sigma_rule": "fw_tamper.yml"},
            "ground_truth": Verdict.TRUE_POSITIVE,
        }
    )


class _FailVuln:
    async def aenrich(self, cves: list[str]) -> list[VulnFinding]:
        raise VulnLookupError("vuln source down")


class TestVulnWiring:
    @pytest.mark.asyncio
    async def test_kev_exploited_boosts(self) -> None:
        """KEV 악용 CVE → vuln_findings 채워지고 confidence 상승."""
        vuln = StubVuln(exploited=frozenset({_CVE}), scores={_CVE: 9.8})
        agent = InvestigationAgent(_settings(), None, vuln=vuln)
        out = await agent.run({"alert": _alert(cves=[_CVE])})
        inv = out["investigation"]
        assert len(inv.vuln_findings) == 1
        assert inv.vuln_findings[0].known_exploited is True
        assert inv.confidence >= 0.5  # 0.3 기준 + 0.2(KEV)

    @pytest.mark.asyncio
    async def test_non_exploited_no_boost(self) -> None:
        """KEV 미등재 CVE 는 부스트 없음(보강만)."""
        vuln = StubVuln(exploited=frozenset(), scores={_CVE: 5.0})
        agent = InvestigationAgent(_settings(), None, vuln=vuln)
        out = await agent.run({"alert": _alert(cves=[_CVE])})
        inv = out["investigation"]
        assert inv.vuln_findings[0].known_exploited is False
        assert inv.confidence < 0.5

    @pytest.mark.asyncio
    async def test_no_cves_no_enrich(self) -> None:
        """CVE 없으면 보강 생략."""
        agent = InvestigationAgent(
            _settings(), None, vuln=StubVuln(exploited=frozenset({_CVE}))
        )
        out = await agent.run({"alert": _alert(cves=[])})
        assert out["investigation"].vuln_findings == []

    @pytest.mark.asyncio
    async def test_vuln_failure_degrades_gracefully(self) -> None:
        """취약점 소스 장애 시 빈 결과로 강등(핫패스 계속)."""
        agent = InvestigationAgent(_settings(), None, vuln=_FailVuln())
        out = await agent.run({"alert": _alert(cves=[_CVE])})
        assert out["investigation"].vuln_findings == []
