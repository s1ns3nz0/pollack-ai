"""SBOM report 노출 테스트 — 정탐 시 공급망 위험이 report 에 실림."""

import pytest

from agents.report_agent import ReportAgent
from core.models import Alert, SbomComponent, Severity, SOCState, Verdict, VulnFinding
from core.sbom import ApprovedSbom, SBOMVerifier
from core.settings import Settings
from core.severity import SeverityEngine


class _StubVuln:
    """CVE → known_exploited 결정론 stub."""

    def __init__(self, exploited: set[str]) -> None:
        self._exploited = exploited

    async def aenrich(self, cves: list[str]) -> list[VulnFinding]:
        return [
            VulnFinding(cve=c, known_exploited=c in self._exploited, source="stub")
            for c in cves
        ]


def _verifier() -> SBOMVerifier:
    return SBOMVerifier(ApprovedSbom.from_yaml())


def _state(verdict: Verdict, components: list[SbomComponent]) -> SOCState:
    return {
        "alert": Alert(
            id="a1",
            scenario_id="S4",
            title="펌웨어 변조",
            severity_baseline=Severity.HIGH,
            signals=["sig"],
            sbom_components=components,
        ),
        "severity": Severity.HIGH,
        "verdict": verdict,
    }


class TestSbomReport:
    @pytest.mark.asyncio
    async def test_tp_exposes_findings(self) -> None:
        """정탐 + 변조 컴포넌트 → report.sbom_findings 노출."""
        agent = ReportAgent(Settings(), SeverityEngine(), sbom=_verifier())
        comps = [
            SbomComponent(name="px4-autopilot", version="1.14.3", hash="sha256:BAD")
        ]

        out = await agent.run(_state(Verdict.TRUE_POSITIVE, comps))

        findings = out["report"].sbom_findings
        assert any(f.issue == "tampered" for f in findings)

    @pytest.mark.asyncio
    async def test_clean_components_no_findings(self) -> None:
        """정상 컴포넌트는 위험 없음."""
        agent = ReportAgent(Settings(), SeverityEngine(), sbom=_verifier())
        comps = [
            SbomComponent(
                name="px4-autopilot",
                version="1.14.3",
                hash="sha256:a1b2c3d4e5f6",
            )
        ]

        out = await agent.run(_state(Verdict.TRUE_POSITIVE, comps))

        assert out["report"].sbom_findings == []

    @pytest.mark.asyncio
    async def test_vuln_threaded_for_cve_check(self) -> None:
        """report_agent 에 주입된 vuln 이 SBOM CVE 검증에 실제로 쓰임(Codex #1)."""
        agent = ReportAgent(
            Settings(),
            SeverityEngine(),
            sbom=_verifier(),
            vuln=_StubVuln({"CVE-2024-1"}),
        )
        comps = [
            SbomComponent(
                name="px4-autopilot",
                version="1.14.3",
                hash="sha256:a1b2c3d4e5f6",
                cves=["CVE-2024-1"],
            )
        ]

        out = await agent.run(_state(Verdict.TRUE_POSITIVE, comps))

        assert any(
            f.issue == "vulnerable" and f.cve == "CVE-2024-1"
            for f in out["report"].sbom_findings
        )

    @pytest.mark.asyncio
    async def test_no_verifier_empty(self) -> None:
        """verifier 미주입 시 빈 리스트(하위호환)."""
        agent = ReportAgent(Settings(), SeverityEngine())
        comps = [SbomComponent(name="rogue")]

        out = await agent.run(_state(Verdict.TRUE_POSITIVE, comps))

        assert out["report"].sbom_findings == []
