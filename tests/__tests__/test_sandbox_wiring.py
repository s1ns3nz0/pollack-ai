"""샌드박스 배선 — Investigation 디토네이션 부스트 + 추출 IOC TI 되먹임 검증."""

import pytest

from agents.investigation_agent import InvestigationAgent
from core.exceptions import SandboxError
from core.models import Alert, SandboxReport, Severity, TiVerdict, Verdict
from core.settings import Settings
from tools.sandbox_tool import StubSandbox
from tools.ti_tool import StubThreatIntel

_HASH = "b" * 64
_C2_IP = "45.146.165.37"


def _settings() -> Settings:
    return Settings()


def _alert(iocs: list[str] | None = None) -> Alert:
    return Alert.model_validate(
        {
            "id": "A",
            "scenario_id": "UAV-FW-TAMPER-004",
            "title": "펌웨어 변조 의심",
            "asset_tier": "T1-Critical",
            "mission_phase": "on-station",
            "severity_baseline": Severity.HIGH,
            "signals": ["펌웨어 해시 변경"],
            "iocs": iocs or [],
            "expected_detection": {"sigma_rule": "fw_tamper.yml"},
            "ground_truth": Verdict.TRUE_POSITIVE,
        }
    )


class _FailSandbox:
    async def adetonate(self, artifact: str) -> SandboxReport:
        raise SandboxError("sandbox down")


class TestSandboxWiring:
    """Investigation 의 샌드박스 디토네이션 + TI 되먹임."""

    @pytest.mark.asyncio
    async def test_malicious_detonation_boosts_and_feeds_ti(self) -> None:
        """악성 해시 디토네이션 → 추출 C2 IP 가 TI 로 되먹여져 악성 판정 + 부스트."""
        sandbox = StubSandbox(malicious=frozenset({_HASH}), extracted_iocs=[_C2_IP])
        ti = StubThreatIntel(malicious=frozenset({_C2_IP}))
        agent = InvestigationAgent(_settings(), None, ti=ti, sandbox=sandbox)
        out = await agent.run({"alert": _alert(iocs=[_HASH])})
        inv = out["investigation"]
        assert len(inv.sandbox_reports) == 1
        assert inv.sandbox_reports[0].verdict == TiVerdict.MALICIOUS
        # 추출된 C2 IP 가 TI 조회에 포함돼 악성으로 잡힘(시너지)
        ti_map = {f.indicator: f.verdict for f in inv.ti_findings}
        assert ti_map.get(_C2_IP) == TiVerdict.MALICIOUS
        assert inv.confidence >= 0.7  # 0.3 기준 + 0.2(샌드박스) + 0.2(TI)

    @pytest.mark.asyncio
    async def test_non_hash_ioc_not_detonated(self) -> None:
        """해시가 아닌 IOC(IP)는 디토네이트하지 않음."""
        sandbox = StubSandbox(malicious=frozenset({_HASH}))
        agent = InvestigationAgent(_settings(), None, sandbox=sandbox)
        out = await agent.run({"alert": _alert(iocs=["8.8.8.8"])})
        assert out["investigation"].sandbox_reports == []

    @pytest.mark.asyncio
    async def test_no_sandbox_injected(self) -> None:
        """샌드박스 미주입이면 보고서 없음(기존 동작 불변)."""
        agent = InvestigationAgent(_settings(), None)
        out = await agent.run({"alert": _alert(iocs=[_HASH])})
        assert out["investigation"].sandbox_reports == []

    @pytest.mark.asyncio
    async def test_sandbox_failure_degrades_gracefully(self) -> None:
        """샌드박스 장애 시 빈 결과로 강등(핫패스 계속 — 크래시 없음)."""
        agent = InvestigationAgent(_settings(), None, sandbox=_FailSandbox())
        out = await agent.run({"alert": _alert(iocs=[_HASH])})
        assert out["investigation"].sandbox_reports == []
