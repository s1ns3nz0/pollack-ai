"""RuleUpdateAgent — Watch List 전용 수정(A/B/C) + PR 발행 검증.

원칙: KQL 불변, Watch List 값만 변경. remediation 힌트 유무/유형별 산출과
발행기 주입·장애 강등을 확인한다.
"""

import pytest

from agents.rule_update_agent import RuleUpdateAgent
from core.exceptions import SOCPlatformError
from core.models import Alert, RulePullRequest, Severity, Verdict
from core.settings import Settings
from tools.rule_publisher import StubRulePublisher


def _settings() -> Settings:
    return Settings()


def _alert(remediation: dict[str, str] | None = None, **overrides: object) -> Alert:
    expected: dict[str, object] = {"sentinel_rule": "S1_GNSS_Spoofing"}
    if remediation is not None:
        expected["remediation"] = remediation
    base: dict[str, object] = {
        "id": "FP-1",
        "scenario_id": "UAV-GNSS-001",
        "title": "GNSS 잔차 급증(정상 RF간섭 구역)",
        "asset_id": "UAV-ANHEUNG-07",
        "asset_tier": "T1-Critical",
        "mission_phase": "on-station",
        "severity_baseline": Severity.HIGH,
        "signals": ["GNSS-INS 잔차 급증"],
        "expected_detection": expected,
        "ground_truth": Verdict.FALSE_POSITIVE,
    }
    base.update(overrides)
    return Alert.model_validate(base)


class TestTypeBException:
    """Type B 예외 허용형 — 정상 구역/기체를 예외 목록에 추가."""

    @pytest.mark.asyncio
    async def test_builds_watchlist_exception_and_pr(self) -> None:
        agent = RuleUpdateAgent(_settings(), StubRulePublisher())
        out = await agent.run(
            {
                "alert": _alert(
                    {
                        "watchlist": "GNSS_Exception_List",
                        "search_key": "ZoneId",
                        "type": "B",
                        "value": "ZONE-ANHEUNG-RF-02",
                    }
                )
            }
        )
        ru = out["rule_update"]
        wl = ru.watchlist_update
        assert wl is not None
        assert wl.watchlist == "GNSS_Exception_List"
        assert wl.update_type == "B"
        assert wl.action == "add"
        assert wl.entry["ZoneId"] == "ZONE-ANHEUNG-RF-02"
        assert wl.entry["source_alert"] == "FP-1"
        pr = ru.pull_request
        assert pr is not None
        assert pr.repo == "s1ns3nz0/dah-sentinel-content"
        assert pr.path == "Watchlists/GNSS_Exception_List.csv"
        assert "GNSS_Exception_List".lower() in pr.branch
        assert ru.pr_status == "proposed"
        assert pr.url  # Stub 가 URL 채움

    @pytest.mark.asyncio
    async def test_falls_back_to_asset_id_when_no_value(self) -> None:
        """명시 value 없으면 asset_id 로 예외 항목 구성."""
        agent = RuleUpdateAgent(_settings())
        out = await agent.run(
            {
                "alert": _alert(
                    {"watchlist": "AOI_Boundary_List", "search_key": "MissionId"}
                )
            }
        )
        wl = out["rule_update"].watchlist_update
        assert wl is not None
        assert wl.entry["MissionId"] == "UAV-ANHEUNG-07"


class TestTypeCThreshold:
    """Type C 임계값형 — KQL 이 읽는 임계값 수치 조정(modify)."""

    @pytest.mark.asyncio
    async def test_builds_threshold_modify(self) -> None:
        agent = RuleUpdateAgent(_settings(), StubRulePublisher())
        out = await agent.run(
            {
                "alert": _alert(
                    {
                        "watchlist": "UAV_Threshold_List",
                        "search_key": "ThresholdKey",
                        "type": "C",
                        "column": "MaxJamIndicator",
                        "threshold": "0.65",
                    }
                )
            }
        )
        wl = out["rule_update"].watchlist_update
        assert wl is not None
        assert wl.action == "modify"
        assert wl.entry["ThresholdKey"] == "MaxJamIndicator"
        assert wl.entry["Value"] == "0.65"


class TestNoRemediation:
    """remediation 힌트 없으면 watchlist 변경 없이 검토 제안만."""

    @pytest.mark.asyncio
    async def test_no_hint_yields_review_only(self) -> None:
        agent = RuleUpdateAgent(_settings(), StubRulePublisher())
        out = await agent.run({"alert": _alert(None)})
        ru = out["rule_update"]
        assert ru.watchlist_update is None
        assert ru.pull_request is None
        assert ru.pr_status == "no_remediation"

    @pytest.mark.asyncio
    async def test_incomplete_hint_ignored(self) -> None:
        """watchlist 만 있고 search_key 없으면 무시(검토 제안)."""
        agent = RuleUpdateAgent(_settings())
        out = await agent.run({"alert": _alert({"watchlist": "X"})})
        assert out["rule_update"].watchlist_update is None


class TestPublisher:
    """발행기 주입/미주입/장애 거동."""

    @pytest.mark.asyncio
    async def test_no_publisher_keeps_proposed(self) -> None:
        agent = RuleUpdateAgent(_settings())
        out = await agent.run(
            {
                "alert": _alert(
                    {"watchlist": "AOI_Boundary_List", "search_key": "MissionId"}
                )
            }
        )
        pr = out["rule_update"].pull_request
        assert pr is not None
        assert pr.status == "proposed"
        assert pr.url == ""  # 발행 안 함

    @pytest.mark.asyncio
    async def test_publish_failure_degrades_to_failed(self) -> None:
        class _FailPublisher:
            async def apublish(self, pr: RulePullRequest) -> RulePullRequest:
                raise SOCPlatformError("github down")

        agent = RuleUpdateAgent(_settings(), _FailPublisher())
        out = await agent.run(
            {
                "alert": _alert(
                    {"watchlist": "AOI_Boundary_List", "search_key": "MissionId"}
                )
            }
        )
        assert out["rule_update"].pr_status == "failed"
