"""main() config 자동 배선 — 팩토리 함수 opt-in 검증."""

from __future__ import annotations

from typing import cast

from pydantic import SecretStr
import pytest

import app.learning as learning
from app.learning import (
    _build_auto_kql,
    _build_publisher,
    _build_threat_landscape,
)
from core.llm import LLMClient
from core.settings import Settings
from tools.rule_publisher import RulePublisher


class TestPublisherFactory:
    def test_no_token_returns_none(self) -> None:
        settings = Settings(github_token=SecretStr(""))
        assert _build_publisher(settings) is None

    def test_with_token_returns_publisher(self) -> None:
        settings = Settings(github_token=SecretStr("ghp_xxx"))
        pub = _build_publisher(settings)
        assert pub is not None


class TestThreatLandscapeFactory:
    def test_default_urls_wire_all_feeds(self) -> None:
        # 디폴트 settings 에 attack/atlas/kev URL 모두 존재
        agent = _build_threat_landscape(Settings())
        assert agent is not None

    def test_no_feed_urls_returns_none(self) -> None:
        settings = Settings(attack_feed_url="", atlas_feed_url="", kev_feed_url="")
        assert _build_threat_landscape(settings) is None


class TestAutoKqlFactory:
    def test_default_settings_returns_none(self) -> None:
        assert _build_auto_kql(Settings()) is None

    def test_enabled_without_publisher_returns_none(self) -> None:
        settings = Settings(auto_kql_enabled=True, github_token=SecretStr(""))

        result = _build_auto_kql(settings)
        assert result is None

    def test_enabled_flag_wires_agent_when_dependencies_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(auto_kql_enabled=True)

        class _FakeLlm:
            async def acomplete(self, system: str, user: str) -> str:
                return "```kql\nSecurityEvent | take 1\n```"

        class _FakePublisher:
            pass

        monkeypatch.setattr(
            "core.llm.get_llm_client",
            lambda _settings: cast(LLMClient, _FakeLlm()),
        )
        monkeypatch.setattr(
            learning,
            "_build_publisher",
            lambda _settings: cast(RulePublisher, _FakePublisher()),
        )

        result = _build_auto_kql(settings)

        assert result is not None
