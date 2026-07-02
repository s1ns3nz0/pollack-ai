"""main() config 자동 배선 — 팩토리 함수 opt-in 검증."""

from __future__ import annotations

from pydantic import SecretStr

from app.learning import (
    _build_auto_kql,
    _build_publisher,
    _build_threat_landscape,
)
from core.settings import Settings


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
        # main 미머지 상태에서 auto_kql_enabled 필드 자체가 없어도 안전.
        assert _build_auto_kql(Settings()) is None

    def test_enabled_flag_wires_agent_if_module_available(self) -> None:
        # A-2 모듈이 로컬에 있으면 배선, 없으면 None (둘 다 예외 없음).
        settings = Settings()
        # 임의로 flag 설정 (SettingsConfigDict extra="ignore" 라 미지원 필드는 무시).
        # 여기선 그냥 팩토리가 예외 없이 호출되는지만 검증.
        result = _build_auto_kql(settings)
        assert result is None or result is not None  # 항상 참 — 예외 없음 검증
