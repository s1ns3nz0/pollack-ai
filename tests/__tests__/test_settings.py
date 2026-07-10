"""Settings 확장 필드 검증."""

from core.settings import Settings


def _settings(**overrides: object) -> Settings:
    return Settings(**overrides)  # type: ignore[arg-type]


def test_dashboard_root_path_defaults_to_dashboard() -> None:
    """대시보드 root_path 기본값은 /dashboard 다."""
    assert _settings().dashboard_root_path == "/dashboard"


def test_azure_openai_fields_default_empty() -> None:
    """kagent 전용 Azure OpenAI 필드는 기본값을 가진다."""
    settings = _settings()
    assert settings.azure_openai_endpoint == ""
    assert settings.azure_openai_deployment == "gpt-4o-soc"
