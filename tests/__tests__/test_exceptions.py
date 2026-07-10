"""커스텀 예외 계층 검증."""

from core.exceptions import SOCPlatformError, ToolServerError


def test_toolserver_error_is_platform_error() -> None:
    """ToolServerError 는 SOCPlatformError 하위다."""
    assert issubclass(ToolServerError, SOCPlatformError)
