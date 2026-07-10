"""soc-toolserver analyze_alert 툴 검증(hotpath mock)."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.toolserver import analyze_alert
from core.exceptions import ToolServerError


@pytest.mark.asyncio
async def test_analyze_alert_returns_hotpath_verdict() -> None:
    """hotpath 응답 JSON 을 가공 없이 반환한다."""
    verdict = {"verdict": "malicious", "severity": "high"}
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json = MagicMock(return_value=verdict)

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client

    with patch("app.toolserver.httpx.AsyncClient", return_value=mock_client):
        result = await analyze_alert({"alert_id": "A-1"})

    assert result == verdict
    mock_client.post.assert_awaited_once()


@pytest.mark.asyncio
async def test_analyze_alert_wraps_http_error() -> None:
    """hotpath HTTP 오류는 ToolServerError 로 감싼다."""
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.side_effect = httpx.ConnectError("refused")

    with patch("app.toolserver.httpx.AsyncClient", return_value=mock_client):
        with pytest.raises(ToolServerError):
            await analyze_alert({"alert_id": "A-1"})
