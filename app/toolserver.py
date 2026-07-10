"""UAV SOC ops MCP toolserver — hotpath LangGraph 표면을 coarse 툴로 노출.

kagent 오케스트레이터가 SSE 로 이 서버를 호출한다. 단일 coarse 툴
``analyze_alert`` 는 alert 를 hotpath Deployment 에 HTTP POST 하고 verdict 를
그대로 반환한다(신규 판정 미생성 — 전달만).
"""

from __future__ import annotations

import os

import httpx
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from core.exceptions import ToolServerError
from utils.logging import get_logger

_logger = get_logger("toolserver")

_HOTPATH_URL = os.environ.get(
    "HOTPATH_URL",
    "http://soc-hotpath.dah-soc.svc.cluster.local:80/alert",
)
_HOST = os.environ.get("MCP_HOST", "0.0.0.0")  # noqa: S104 — 컨테이너 내부
_PORT = int(os.environ.get("MCP_PORT", "8080"))

mcp = FastMCP("uav-soc-ops", host=_HOST, port=_PORT)


@mcp.tool()
async def analyze_alert(alert: dict[str, object]) -> dict[str, object]:
    """UAV SOC alert 를 hotpath 그래프에 제출하고 판정을 반환한다.

    Args:
        alert: SOC alert JSON(alert_id, 원 이벤트 필드 포함).

    Returns:
        hotpath 가 반환한 verdict/severity JSON(가공 없음).

    Raises:
        ToolServerError: hotpath 연결/HTTP 오류 시.
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(_HOTPATH_URL, json=alert)
            resp.raise_for_status()
            verdict: dict[str, object] = resp.json()
            return verdict
    except httpx.HTTPStatusError as exc:
        raise ToolServerError(f"hotpath HTTP 오류 {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        raise ToolServerError(f"hotpath 연결 실패: {exc}") from exc


async def _healthz(_request: Request) -> PlainTextResponse:
    """Liveness/readiness probe."""
    return PlainTextResponse("ok")


def build_app() -> Starlette:
    """SSE MCP 앱에 /healthz 를 추가한 Starlette 앱을 반환한다.

    Returns:
        `/sse`(MCP) + `/healthz`(프로브) 라우트를 가진 Starlette 앱.
    """
    app = mcp.sse_app()
    app.router.routes.append(Route("/healthz", _healthz))
    return app


def main() -> None:
    """toolserver 를 uvicorn 으로 실행(SSE + healthz)."""
    import uvicorn

    _logger.info("toolserver listening host=%s port=%d", _HOST, _PORT)
    uvicorn.run(build_app(), host=_HOST, port=_PORT)


if __name__ == "__main__":
    main()
