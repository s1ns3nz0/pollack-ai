"""FastAPI dashboard server for replay and SSE snapshot delivery."""

from __future__ import annotations

from collections.abc import Iterator
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
import uvicorn

from core.dashboard import DashboardSnapshot, TopologyPolicy
from core.settings import get_settings
from utils.logging import get_logger

_logger = get_logger("dashboard")
_STATIC_DIR = Path(__file__).resolve().parent / "dashboard_static"


def load_snapshots(snapshot_dir: Path) -> list[DashboardSnapshot]:
    """Load replay snapshots from a directory.

    Args:
        snapshot_dir: Directory containing dashboard snapshot JSON files.

    Returns:
        Valid snapshots sorted by filename. Invalid files are skipped and logged.
    """
    if not snapshot_dir.exists():
        return []

    snapshots: list[DashboardSnapshot] = []
    for path in sorted(snapshot_dir.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            snapshots.append(DashboardSnapshot.model_validate(raw))
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            _logger.warning("dashboard snapshot skipped path=%s error=%s", path, exc)
    return snapshots


def _sse_events(snapshot_dir: Path) -> Iterator[str]:
    """Yield replay snapshots as SSE events.

    Args:
        snapshot_dir: Replay snapshot directory.

    Yields:
        Server-sent event payloads carrying dashboard snapshots.
    """
    for snapshot in load_snapshots(snapshot_dir):
        data = snapshot.model_dump_json()
        yield f"event: snapshot\ndata: {data}\n\n"
    yield 'event: done\ndata: {"status":"complete"}\n\n'


def create_app(snapshot_dir: str | Path | None = None) -> FastAPI:
    """Create the dashboard FastAPI app.

    Args:
        snapshot_dir: Optional replay snapshot directory.

    Returns:
        Configured FastAPI application.
    """
    replay_dir = (
        Path(snapshot_dir) if snapshot_dir is not None else Path("demo_snapshots")
    )
    app = FastAPI(title="UAV AI SOC Defense Dashboard")
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="dashboard_static")

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        """Return the dashboard HTML shell.

        Returns:
            HTML response for the dashboard entrypoint.
        """
        html = (_STATIC_DIR / "index.html").read_text(encoding="utf-8")
        return HTMLResponse(html)

    @app.get("/api/snapshots")
    async def snapshots() -> dict[str, list[dict[str, object]]]:
        """Return replay snapshots.

        Returns:
            Serialized replay snapshots keyed by ``snapshots``.
        """
        return {
            "snapshots": [
                snapshot.model_dump(mode="json")
                for snapshot in load_snapshots(replay_dir)
            ]
        }

    @app.get("/api/topology")
    async def topology() -> dict[str, object]:
        """Return the static topology view model.

        Returns:
            Serialized topology nodes and edges.
        """
        return TopologyPolicy.from_yaml().to_view_model().model_dump(mode="json")

    @app.get("/events")
    async def events() -> StreamingResponse:
        """Stream replay snapshots as server-sent events.

        Returns:
            Streaming SSE response carrying replay snapshots.
        """
        return StreamingResponse(
            _sse_events(replay_dir),
            media_type="text/event-stream",
        )

    return app


app = create_app()


def main() -> None:
    """Run the dashboard server using Settings-driven host/port.

    `dashboard_public_url` 이 설정되면 외부(Azure 도메인) 접속을 위해 모든
    인터페이스에 바인드하고, 비어 있으면 로컬 전용(127.0.0.1)으로만 연다.
    """
    settings = get_settings()
    public_url = settings.dashboard_public_url.strip().rstrip("/")
    host = settings.dashboard_host
    if public_url and host == "127.0.0.1":
        host = "0.0.0.0"  # noqa: S104 — 공개 도메인 opt-in 시에만 외부 바인드

    _logger.info(
        "dashboard listening: http://127.0.0.1:%d (host=%s)",
        settings.dashboard_port,
        host,
    )
    if public_url:
        _logger.info("dashboard public url: %s", public_url)
    else:
        _logger.info("dashboard public url unset — local access only")

    uvicorn.run(app, host=host, port=settings.dashboard_port)


if __name__ == "__main__":
    main()
