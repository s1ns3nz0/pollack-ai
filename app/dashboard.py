"""FastAPI dashboard server for replay and SSE snapshot delivery."""

from __future__ import annotations

from collections.abc import Iterator
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from core.dashboard import DashboardSnapshot, TopologyPolicy
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
