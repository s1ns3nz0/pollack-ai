"""Dashboard FastAPI app tests."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.dashboard import create_app


def _snapshot() -> dict[str, object]:
    """Build a minimal valid dashboard snapshot payload for tests.

    Returns:
        Minimal snapshot payload in dashboard wire format.
    """
    return {
        "schema_version": "dashboard.snapshot.v1",
        "step": 1,
        "mode": "replay",
        "generated_at": "2026-07-10T00:00:00Z",
        "summary": {
            "active_story_count": 1,
            "max_mission_impact": "MINIMAL",
            "hitl_pending_count": 1,
            "decision_advantage": "margin",
        },
        "stories": [],
        "selected_story_id": "RED-01",
        "navigator": [],
        "topology": {"nodes": [], "edges": []},
        "bluf": {},
        "source": {"alert_id": "a1", "scenario_id": "S1", "trace": []},
    }


def test_root_serves_dashboard_html(tmp_path: Path) -> None:
    """Root endpoint returns the dashboard shell."""
    client = TestClient(create_app(tmp_path))

    response = client.get("/")

    assert response.status_code == 200
    assert "UAV AI SOC" in response.text


def test_snapshots_endpoint_loads_replay_files(tmp_path: Path) -> None:
    """Snapshot endpoint returns replay JSON sorted by filename."""
    (tmp_path / "001.json").write_text(json.dumps(_snapshot()), encoding="utf-8")
    client = TestClient(create_app(tmp_path))

    response = client.get("/api/snapshots")

    assert response.status_code == 200
    payload = response.json()
    assert payload["snapshots"][0]["step"] == 1


def test_snapshots_endpoint_degrades_when_empty(tmp_path: Path) -> None:
    """Empty replay directory returns an explicit empty list."""
    client = TestClient(create_app(tmp_path))

    response = client.get("/api/snapshots")

    assert response.status_code == 200
    assert response.json() == {"snapshots": []}


def test_topology_endpoint_returns_nodes(tmp_path: Path) -> None:
    """Topology endpoint exposes static topology view model."""
    client = TestClient(create_app(tmp_path))

    response = client.get("/api/topology")

    assert response.status_code == 200
    node_ids = {node["id"] for node in response.json()["nodes"]}
    assert "av-muav" in node_ids


def test_events_stream_uses_snapshot_wire_format(tmp_path: Path) -> None:
    """SSE endpoint streams replay snapshots as dashboard snapshot events."""
    (tmp_path / "001.json").write_text(json.dumps(_snapshot()), encoding="utf-8")
    client = TestClient(create_app(tmp_path))

    with client.stream("GET", "/events") as response:
        body = response.read().decode("utf-8")

    assert response.status_code == 200
    assert "event: snapshot" in body
    assert "dashboard.snapshot.v1" in body
    assert 'event: done\ndata: {"status":"complete"}' in body
