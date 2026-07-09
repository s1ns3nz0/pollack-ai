"""Dashboard replay snapshot writer tests."""

import json
from pathlib import Path

from core.dashboard import DashboardSnapshot, write_dashboard_snapshot


def test_write_dashboard_snapshot_uses_ordered_filename(tmp_path: Path) -> None:
    """Snapshot writer stores deterministic replay JSON filenames."""
    snapshot = DashboardSnapshot(step=7, generated_at="2026-07-10T00:00:00Z")

    path = write_dashboard_snapshot(snapshot, tmp_path)

    assert path.name == "007-dashboard.snapshot.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "dashboard.snapshot.v1"
    assert payload["step"] == 7
