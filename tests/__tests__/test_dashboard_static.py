"""Dashboard static asset smoke tests."""

from pathlib import Path
import re

_STATIC = Path("app/dashboard_static")


def test_dashboard_html_references_static_assets() -> None:
    """HTML shell loads dashboard CSS and JavaScript."""
    html = (_STATIC / "index.html").read_text(encoding="utf-8")

    assert "dashboard.css" in html
    assert "dashboard.js" in html
    assert 'id="story-rail"' in html
    assert 'id="navigator"' in html
    assert 'id="bluf-card"' in html
    assert 'id="topology-map"' in html
    assert "사이버 작전 참모 상황판" in html


def test_dashboard_css_is_dark_and_not_single_hue() -> None:
    """CSS defines a dark multi-color command center theme."""
    css = (_STATIC / "dashboard.css").read_text(encoding="utf-8")

    assert "#070a10" in css
    assert "#28d7c4" in css
    assert "#f6c945" in css
    assert "#ff5870" in css
    assert "#69a8ff" in css
    assert "--ax-surface" in css


def test_dashboard_js_handles_replay_and_sse() -> None:
    """JavaScript includes replay and live stream adapters."""
    js = (_STATIC / "dashboard.js").read_text(encoding="utf-8")

    assert "fetch('api/snapshots')" in js
    assert "fetch('api/topology')" in js
    assert "new EventSource('events')" in js
    assert "renderSnapshot" in js
    assert "selectStory" in js
    assert "state.eventSource" in js
    assert "state.eventSource.close()" in js
    assert "state.eventSource = null" in js
    assert ".addEventListener(" in js
    assert "전술 열 전체 표시" in js
    assert "진행 중/관측됨" in js
    assert "예상 다음 수순" in js
    assert "시뮬레이션/미연동" in js
    assert "방어 공백/미구현" in js
    assert "innerHTML" not in js
    assert "onclick=" not in js


def test_dashboard_js_closes_sse_on_done_and_dedupes_snapshots() -> None:
    """JavaScript handles terminal SSE completion and duplicate snapshots."""
    js = (_STATIC / "dashboard.js").read_text(encoding="utf-8")

    assert 'addEventListener("done"' in js or "addEventListener('done'" in js
    assert "state.eventSource.close()" in js
    assert "seenSnapshotKeys" in js or "snapshotKeys" in js
    assert "schema_version" in js
    assert "source.alert_id" in js or "alert_id" in js
    assert "source.scenario_id" in js or "scenario_id" in js
    assert "generated_at" in js


def test_dashboard_js_keeps_topology_and_reconnects_in_empty_or_error_states() -> None:
    """JavaScript preserves topology on empty replay and avoids closing SSE on error."""
    js = (_STATIC / "dashboard.js").read_text(encoding="utf-8")

    assert "리플레이 스냅샷 없음" in js
    assert "renderTopology(snapshot);" in js
    assert "state.topology" in js
    assert "if (state.snapshots.length === 0) {" in js
    assert "실시간 재연결 중" in js
    assert "topologyFromSnapshot" in js
    assert "주요 연결 관계" in js

    onerror_match = re.search(
        r"state\.eventSource\.onerror\s*=\s*\(\)\s*=>\s*\{(?P<body>.*?)\n\s*\};",
        js,
        re.DOTALL,
    )
    assert onerror_match is not None
    onerror_body = onerror_match.group("body")
    assert "closeLiveConnection()" not in onerror_body
    assert ".close()" not in onerror_body


def test_dashboard_js_labels_replay_data_even_when_sse_connected() -> None:
    """Live SSE that serves replay-mode snapshots must not claim 실시간 data."""
    js = (_STATIC / "dashboard.js").read_text(encoding="utf-8")

    assert "snapshot.mode" in js
    assert "리플레이 수신 중(SSE)" in js
    assert "리플레이 데이터" in js
    assert "mode-badge" in js


def test_dashboard_css_styles_data_mode_badge() -> None:
    """Data-mode badge has a distinct visual treatment."""
    css = (_STATIC / "dashboard.css").read_text(encoding="utf-8")

    assert ".mode-badge" in css


def test_dashboard_css_marks_stub_nodes_distinctly() -> None:
    """Stub topology nodes have a distinct visual treatment."""
    css = (_STATIC / "dashboard.css").read_text(encoding="utf-8")

    assert ".node.STUB" in css
