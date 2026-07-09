"""Dashboard static asset smoke tests."""

from pathlib import Path

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


def test_dashboard_css_is_dark_and_not_single_hue() -> None:
    """CSS defines a dark multi-color command center theme."""
    css = (_STATIC / "dashboard.css").read_text(encoding="utf-8")

    assert "#08111f" in css
    assert "#26d9a8" in css
    assert "#f2c94c" in css
    assert "#ef476f" in css


def test_dashboard_js_handles_replay_and_sse() -> None:
    """JavaScript includes replay and live stream adapters."""
    js = (_STATIC / "dashboard.js").read_text(encoding="utf-8")

    assert "fetch('/api/snapshots')" in js
    assert "fetch('/api/topology')" in js
    assert "new EventSource('/events')" in js
    assert "renderSnapshot" in js
    assert "selectStory" in js
    assert "state.eventSource" in js
    assert "state.eventSource.close()" in js
    assert "state.eventSource = null" in js
    assert ".addEventListener(" in js
    assert "innerHTML" not in js
    assert "onclick=" not in js
