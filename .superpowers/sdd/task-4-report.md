# Task 4 Report

## Status

- Outcome: DONE
- Scope honored: touched only the Task 4 UI files and this report file.

## Summary

Replaced the placeholder dashboard shell with the required static layout, added
dark command-center CSS, and added a vanilla JavaScript replay/live renderer
for snapshots, navigator cells, BLUF content, topology nodes, and replay
controls.

## Files Changed

- `app/dashboard_static/index.html`
- `app/dashboard_static/dashboard.css`
- `app/dashboard_static/dashboard.js`
- `tests/__tests__/test_dashboard_static.py`
- `.superpowers/sdd/task-4-report.md`

## TDD Evidence

### RED

Command:

```bash
pytest tests/__tests__/test_dashboard_static.py -v
```

Observed failure:

```text
FAILED tests/__tests__/test_dashboard_static.py::test_dashboard_html_references_static_assets
FAILED tests/__tests__/test_dashboard_static.py::test_dashboard_css_is_dark_and_not_single_hue
FAILED tests/__tests__/test_dashboard_static.py::test_dashboard_js_handles_replay_and_sse
```

Reasons:
- `index.html` did not reference `dashboard.css` or `dashboard.js`
- `app/dashboard_static/dashboard.css` did not exist
- `app/dashboard_static/dashboard.js` did not exist

### GREEN

Command:

```bash
pytest tests/__tests__/test_dashboard_static.py tests/__tests__/test_dashboard_app.py -v
```

Observed result:

```text
============================== 8 passed in 0.21s ===============================
```

## Verification Notes

- HTML now exposes all required region ids:
  `top-strip`, `story-rail`, `navigator`, `bluf-card`, `topology-map`,
  `replay-controls`
- CSS uses the required dark multi-color palette tokens:
  `#08111f`, `#26d9a8`, `#f2c94c`, `#ef476f`
- JavaScript includes replay loading from `/api/snapshots` and SSE connection to
  `/events`
- The layout keeps stable panel dimensions with dense grid-based sections and a
  mobile fallback at `max-width: 900px`

## Commit

- Planned commit message: `feat: add dashboard static UI`

## Review Fixes

- Replaced string-based renderers in `dashboard.js` with DOM node creation using
  `document.createElement(...)`, `textContent`, `replaceChildren()`, and
  `addEventListener(...)`.
- Removed inline `onclick` handlers from replay controls and story selection.
- Added `state.eventSource` tracking with duplicate-live guard and explicit
  close/reset behavior on stream error.
- Added `loadTopology()` with `fetch('/api/topology')` and snapshot topology
  fallback when snapshot nodes are absent.
- Updated story selection reconciliation so a missing selected story resets to
  `snapshot.selected_story_id`.
- Updated replay footer styling to wrap on narrow screens.

## Review Fix Verification

Command:

```bash
pytest tests/__tests__/test_dashboard_static.py tests/__tests__/test_dashboard_app.py -v
```

Observed result:

```text
============================== 8 passed in 0.23s ===============================
```
