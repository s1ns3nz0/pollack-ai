# Final SSE replay duplication fix report

## Summary

- Added an explicit terminal SSE event from `/events` after replay snapshots:
  `event: done` with `{"status":"complete"}`.
- Updated `dashboard.js` to listen for the `done` event, close the
  `EventSource` intentionally, set `live` false, and surface a completed
  connection state.
- Added client-side snapshot dedupe keyed from stable snapshot fields:
  `schema_version`, `step`, `source.alert_id`, `source.scenario_id`, and
  `generated_at`.
- Added regression coverage for both the server terminal event and the client
  terminal/dedupe behavior.

## Root cause

- `/events` is a finite replay stream over snapshot files.
- Browser `EventSource` reconnects after normal EOF unless the client closes it.
- The dashboard appended each replayed `snapshot` event without dedupe.
- Reconnects therefore duplicated snapshots and inflated the visible step count.

## Files changed

- `app/dashboard.py`
- `app/dashboard_static/dashboard.js`
- `tests/__tests__/test_dashboard_app.py`
- `tests/__tests__/test_dashboard_static.py`

## Verification

- Targeted regression tests:
  `pytest tests/__tests__/test_dashboard_app.py tests/__tests__/test_dashboard_static.py -v`
  -> 10 passed
- Formatter:
  `black .`
  -> 265 files left unchanged
- Lint:
  `ruff check .`
  -> passed
- Type check:
  `mypy .`
  -> no issues in 265 source files
- Full test suite:
  `pytest`
  -> 1364 passed in 29.04s

## Notes

- Error-path reconnect behavior remains intact. Only the normal replay-complete
  path now shuts down the `EventSource`.
- Replay payload duplicates are now harmless even if the browser reconnects or a
  snapshot appears in both preload and SSE replay paths.
