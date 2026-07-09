# Task 2 Report

## Status

- Outcome: DONE
- Scope honored: touched only Task 2 files plus this Task 2 report.

## Summary

Implemented the dashboard snapshot view models and deterministic snapshot
builder surface:

- Added `DashboardSummary`, `DashboardAlertRef`, `DashboardStory`,
  `DashboardNavigatorCell`, `DashboardBluf`, `DashboardSource`, and
  `DashboardSnapshot` to `core/dashboard.py`.
- Added `DashboardMode = Literal["replay", "live"]`.
- Implemented `build_dashboard_snapshot(state, *, step=0, mode="replay",
  topology=None)`.
- Implemented helper functions for report extraction, tactic selection,
  navigator coverage loading, BLUF assembly, and topology overlay.
- Added focused tests covering summary/story output, BLUF language,
  navigator flags, and topology highlighting.

## Files Changed

- `core/dashboard.py`
- `tests/__tests__/test_dashboard_snapshot.py`

## Verification

Command:

```bash
pytest tests/__tests__/test_dashboard_snapshot.py -v
black core/dashboard.py tests/__tests__/test_dashboard_snapshot.py
ruff check core/dashboard.py tests/__tests__/test_dashboard_snapshot.py
mypy core/dashboard.py tests/__tests__/test_dashboard_snapshot.py
```

Results:

- `pytest tests/__tests__/test_dashboard_snapshot.py -v` -> 4 passed
- `black core/dashboard.py tests/__tests__/test_dashboard_snapshot.py` ->
  2 files left unchanged
- `ruff check core/dashboard.py tests/__tests__/test_dashboard_snapshot.py` ->
  passed
- `mypy core/dashboard.py tests/__tests__/test_dashboard_snapshot.py` ->
  passed

## Commit

- Will be created after staging the Task 2 files and this report.

## Review Fixes

- Replaced navigator predicted-tactic inference with authoritative sources
  only: `staged_defenses[].tactic` first, then
  `scenario_tactic_map()[campaign_matches[].next_expected]`. Removed
  `hunt_candidates` and substring heuristics from predicted tactic state.
- Reworked dashboard HITL rendering to prefer authoritative requirement
  signals from `approval`, `report.hitl`, and `response.hitl` in that order:
  `PENDING` / `APPROVED` / `REQUIRED` / `NOT_REQUIRED`.
- Added targeted regressions for:
  - required HITL without approval staying `REQUIRED` with
    `hitl_pending_count == 0`
  - campaign `next_expected` resolving via `scenario_tactic_map`
  - `hunt_candidates` technique IDs not setting navigator predicted state

## Review Fix Verification

Command:

```bash
pytest tests/__tests__/test_dashboard_snapshot.py -v
black core/dashboard.py tests/__tests__/test_dashboard_snapshot.py
ruff check core/dashboard.py tests/__tests__/test_dashboard_snapshot.py
mypy core/dashboard.py tests/__tests__/test_dashboard_snapshot.py
```

Results:

- `pytest tests/__tests__/test_dashboard_snapshot.py -v` -> 7 passed
- `black core/dashboard.py tests/__tests__/test_dashboard_snapshot.py` ->
  2 files left unchanged
- `ruff check core/dashboard.py tests/__tests__/test_dashboard_snapshot.py` ->
  passed
- `mypy core/dashboard.py tests/__tests__/test_dashboard_snapshot.py` ->
  passed

## Follow-up Review Fixes

Fixed the remaining Task 2 review findings:

- `_has_hitl_signal()` now uses exact allowlist parsing, so explicit negative
  values like `NOT_REQUIRED`, `AUTO`, and empty strings no longer force HITL.
- `_next_expected_tactic()` now skips blank staged-defense tactics and falls
  back to campaign `next_expected` mapping when needed.
- Added regressions for:
  - `report.hitl = NOT_REQUIRED` and `response.hitl = NOT_REQUIRED` producing
    `story.hitl_status = NOT_REQUIRED`, `summary.hitl_pending_count = 0`, and
    `bluf.hitl_badge = NOT_REQUIRED`
  - blank first staged-defense tactic still allowing campaign
    `scenario_tactic_map()` fallback to mark a predicted navigator cell

## Follow-up Verification

Command:

```bash
pytest tests/__tests__/test_dashboard_snapshot.py -v
black core/dashboard.py tests/__tests__/test_dashboard_snapshot.py
ruff check core/dashboard.py tests/__tests__/test_dashboard_snapshot.py
mypy core/dashboard.py tests/__tests__/test_dashboard_snapshot.py
```

Results:

- `pytest tests/__tests__/test_dashboard_snapshot.py -v` -> 9 passed
- `black core/dashboard.py tests/__tests__/test_dashboard_snapshot.py` ->
  2 files left unchanged
- `ruff check core/dashboard.py tests/__tests__/test_dashboard_snapshot.py` ->
  passed
- `mypy core/dashboard.py tests/__tests__/test_dashboard_snapshot.py` ->
  passed
