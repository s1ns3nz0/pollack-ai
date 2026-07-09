# Task 5 Report

## Status

- Outcome: DONE
- Scope honored: touched only `agents/graph.py`, the new graph test file, and this
  report file.

## Summary

Implemented Task 5 opt-in graph wiring for the active hunt node:

- Added imports: `ActiveHuntAgent`, `ActiveHuntPlanner`/`ActiveHuntPolicy`,
  `AzureMonitorSentinelQueryClient`.
- After `_hunt_planner` and before `ReportAgent` construction, `build_soc_graph`
  now builds an optional `ActiveHuntAgent` only when `active_hunt_enabled` is
  True AND `sentinel_workspace_id` is non-empty. Construction failures
  (`SOCPlatformError` from policy/coverage YAML load, `ValueError` from client
  init) are caught and logged (`active_hunt 비활성화: ...`) — the graph build
  never crashes and falls back to the default shape.
- Node list is now assembled in two parts so `active_hunt` is inserted between
  `investigation` and `validation` only when the agent was built; the
  `investigation → validation` edge is replaced by
  `investigation → active_hunt → validation` in that case.
- Default behavior unchanged: with `active_hunt_enabled=False` (default) the
  node and edges are identical to before.

## Files Changed

- `agents/graph.py`
- `tests/__tests__/test_active_hunt_graph.py`

## TDD Evidence

### RED / Baseline (Step 2, per brief)

Command:

```bash
pytest tests/__tests__/test_active_hunt_graph.py -v
```

Output before wiring (brief-specified expectation — both tests PASS pre-wiring,
providing the absence/degradation guard rather than a failing red):

```text
tests/__tests__/test_active_hunt_graph.py::test_active_hunt_disabled_by_default PASSED [ 50%]
tests/__tests__/test_active_hunt_graph.py::test_active_hunt_enabled_without_workspace_degrades_to_disabled PASSED [100%]
============================== 2 passed in 0.58s ===============================
```

### GREEN (after wiring)

Command:

```bash
pytest tests/__tests__/test_active_hunt_graph.py -v
```

Output:

```text
tests/__tests__/test_active_hunt_graph.py::test_active_hunt_disabled_by_default PASSED [ 50%]
tests/__tests__/test_active_hunt_graph.py::test_active_hunt_enabled_without_workspace_degrades_to_disabled PASSED [100%]
============================== 2 passed in 0.60s ===============================
```

### Enabled-path manual verification

Because the brief's test file only asserts node absence, the enabled path was
verified directly (script, not committed):

```text
enabled path OK: investigation -> active_hunt -> validation
policy-missing fallback OK: default graph shape, no crash
```

Assertions checked: with `active_hunt_enabled=True, sentinel_workspace_id="ws-123"`
the compiled graph contains `active_hunt`, edges
`("investigation","active_hunt")` and `("active_hunt","validation")` exist, and
`("investigation","validation")` is absent. With a nonexistent
`active_hunt_policy_path` the build logs
`active_hunt 비활성화: active hunt 정책 적재 실패: [Errno 2] ...` and degrades to
the default graph shape without raising.

### Regression (Step 7 + broader sweep)

```bash
pytest tests/__tests__/test_soc_agents.py tests/__tests__/test_hunt.py -q
# 28 passed in 1.55s

pytest tests/__tests__/ -k "active_hunt or graph" -q
# 65 passed, 1170 deselected in 8.33s
```

Post-reformat combined rerun:

```text
pytest tests/__tests__/test_active_hunt_graph.py tests/__tests__/test_soc_agents.py tests/__tests__/test_hunt.py -q
============================== 30 passed in 1.90s ==============================
```

## Formatting And Lint

### black

```bash
black agents/graph.py tests/__tests__/test_active_hunt_graph.py
```

```text
reformatted agents/graph.py
All done! ✨ 🍰 ✨
1 file reformatted, 1 file left unchanged.
```

(black wrapped the 89-col `ActiveHuntPolicy.from_yaml(...)` line; tests rerun
green afterwards, `black --check` now clean on both files.)

### ruff

```bash
ruff check agents/graph.py tests/__tests__/test_active_hunt_graph.py
```

```text
warning: The following rules have been removed and ignoring them has no effect:
    - ANN101
    - ANN102

All checks passed!
```

## Verification Notes

- Active hunt node ABSENT by default (`active_hunt_enabled=False`).
- Enabling requires both the flag and a non-empty `sentinel_workspace_id`
  (client raises `ValueError` on empty workspace; the gate short-circuits
  before construction).
- Fallback on dependency-load failure is logged, never raised — graph build is
  crash-safe.
- One deliberate micro-deviation from the brief's snippet: `active_hunt` is
  declared `active_hunt: ActiveHuntAgent | None = None` (brief had bare
  `= None`) to match the file's existing optional-wiring annotation style and
  keep mypy inference correct.

## Commit

- Staged scope: `agents/graph.py`, `tests/__tests__/test_active_hunt_graph.py`,
  `.superpowers/sdd/task-5-report.md`

## Review Fix Round 1

Finding [Medium]: no automated test for the ENABLED graph shape (previously
verified only by an uncommitted manual script).

Fix: added
`test_active_hunt_enabled_wires_node_between_investigation_and_validation` to
`tests/__tests__/test_active_hunt_graph.py`. It builds
`build_soc_graph(settings=Settings(active_hunt_enabled=True, sentinel_workspace_id="ws-test"))`
(offline: no Azure network at construction; default policy YAML loads) and
asserts:

- `active_hunt` node present
- edge `("investigation", "active_hunt")` present
- edge `("active_hunt", "validation")` present
- direct edge `("investigation", "validation")` ABSENT

Style matches the file's existing two tests (no docstrings, same Settings
construction and `graph.get_graph()` access pattern).

Verification:

```text
pytest tests/__tests__/test_active_hunt_graph.py -v
  test_active_hunt_disabled_by_default PASSED
  test_active_hunt_enabled_without_workspace_degrades_to_disabled PASSED
  test_active_hunt_enabled_wires_node_between_investigation_and_validation PASSED
  3 passed in 0.81s

black --check: 1 file would be left unchanged.
ruff check: All checks passed!
```

Regression sanity (scratch script, not committed): running the same assertion
logic against a disabled graph (`active_hunt_enabled=False`) FAILS as expected —
`active_hunt` absent and the direct `investigation → validation` edge present —
so the test would catch a wiring regression.
