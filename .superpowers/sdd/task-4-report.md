# Task 4 Report

## Status

- Outcome: DONE
- Scope honored: touched only Task 4 files plus the requested Task 4 report file.

## Summary

Implemented Task 4 exposure for active hunt findings:

- Added `SOCReport.active_hunt_findings`.
- Added `OscalEvidence.active_hunt_findings`.
- Updated `ReportAgent` to read `state.get("active_hunt_findings", [])`, include it in
  `SOCReport`, and append a guardrail flag when matched findings exist.
- Updated commander brief key facts to mention matched active hunt findings.
- Updated OSCAL evidence builder to copy `active_hunt_findings`.
- Added focused tests for report and OSCAL exposure.

Validation verdict/confidence behavior was left unchanged.

## Files Changed

- `core/models.py`
- `agents/report_agent.py`
- `core/oscal.py`
- `core/brief.py`
- `tests/__tests__/test_active_hunt_report.py`

## TDD Evidence

### RED

Command:

```bash
pytest tests/__tests__/test_active_hunt_report.py -v
```

Initial failure after aligning the test fixture to local `Alert` model shape:

```text
FAILED tests/__tests__/test_active_hunt_report.py::test_report_includes_active_hunt_findings - AttributeError: 'SOCReport' object has no attribute 'active_hunt_findings'
FAILED tests/__tests__/test_active_hunt_report.py::test_oscal_evidence_includes_active_hunt_findings - AttributeError: 'OscalEvidence' object has no attribute 'active_hunt_findings'
============================== 2 failed in 0.23s ===============================
```

Note: the very first run failed earlier on `Alert.severity_baseline="medium"` because this
worktree expects enum values such as `"m"`. I updated the test fixture to follow the local
model contract, then reran to get the intended Task 4 red state above.

### GREEN

Command:

```bash
pytest tests/__tests__/test_active_hunt_report.py -v
```

Passing output:

```text
tests/__tests__/test_active_hunt_report.py::test_report_includes_active_hunt_findings PASSED [ 50%]
tests/__tests__/test_active_hunt_report.py::test_oscal_evidence_includes_active_hunt_findings PASSED [100%]
============================== 2 passed in 0.18s ===============================
```

## Formatting And Lint

### black

Command:

```bash
black core/models.py agents/report_agent.py core/oscal.py core/brief.py tests/__tests__/test_active_hunt_report.py
```

Output:

```text
reformatted core/brief.py

All done! ✨ 🍰 ✨
1 file reformatted, 4 files left unchanged.
```

### ruff

Command:

```bash
ruff check core/models.py agents/report_agent.py core/oscal.py core/brief.py tests/__tests__/test_active_hunt_report.py
```

Output:

```text
warning: The following rules have been removed and ignoring them has no effect:
    - ANN101
    - ANN102

All checks passed!
```

## Verification Notes

- `ReportAgent` does not trigger active hunt work; it only reads
  `state.get("active_hunt_findings", [])`.
- Commander brief exposure is limited to matched findings.
- OSCAL evidence copies the findings list without changing validation verdict/confidence.

## Commit

- Commit created after staging only the Task 4 files and the required Task 4 report file.
- Staged scope: `agents/report_agent.py`, `core/brief.py`, `core/models.py`,
  `core/oscal.py`, `tests/__tests__/test_active_hunt_report.py`,
  `.superpowers/sdd/task-4-report.md`
