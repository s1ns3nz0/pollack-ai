# Active Hunt Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an opt-in `ActiveHuntAgent` that runs bounded, template-only Sentinel KQL hunts for forward predictions and backward kill-chain reconstruction, then exposes evidence-only findings in reports.

**Architecture:** Add a policy-driven active hunt core that plans query candidates from alert context, predictions, mission risk, CPCON posture, and coverage tactic order. Keep Sentinel IO behind a small protocol-based tool so tests use fake clients and production uses Azure Monitor Logs only when configured. Wire the agent as an opt-in LangGraph node between `investigation` and `validation`, and keep validation verdict/confidence unchanged.

**Tech Stack:** Python 3.11+, pydantic v2, LangGraph, Azure Monitor Query (`azure-monitor-query`), Azure Identity (`azure-identity`), pytest, pytest-asyncio.

## Global Constraints

- `ACTIVE_HUNT_ENABLED=false` by default.
- KQL is template-only from `core/policy/active-hunt.yaml`; no runtime LLM KQL generation.
- Active hunt is read-only and evidence-only in the first implementation.
- Validation verdict/confidence must not change from active hunt findings.
- Forward window default: 30 minutes after alert time.
- Backward window default: 24 hours before alert time.
- Backward force window for `Exfiltration` and `Impact`: 72 hours.
- Global max lookback: 72 hours.
- Query row limit: 20.
- Max queries per alert: 5.
- Query timeout: 8 seconds.
- Existing user worktree changes must not be reverted or reformatted outside touched files.

---

## File Structure

- Create `core/active_hunt.py`: policy models, YAML loader, query candidate planner, KQL template renderer, and pure result conversion helpers.
- Create `core/policy/active-hunt.yaml`: default active hunt limits, backward trigger policy, and initial KQL templates.
- Create `tools/sentinel_query_tool.py`: `SentinelQueryClient` protocol, `SentinelQueryResult`, and Azure Monitor implementation.
- Create `agents/active_hunt_agent.py`: `BaseSOCAgent` node that plans candidates, calls the query client, and returns `active_hunt_findings`.
- Modify `core/models.py`: append `ActiveHuntFinding`; add `active_hunt_findings` to `SOCReport` and `SOCState`.
- Modify `core/settings.py`: append active hunt settings.
- Modify `agents/graph.py`: build active hunt dependencies only when enabled; insert opt-in node between `investigation` and `validation`.
- Modify `agents/report_agent.py`: copy state findings into `SOCReport`; add brief guardrail when matched findings exist.
- Modify `core/oscal.py`: include active hunt findings in evidence.
- Modify `core/brief.py`: surface matched active hunt findings in commander brief facts/caveats.
- Add tests under `tests/__tests__/`.

---

### Task 1: Active Hunt Models And Policy Planner

**Files:**
- Create: `core/active_hunt.py`
- Create: `core/policy/active-hunt.yaml`
- Modify: `core/models.py`
- Test: `tests/__tests__/test_active_hunt_policy.py`

**Interfaces:**
- Consumes: `core.models.Alert`, `core.models.AttackPrediction`, `core.models.MissionRisk`, `tools.coverage.CoverageMatrix`
- Produces:
  - `core.models.ActiveHuntFinding`
  - `core.active_hunt.ActiveHuntPolicy.from_yaml(path: str | Path | None = None) -> ActiveHuntPolicy`
  - `core.active_hunt.ActiveHuntPolicy.should_backward_hunt(alert: Alert, mission_risk: MissionRisk | None, current_order: int, cpcon_level: int, coverage: CoverageMatrix) -> bool`
  - `core.active_hunt.ActiveHuntPlanner.plan(alert: Alert, predictions: Sequence[AttackPrediction], mission_risk: MissionRisk | None, cpcon_level: int) -> ActiveHuntPlan`

- [ ] **Step 1: Write failing tests for policy thresholds and template-only planning**

Create `tests/__tests__/test_active_hunt_policy.py`:

```python
"""Active hunt policy tests — bounded template-only forward/backward KQL planning."""

from __future__ import annotations

from pathlib import Path

from core.active_hunt import ActiveHuntPlanner, ActiveHuntPolicy
from core.models import Alert, AttackPrediction, MissionRisk
from tools.coverage import Archetype, CoverageMatrix, TacticCoverage


def _coverage() -> CoverageMatrix:
    tactics = [
        TacticCoverage(name="InitialAccess", order=3, covered=["T1133"]),
        TacticCoverage(name="Discovery", order=8, covered=["T0842"]),
        TacticCoverage(name="LateralMovement", order=9, covered=["T1563"]),
        TacticCoverage(name="CommandAndControl", order=11, covered=["T1071"]),
        TacticCoverage(name="Exfiltration", order=12, covered=["T1041"]),
        TacticCoverage(name="Impact", order=15, covered=["T1485"]),
    ]
    return CoverageMatrix(tactics, {"A": Archetype(id="A")})


def _alert(tactic: str = "CommandAndControl") -> Alert:
    return Alert(
        id="a1",
        scenario_id="S2-C2-HIJACK",
        title="C2 hijack",
        asset_id="UAV-1",
        asset_tier="T2-Important",
        mission_phase="ISR",
        severity_baseline="medium",
        mitre={"techniques": ["T1071"], "tactics": [tactic]},
        signals=["지상국 미발신 명령 수신"],
        iocs=[],
        cves=[],
        sbom_components=[],
    )


def _risk(score: int, key: bool = False) -> MissionRisk:
    return MissionRisk(
        asset_id="UAV-1",
        mission_phase="ISR",
        score=score,
        is_key_terrain=key,
        dependents=[],
        factors={"score": score},
        rationale=[f"score={score}"],
    )


def test_policy_defaults_load() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    assert policy.limits.max_queries_per_alert == 5
    assert policy.limits.row_limit == 20
    assert policy.windows.forward_default_minutes == 30
    assert policy.windows.backward_force_hours == 72


def test_cpcon_threshold_controls_backward_hunt() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    cov = _coverage()
    assert policy.should_backward_hunt(_alert("Discovery"), None, 8, 5, cov) is False
    assert policy.should_backward_hunt(_alert("Discovery"), None, 8, 2, cov) is True


def test_key_terrain_and_mission_risk_lower_backward_threshold() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    cov = _coverage()
    alert = _alert("Discovery").model_copy(update={"key_terrain": True})
    assert policy.should_backward_hunt(alert, _risk(8, key=True), 8, 5, cov) is True


def test_force_tactic_always_runs_backward_hunt() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    cov = _coverage()
    assert policy.should_backward_hunt(_alert("Impact"), None, 15, 5, cov) is True


def test_forward_planner_uses_registered_template_only() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    planner = ActiveHuntPlanner(policy, _coverage())
    plan = planner.plan(
        _alert("InitialAccess"),
        [
            AttackPrediction(
                next_technique="T1133",
                probability=0.9,
                support_count=3,
                basis_actor_id="actor-1",
            )
        ],
        None,
        cpcon_level=5,
    )
    queries = plan.queries
    assert [q.technique for q in queries] == ["T1133"]
    assert queries[0].direction == "forward"
    assert "UAVGcsAccess_CL" in queries[0].kql
    assert "{start}" not in queries[0].kql
    assert "{end}" not in queries[0].kql


def test_missing_template_becomes_unavailable_finding() -> None:
    policy = ActiveHuntPolicy.from_yaml()
    planner = ActiveHuntPlanner(policy, _coverage())
    plan = planner.plan(
        _alert("InitialAccess"),
        [
            AttackPrediction(
                next_technique="T9999",
                probability=0.9,
                support_count=3,
                basis_actor_id="actor-1",
            )
        ],
        None,
        cpcon_level=5,
    )
    finding = plan.unavailable_findings[0]
    assert finding.direction == "forward"
    assert finding.technique == "T9999"
    assert finding.query_id == "query_unavailable"
    assert finding.error == "query template unavailable"
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
pytest tests/__tests__/test_active_hunt_policy.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'core.active_hunt'` or `ImportError` for `ActiveHuntFinding`.

- [ ] **Step 3: Add active hunt finding model**

In `core/models.py`, append this model immediately after `HuntHypothesis`:

```python
class ActiveHuntFinding(BaseModel):
    """능동 헌팅 KQL 조회 결과 — 예측/역추적 evidence-only finding.

    Attributes:
        direction: "forward" 또는 "backward".
        technique: 조회 대상 MITRE technique id.
        tactic: technique 소속 tactic.
        query_id: 정책 query template id 또는 "query_unavailable".
        matched: Sentinel 조회 결과가 1건 이상인지 여부.
        row_count: 전체 결과 수. 샘플 수와 다를 수 있다.
        time_window: 조회 시간창 설명.
        rationale: 왜 조회했는가.
        sample: 보고서에 남길 작은 샘플(row_limit 이하, 문자열화).
        error: 조회 실패나 template 부재 사유.
    """

    direction: str
    technique: str
    tactic: str = ""
    query_id: str
    matched: bool = False
    row_count: int = 0
    time_window: str = ""
    rationale: str = ""
    sample: list[dict[str, str]] = Field(default_factory=list)
    error: str = ""
```

- [ ] **Step 4: Add default active hunt policy YAML**

Create `core/policy/active-hunt.yaml`:

```yaml
# Active Hunt Agent 정책 — template-only Sentinel KQL 능동 헌팅.
# 1차 버전은 evidence-only: validation verdict/confidence 를 바꾸지 않는다.

version: 0.1

limits:
  max_queries_per_alert: 5
  row_limit: 20
  query_timeout_seconds: 8
  max_lookback_hours: 72

windows:
  forward_default_minutes: 30
  backward_default_hours: 24
  backward_force_hours: 72

backward_policy:
  force_tactics: [Exfiltration, Impact]
  cpcon_thresholds:
    5: CommandAndControl
    4: CommandAndControl
    3: LateralMovement
    2: Discovery
    1: InitialAccess
  key_terrain_order_delta: -2
  high_mission_risk_order_delta: -2
  high_mission_risk_score: 8

queries:
  T1133_external_remote_service:
    technique: T1133
    tactic: InitialAccess
    direction: both
    table: UAVGcsAccess_CL
    rationale: 외부 원격 서비스 접근 흔적 확인.
    kql: |
      UAVGcsAccess_CL
      | where TimeGenerated between (datetime({start}) .. datetime({end}))
      | where ClientIp !startswith "10."
      | where ClientIp !startswith "172.16."
      | where ClientIp !startswith "192.168."
      | take {row_limit}

  T1563_session_hijack:
    technique: T1563
    tactic: LateralMovement
    direction: both
    table: UAVGcsAccess_CL
    rationale: 동일 세션 ID 의 다중 ClientIp 사용 흔적 확인.
    kql: |
      UAVGcsAccess_CL
      | where TimeGenerated between (datetime({start}) .. datetime({end}))
      | summarize ips = make_set(ClientIp), rows = count() by SessionId
      | where array_length(ips) > 1
      | take {row_limit}

  T1041_exfil_over_c2:
    technique: T1041
    tactic: Exfiltration
    direction: both
    table: UAVGcsAccess_CL
    rationale: C2 채널을 통한 대량 송신 흔적 확인.
    kql: |
      UAVGcsAccess_CL
      | where TimeGenerated between (datetime({start}) .. datetime({end}))
      | where BytesSent > 100 * 1024 * 1024
      | take {row_limit}
```

- [ ] **Step 5: Implement policy and planner**

Create `core/active_hunt.py`:

```python
"""Active hunt policy/planner — template-only Sentinel KQL 후보 생성.

1차 버전은 읽기전용 evidence-only 이다. 이 모듈은 네트워크 IO 를 하지 않는다.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from core.exceptions import PolicyError
from core.models import ActiveHuntFinding, Alert, AttackPrediction, MissionRisk
from core.policy_loader import load_policy_mapping, require_mapping
from tools.coverage import CoverageMatrix, TacticCoverage

_POLICY = Path(__file__).resolve().parent / "policy" / "active-hunt.yaml"
_DEFAULT_ALERT_TIME = datetime(1970, 1, 1, tzinfo=UTC)


class HuntLimits(BaseModel):
    """Active hunt 비용/지연 제한."""

    max_queries_per_alert: int = Field(default=5, ge=1)
    row_limit: int = Field(default=20, ge=1)
    query_timeout_seconds: float = Field(default=8.0, gt=0.0)
    max_lookback_hours: int = Field(default=72, ge=1)


class HuntWindows(BaseModel):
    """방향별 조회 시간창."""

    forward_default_minutes: int = Field(default=30, ge=1)
    backward_default_hours: int = Field(default=24, ge=1)
    backward_force_hours: int = Field(default=72, ge=1)


class BackwardPolicy(BaseModel):
    """Backward hunt 트리거 정책."""

    force_tactics: list[str] = Field(default_factory=list)
    cpcon_thresholds: dict[int, str] = Field(default_factory=dict)
    key_terrain_order_delta: int = -2
    high_mission_risk_order_delta: int = -2
    high_mission_risk_score: int = 8


class HuntQueryTemplate(BaseModel):
    """정책 YAML 의 KQL template 한 건."""

    technique: str
    tactic: str = ""
    direction: Literal["forward", "backward", "both"] = "both"
    table: str
    rationale: str = ""
    kql: str


@dataclass(frozen=True)
class HuntQuery:
    """렌더링 완료된 active hunt query."""

    query_id: str
    direction: Literal["forward", "backward"]
    technique: str
    tactic: str
    kql: str
    timeout_seconds: float
    row_limit: int
    time_window: str
    rationale: str


@dataclass(frozen=True)
class ActiveHuntPlan:
    """Query candidates plus non-executable findings."""

    queries: list[HuntQuery]
    unavailable_findings: list[ActiveHuntFinding]


class ActiveHuntPolicy(BaseModel):
    """Active hunt 정책 루트."""

    version: float = 0.1
    limits: HuntLimits = Field(default_factory=HuntLimits)
    windows: HuntWindows = Field(default_factory=HuntWindows)
    backward_policy: BackwardPolicy = Field(default_factory=BackwardPolicy)
    queries: dict[str, HuntQueryTemplate] = Field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> ActiveHuntPolicy:
        """active-hunt.yaml 을 적재한다.

        Args:
            path: 정책 파일 경로. None 이면 기본 정책.

        Returns:
            검증된 active hunt 정책.

        Raises:
            PolicyError: 파일 부재/파싱 실패/스키마 오류.
        """
        raw = load_policy_mapping(path, _POLICY, label="active hunt 정책")
        try:
            data = dict(raw)
            queries_raw = require_mapping(
                data.get("queries"), label="active hunt queries"
            )
            data["queries"] = {
                str(qid): HuntQueryTemplate.model_validate(q)
                for qid, q in queries_raw.items()
                if isinstance(q, dict)
            }
            return cls.model_validate(data)
        except ValidationError as exc:
            raise PolicyError(f"active hunt 정책 검증 실패: {exc}") from exc

    def should_backward_hunt(
        self,
        alert: Alert,
        mission_risk: MissionRisk | None,
        current_order: int,
        cpcon_level: int,
        coverage: CoverageMatrix,
    ) -> bool:
        """CPCON/임무위험/핵심지형 기반 backward hunt 여부를 결정한다."""
        tactics = _alert_tactics(alert)
        if any(t in self.backward_policy.force_tactics for t in tactics):
            return True
        threshold_tactic = self.backward_policy.cpcon_thresholds.get(cpcon_level)
        threshold = coverage.tactic_order(threshold_tactic or "") or current_order + 1
        if alert.key_terrain:
            threshold += self.backward_policy.key_terrain_order_delta
        if (
            mission_risk is not None
            and mission_risk.score >= self.backward_policy.high_mission_risk_score
        ):
            threshold += self.backward_policy.high_mission_risk_order_delta
        max_order = coverage.max_tactic_order([t.name for t in coverage.tactics])
        threshold = max(1, min(max_order, threshold))
        return current_order >= threshold


class ActiveHuntPlanner:
    """Alert context → bounded active hunt query 후보."""

    def __init__(self, policy: ActiveHuntPolicy, coverage: CoverageMatrix) -> None:
        self._policy = policy
        self._coverage = coverage

    def plan(
        self,
        alert: Alert,
        predictions: Sequence[AttackPrediction],
        mission_risk: MissionRisk | None,
        cpcon_level: int,
    ) -> ActiveHuntPlan:
        """forward/backward query 후보를 생성한다."""
        queries: list[HuntQuery] = []
        unavailable: list[ActiveHuntFinding] = []
        alert_time = _alert_time(alert)
        for pred in predictions:
            tactic = self._coverage.tactic_of(pred.next_technique) or ""
            planned = self._queries_for(
                direction="forward",
                technique=pred.next_technique,
                tactic=tactic,
                start=alert_time,
                end=alert_time
                + timedelta(minutes=self._policy.windows.forward_default_minutes),
                rationale=f"예측 다음 technique(p={pred.probability:.2f})",
            )
            if planned:
                queries.extend(planned)
            else:
                unavailable.append(
                    self.unavailable_finding(
                        direction="forward",
                        technique=pred.next_technique,
                        tactic=tactic,
                        rationale="예측 technique template 없음",
                    )
                )
        current_order = self._current_order(alert)
        if self._policy.should_backward_hunt(
            alert, mission_risk, current_order, cpcon_level, self._coverage
        ):
            hours = self._backward_hours(alert)
            start = alert_time - timedelta(hours=hours)
            end = alert_time
            for tactic in self._previous_tactics(current_order):
                for technique in self._techniques_for_tactic(tactic.name):
                    queries.extend(
                        self._queries_for(
                            direction="backward",
                            technique=technique,
                            tactic=tactic.name,
                            start=start,
                            end=end,
                            rationale=f"후반 단계 alert 역추적({tactic.name})",
                        )
                    )
        return ActiveHuntPlan(
            queries=queries[: self._policy.limits.max_queries_per_alert],
            unavailable_findings=unavailable,
        )

    def unavailable_finding(
        self, direction: str, technique: str, tactic: str, rationale: str
    ) -> ActiveHuntFinding:
        """등록된 template 이 없을 때 report 에 남길 finding."""
        return ActiveHuntFinding(
            direction=direction,
            technique=technique,
            tactic=tactic,
            query_id="query_unavailable",
            rationale=rationale,
            error="query template unavailable",
        )

    def _queries_for(
        self,
        *,
        direction: Literal["forward", "backward"],
        technique: str,
        tactic: str,
        start: datetime,
        end: datetime,
        rationale: str,
    ) -> list[HuntQuery]:
        out: list[HuntQuery] = []
        for qid, tmpl in self._policy.queries.items():
            if tmpl.technique != technique:
                continue
            if tmpl.direction not in (direction, "both"):
                continue
            kql = tmpl.kql.format(
                start=_fmt(start),
                end=_fmt(end),
                row_limit=self._policy.limits.row_limit,
            )
            out.append(
                HuntQuery(
                    query_id=qid,
                    direction=direction,
                    technique=technique,
                    tactic=tactic or tmpl.tactic,
                    kql=kql,
                    timeout_seconds=self._policy.limits.query_timeout_seconds,
                    row_limit=self._policy.limits.row_limit,
                    time_window=f"{_fmt(start)}..{_fmt(end)}",
                    rationale=tmpl.rationale or rationale,
                )
            )
        return out

    def _current_order(self, alert: Alert) -> int:
        return self._coverage.max_tactic_order(_alert_tactics(alert))

    def _backward_hours(self, alert: Alert) -> int:
        tactics = _alert_tactics(alert)
        force = any(t in self._policy.backward_policy.force_tactics for t in tactics)
        hours = (
            self._policy.windows.backward_force_hours
            if force
            else self._policy.windows.backward_default_hours
        )
        return min(hours, self._policy.limits.max_lookback_hours)

    def _previous_tactics(self, current_order: int) -> list[TacticCoverage]:
        return [t for t in self._coverage.tactics if 0 < t.order < current_order]

    def _techniques_for_tactic(self, tactic: str) -> list[str]:
        for t in self._coverage.tactics:
            if t.name == tactic:
                techniques = [*t.covered, *t.planned, *(g.id for g in t.uncovered)]
                return list(dict.fromkeys(techniques))
        return []


def _alert_tactics(alert: Alert) -> list[str]:
    raw = alert.mitre.get("tactics", [])
    return [str(t) for t in raw] if isinstance(raw, list) else []


def _alert_time(alert: Alert) -> datetime:
    raw = getattr(alert, "timestamp", None) or getattr(alert, "time_generated", None)
    if not isinstance(raw, str) or not raw:
        return _DEFAULT_ALERT_TIME
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return _DEFAULT_ALERT_TIME


def _fmt(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
```

- [ ] **Step 6: Run policy tests**

Run:

```bash
pytest tests/__tests__/test_active_hunt_policy.py -v
```

Expected: PASS.

- [ ] **Step 7: Format and commit**

Run:

```bash
black core/active_hunt.py core/models.py tests/__tests__/test_active_hunt_policy.py
ruff check core/active_hunt.py core/models.py tests/__tests__/test_active_hunt_policy.py
```

Expected: both commands PASS.

Commit:

```bash
git add core/active_hunt.py core/models.py core/policy/active-hunt.yaml tests/__tests__/test_active_hunt_policy.py
git commit -m "feat: active hunt 정책 플래너 추가"
```

---

### Task 2: Sentinel Query Tool Boundary

**Files:**
- Create: `tools/sentinel_query_tool.py`
- Modify: `core/settings.py`
- Test: `tests/__tests__/test_sentinel_query_tool.py`

**Interfaces:**
- Consumes: `core.settings.Settings`
- Produces:
  - `tools.sentinel_query_tool.SentinelQueryResult(rows: list[dict[str, str]], row_count: int)`
  - `tools.sentinel_query_tool.SentinelQueryClient.aquery(kql: str, timeout_seconds: float) -> SentinelQueryResult`
  - `tools.sentinel_query_tool.AzureMonitorSentinelQueryClient(settings: Settings)`

- [ ] **Step 1: Write failing tests for fake-safe result normalization and config gate**

Create `tests/__tests__/test_sentinel_query_tool.py`:

```python
"""Sentinel query tool tests — Azure boundary stays thin and normalized."""

from __future__ import annotations

import pytest

from core.settings import Settings
from tools.sentinel_query_tool import (
    AzureMonitorSentinelQueryClient,
    SentinelQueryResult,
    normalize_rows,
)


def test_result_model_stringifies_sample_values() -> None:
    rows = normalize_rows([{"A": 1, "B": None, "C": True}], limit=20)
    assert rows == [{"A": "1", "B": "", "C": "True"}]


def test_result_model_applies_limit() -> None:
    rows = normalize_rows([{"A": i} for i in range(30)], limit=2)
    assert rows == [{"A": "0"}, {"A": "1"}]


def test_sentinel_query_result_counts_original_rows() -> None:
    result = SentinelQueryResult.from_raw([{"A": 1}, {"A": 2}], limit=1)
    assert result.row_count == 2
    assert result.rows == [{"A": "1"}]


def test_azure_client_requires_workspace_id() -> None:
    settings = Settings(sentinel_workspace_id="")
    with pytest.raises(ValueError, match="SENTINEL_WORKSPACE_ID"):
        AzureMonitorSentinelQueryClient(settings)
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
pytest tests/__tests__/test_sentinel_query_tool.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'tools.sentinel_query_tool'`.

- [ ] **Step 3: Add active hunt settings**

In `core/settings.py`, append this block near the other feature settings:

```python
    # ── Active Hunt Agent ──────────────────────────────
    active_hunt_enabled: bool = Field(
        default=False,
        description="opt-in — Sentinel KQL 능동 헌팅 노드 활성화.",
    )
    active_hunt_policy_path: str = Field(
        default="core/policy/active-hunt.yaml",
        description="Active hunt 정책 YAML 경로.",
    )
```

- [ ] **Step 4: Implement Sentinel query tool**

Create `tools/sentinel_query_tool.py`:

```python
"""Sentinel/Log Analytics read-only query boundary for ActiveHuntAgent."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, runtime_checkable

from azure.identity.aio import DefaultAzureCredential
from azure.monitor.query.aio import LogsQueryClient
from pydantic import BaseModel, Field

from core.settings import Settings


class SentinelQueryResult(BaseModel):
    """Normalized Sentinel query result."""

    rows: list[dict[str, str]] = Field(default_factory=list)
    row_count: int = 0

    @classmethod
    def from_raw(
        cls, rows: Sequence[Mapping[str, object]], limit: int
    ) -> SentinelQueryResult:
        """Create normalized result from raw row mappings."""
        return cls(rows=normalize_rows(rows, limit), row_count=len(rows))


@runtime_checkable
class SentinelQueryClient(Protocol):
    """Read-only KQL query client contract."""

    async def aquery(self, kql: str, timeout_seconds: float) -> SentinelQueryResult:
        """Run a KQL query and return normalized rows."""
        ...


def normalize_rows(
    rows: Sequence[Mapping[str, object]], limit: int
) -> list[dict[str, str]]:
    """Stringify and bound raw rows for report-safe samples."""
    out: list[dict[str, str]] = []
    for row in rows[:limit]:
        out.append({str(k): "" if v is None else str(v) for k, v in row.items()})
    return out


class AzureMonitorSentinelQueryClient:
    """Azure Monitor Logs implementation of SentinelQueryClient.

    Args:
        settings: Settings with `sentinel_workspace_id`.
    """

    def __init__(self, settings: Settings) -> None:
        if not settings.sentinel_workspace_id:
            raise ValueError("SENTINEL_WORKSPACE_ID is required for active hunt")
        self._workspace_id = settings.sentinel_workspace_id
        self._credential = DefaultAzureCredential()
        self._client = LogsQueryClient(self._credential)

    async def aquery(self, kql: str, timeout_seconds: float) -> SentinelQueryResult:
        """Run KQL against the configured Log Analytics workspace."""
        response = await self._client.query_workspace(
            self._workspace_id,
            kql,
            timespan=None,
            server_timeout=int(timeout_seconds),
        )
        rows: list[dict[str, object]] = []
        for table in getattr(response, "tables", []):
            columns = [str(c) for c in table.columns]
            for raw_row in table.rows:
                rows.append(dict(zip(columns, raw_row, strict=False)))
        return SentinelQueryResult.from_raw(rows, limit=len(rows))
```

- [ ] **Step 5: Run tool tests**

Run:

```bash
pytest tests/__tests__/test_sentinel_query_tool.py -v
```

Expected: PASS.

- [ ] **Step 6: Format and commit**

Run:

```bash
black tools/sentinel_query_tool.py core/settings.py tests/__tests__/test_sentinel_query_tool.py
ruff check tools/sentinel_query_tool.py core/settings.py tests/__tests__/test_sentinel_query_tool.py
```

Expected: both commands PASS.

Commit:

```bash
git add tools/sentinel_query_tool.py core/settings.py tests/__tests__/test_sentinel_query_tool.py
git commit -m "feat: Sentinel 조회 경계 추가"
```

---

### Task 3: ActiveHuntAgent Execution

**Files:**
- Create: `agents/active_hunt_agent.py`
- Modify: `core/models.py`
- Test: `tests/__tests__/test_active_hunt_agent.py`

**Interfaces:**
- Consumes:
  - `ActiveHuntPlanner.plan(...) -> ActiveHuntPlan`
  - `SentinelQueryClient.aquery(kql, timeout_seconds) -> SentinelQueryResult`
- Produces:
  - `ActiveHuntAgent.run(state: SOCState) -> SOCState` returning `{"active_hunt_findings": findings, "trace": ["active_hunt"]}`

- [ ] **Step 1: Write failing tests for matched, no-result, and error findings**

Create `tests/__tests__/test_active_hunt_agent.py`:

```python
"""ActiveHuntAgent tests — read-only KQL execution to evidence findings."""

from __future__ import annotations

from core.active_hunt import ActiveHuntPlanner, ActiveHuntPolicy
from core.models import Alert, AttackPrediction, InvestigationResult, MissionRisk
from core.settings import Settings
from agents.active_hunt_agent import ActiveHuntAgent
from tools.coverage import Archetype, CoverageMatrix, TacticCoverage
from tools.sentinel_query_tool import SentinelQueryResult


class _FakeClient:
    def __init__(self, result: SentinelQueryResult | Exception) -> None:
        self.result = result
        self.queries: list[str] = []

    async def aquery(self, kql: str, timeout_seconds: float) -> SentinelQueryResult:
        self.queries.append(kql)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _coverage() -> CoverageMatrix:
    return CoverageMatrix(
        [
            TacticCoverage(name="InitialAccess", order=3, covered=["T1133"]),
            TacticCoverage(name="CommandAndControl", order=11, covered=["T1071"]),
        ],
        {"A": Archetype(id="A")},
    )


def _state() -> dict[str, object]:
    alert = Alert(
        id="a1",
        scenario_id="S2-C2-HIJACK",
        title="C2 hijack",
        asset_id="UAV-1",
        asset_tier="T2-Important",
        mission_phase="ISR",
        severity_baseline="medium",
        mitre={"techniques": ["T1071"], "tactics": ["CommandAndControl"]},
        signals=["지상국 미발신 명령 수신"],
        iocs=[],
        cves=[],
        sbom_components=[],
    )
    inv = InvestigationResult(
        predictions=[
            AttackPrediction(
                next_technique="T1133",
                probability=0.9,
                support_count=3,
                basis_actor_id="actor-1",
            )
        ]
    )
    return {
        "alert": alert,
        "investigation": inv,
        "mission_risk": MissionRisk(asset_id="UAV-1", score=0, factors={}),
    }


async def test_agent_returns_matched_finding() -> None:
    client = _FakeClient(SentinelQueryResult(rows=[{"ClientIp": "203.0.113.66"}], row_count=1))
    agent = ActiveHuntAgent(
        Settings(active_hunt_enabled=True),
        ActiveHuntPlanner(ActiveHuntPolicy.from_yaml(), _coverage()),
        client,
        cpcon_level=5,
    )
    out = await agent.run(_state())  # type: ignore[arg-type]
    findings = out["active_hunt_findings"]
    assert findings[0].matched is True
    assert findings[0].row_count == 1
    assert findings[0].sample == [{"ClientIp": "203.0.113.66"}]
    assert out["trace"] == ["active_hunt"]


async def test_agent_returns_no_result_finding() -> None:
    client = _FakeClient(SentinelQueryResult(rows=[], row_count=0))
    agent = ActiveHuntAgent(
        Settings(active_hunt_enabled=True),
        ActiveHuntPlanner(ActiveHuntPolicy.from_yaml(), _coverage()),
        client,
        cpcon_level=5,
    )
    out = await agent.run(_state())  # type: ignore[arg-type]
    finding = out["active_hunt_findings"][0]
    assert finding.matched is False
    assert finding.row_count == 0
    assert finding.error == ""


async def test_agent_converts_query_error_to_error_finding() -> None:
    client = _FakeClient(RuntimeError("boom"))
    agent = ActiveHuntAgent(
        Settings(active_hunt_enabled=True),
        ActiveHuntPlanner(ActiveHuntPolicy.from_yaml(), _coverage()),
        client,
        cpcon_level=5,
    )
    out = await agent.run(_state())  # type: ignore[arg-type]
    finding = out["active_hunt_findings"][0]
    assert finding.matched is False
    assert finding.error == "boom"
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
pytest tests/__tests__/test_active_hunt_agent.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'agents.active_hunt_agent'`.

- [ ] **Step 3: Add SOCState field**

In `core/models.py`, add this to `SOCState`:

```python
    active_hunt_findings: list[ActiveHuntFinding]
```

- [ ] **Step 4: Implement ActiveHuntAgent**

Create `agents/active_hunt_agent.py`:

```python
"""ActiveHuntAgent — bounded read-only Sentinel KQL hunts."""

from __future__ import annotations

from agents.base import BaseSOCAgent
from core.active_hunt import ActiveHuntPlanner, HuntQuery
from core.models import ActiveHuntFinding, InvestigationResult, MissionRisk, SOCState
from core.settings import Settings
from tools.sentinel_query_tool import SentinelQueryClient


class ActiveHuntAgent(BaseSOCAgent):
    """Run policy-approved active hunt KQL templates and return evidence findings.

    Args:
        settings: 전역 설정.
        planner: query 후보 생성기.
        client: Sentinel read-only query client.
        cpcon_level: 현재 전역 CPCON level.
    """

    def __init__(
        self,
        settings: Settings,
        planner: ActiveHuntPlanner,
        client: SentinelQueryClient,
        cpcon_level: int,
    ) -> None:
        super().__init__(settings)
        self._planner = planner
        self._client = client
        self._cpcon_level = cpcon_level

    async def run(self, state: SOCState) -> SOCState:
        """Active hunt query 를 실행하고 finding 을 상태에 추가한다."""
        alert = state["alert"]
        inv: InvestigationResult | None = state.get("investigation")
        mission_risk: MissionRisk | None = state.get("mission_risk")
        predictions = inv.predictions if inv is not None else []
        plan = self._planner.plan(
            alert, predictions, mission_risk, self._cpcon_level
        )
        findings: list[ActiveHuntFinding] = list(plan.unavailable_findings)
        for query in plan.queries:
            findings.append(await self._run_query(query))
        self._logger.info(
            "active_hunt: alert=%s queries=%d matched=%d",
            alert.id,
            len(plan.queries),
            sum(1 for f in findings if f.matched),
        )
        return {"active_hunt_findings": findings, "trace": ["active_hunt"]}

    async def _run_query(self, query: HuntQuery) -> ActiveHuntFinding:
        try:
            result = await self._client.aquery(query.kql, query.timeout_seconds)
        except Exception as exc:
            return ActiveHuntFinding(
                direction=query.direction,
                technique=query.technique,
                tactic=query.tactic,
                query_id=query.query_id,
                time_window=query.time_window,
                rationale=query.rationale,
                error=str(exc),
            )
        return ActiveHuntFinding(
            direction=query.direction,
            technique=query.technique,
            tactic=query.tactic,
            query_id=query.query_id,
            matched=result.row_count > 0,
            row_count=result.row_count,
            time_window=query.time_window,
            rationale=query.rationale,
            sample=result.rows[: query.row_limit],
        )
```

- [ ] **Step 5: Run agent tests**

Run:

```bash
pytest tests/__tests__/test_active_hunt_agent.py -v
```

Expected: PASS.

- [ ] **Step 6: Format and commit**

Run:

```bash
black agents/active_hunt_agent.py core/models.py tests/__tests__/test_active_hunt_agent.py
ruff check agents/active_hunt_agent.py core/models.py tests/__tests__/test_active_hunt_agent.py
```

Expected: both commands PASS.

Commit:

```bash
git add agents/active_hunt_agent.py core/models.py tests/__tests__/test_active_hunt_agent.py
git commit -m "feat: ActiveHuntAgent 실행 노드 추가"
```

---

### Task 4: Report, OSCAL, And Commander Brief Exposure

**Files:**
- Modify: `core/models.py`
- Modify: `agents/report_agent.py`
- Modify: `core/oscal.py`
- Modify: `core/brief.py`
- Test: `tests/__tests__/test_active_hunt_report.py`

**Interfaces:**
- Consumes: `SOCState.active_hunt_findings`
- Produces:
  - `SOCReport.active_hunt_findings: list[ActiveHuntFinding]`
  - `OscalEvidence.active_hunt_findings: list[ActiveHuntFinding]`
  - Commander brief key fact when matched findings exist

- [ ] **Step 1: Write failing report exposure tests**

Create `tests/__tests__/test_active_hunt_report.py`:

```python
"""Active hunt report exposure tests."""

from __future__ import annotations

from agents.report_agent import ReportAgent
from core.models import (
    ActiveHuntFinding,
    Alert,
    InvestigationResult,
    Severity,
    Verdict,
)
from core.settings import Settings
from core.severity import SeverityEngine


def _alert() -> Alert:
    return Alert(
        id="a1",
        scenario_id="S2-C2-HIJACK",
        title="C2 hijack",
        asset_id="UAV-1",
        asset_tier="T2-Important",
        mission_phase="ISR",
        severity_baseline="medium",
        mitre={"techniques": ["T1071"], "tactics": ["CommandAndControl"]},
        signals=["지상국 미발신 명령 수신"],
        iocs=[],
        cves=[],
        sbom_components=[],
    )


async def test_report_includes_active_hunt_findings() -> None:
    finding = ActiveHuntFinding(
        direction="backward",
        technique="T1133",
        tactic="InitialAccess",
        query_id="T1133_external_remote_service",
        matched=True,
        row_count=2,
        rationale="이전 침투 흔적 확인",
    )
    agent = ReportAgent(Settings(), SeverityEngine())
    out = await agent.run(
        {
            "alert": _alert(),
            "severity": Severity.HIGH,
            "verdict": Verdict.TRUE_POSITIVE,
            "investigation": InvestigationResult(confidence=0.7),
            "active_hunt_findings": [finding],
            "guardrail_flags": [],
            "node_timings": [],
        }
    )
    report = out["report"]
    assert report.active_hunt_findings == [finding]
    assert any("active hunt matched" in flag for flag in report.guardrail_flags)
    assert any("active hunt" in fact for fact in report.commander_brief.key_facts)
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
pytest tests/__tests__/test_active_hunt_report.py -v
```

Expected: FAIL because `SOCReport` has no `active_hunt_findings` field.

- [ ] **Step 3: Add report and evidence fields**

In `core/models.py`, add to `SOCReport` after `hunt_hypotheses`:

```python
    active_hunt_findings: list[ActiveHuntFinding] = Field(
        default_factory=list,
        description="ActiveHuntAgent Sentinel KQL 조회 결과(evidence-only).",
    )
```

In `OscalEvidence`, add:

```python
    active_hunt_findings: list[ActiveHuntFinding] = Field(
        default_factory=list,
        description="Active hunt KQL 조회 evidence.",
    )
```

- [ ] **Step 4: Wire ReportAgent**

In `agents/report_agent.py`, inside `run()` before `SOCReport(...)`:

```python
        active_hunt_findings = state.get("active_hunt_findings", [])
```

Pass it into `SOCReport(...)`:

```python
            active_hunt_findings=active_hunt_findings,
```

After the existing ground segment guardrail block, add:

```python
        matched_hunts = [f for f in active_hunt_findings if f.matched]
        if matched_hunts:
            report.guardrail_flags = list(report.guardrail_flags) + [
                f"active hunt matched {len(matched_hunts)}건 — 예측/역추적 KQL 근거 존재"
            ]
```

- [ ] **Step 5: Wire OSCAL evidence**

In `core/oscal.py`, find `build_evidence(...)` and after assigning `ev.investigation`, add:

```python
    ev.active_hunt_findings = list(state.get("active_hunt_findings", []))
```

- [ ] **Step 6: Wire commander brief**

In `core/brief.py`, inside `_key_facts`, add after campaign/killweb facts:

```python
        matched_hunts = [f for f in report.active_hunt_findings if f.matched]
        if matched_hunts:
            facts.append(f"active hunt matched {len(matched_hunts)}건")
```

- [ ] **Step 7: Run report tests**

Run:

```bash
pytest tests/__tests__/test_active_hunt_report.py -v
```

Expected: PASS.

- [ ] **Step 8: Format and commit**

Run:

```bash
black core/models.py agents/report_agent.py core/oscal.py core/brief.py tests/__tests__/test_active_hunt_report.py
ruff check core/models.py agents/report_agent.py core/oscal.py core/brief.py tests/__tests__/test_active_hunt_report.py
```

Expected: both commands PASS.

Commit:

```bash
git add core/models.py agents/report_agent.py core/oscal.py core/brief.py tests/__tests__/test_active_hunt_report.py
git commit -m "feat: active hunt 결과 리포트 노출"
```

---

### Task 5: Opt-In Graph Wiring

**Files:**
- Modify: `agents/graph.py`
- Test: `tests/__tests__/test_active_hunt_graph.py`

**Interfaces:**
- Consumes:
  - `Settings.active_hunt_enabled`
  - `Settings.active_hunt_policy_path`
  - `ActiveHuntAgent`
  - `AzureMonitorSentinelQueryClient`
- Produces:
  - Active hunt node is absent by default.
  - Active hunt node appears between `investigation` and `validation` when enabled and dependencies load.

- [ ] **Step 1: Write graph wiring tests**

Create `tests/__tests__/test_active_hunt_graph.py`:

```python
"""Active hunt graph opt-in wiring tests."""

from __future__ import annotations

from agents.graph import build_soc_graph
from core.settings import Settings


def test_active_hunt_disabled_by_default() -> None:
    graph = build_soc_graph(settings=Settings(active_hunt_enabled=False))
    assert "active_hunt" not in graph.get_graph().nodes


def test_active_hunt_enabled_without_workspace_degrades_to_disabled() -> None:
    graph = build_soc_graph(
        settings=Settings(active_hunt_enabled=True, sentinel_workspace_id="")
    )
    assert "active_hunt" not in graph.get_graph().nodes
```

- [ ] **Step 2: Run graph tests to verify enabled case fails**

Run:

```bash
pytest tests/__tests__/test_active_hunt_graph.py -v
```

Expected: first test PASS, second test PASS before wiring or FAIL if settings field is missing. After Task 2 settings field exists, this provides the degradation guard.

- [ ] **Step 3: Add graph imports**

In `agents/graph.py`, add imports:

```python
from agents.active_hunt_agent import ActiveHuntAgent
from core.active_hunt import ActiveHuntPlanner, ActiveHuntPolicy
from tools.sentinel_query_tool import AzureMonitorSentinelQueryClient
```

- [ ] **Step 4: Build optional active hunt agent**

In `build_soc_graph(...)`, after `_hunt_planner` creation and before `report = ReportAgent(...)`, add:

```python
    active_hunt = None
    if settings.active_hunt_enabled and settings.sentinel_workspace_id:
        try:
            _active_policy = ActiveHuntPolicy.from_yaml(settings.active_hunt_policy_path)
            _active_coverage = CoverageMatrix.from_yaml()
            active_hunt = ActiveHuntAgent(
                settings,
                ActiveHuntPlanner(_active_policy, _active_coverage),
                AzureMonitorSentinelQueryClient(settings),
                cpcon_level=settings.cyber_posture_level,
            )
        except (SOCPlatformError, ValueError) as exc:
            get_logger("graph").warning("active_hunt 비활성화: %s", exc)
```

- [ ] **Step 5: Insert optional graph node**

Replace the static node list:

```python
    nodes: list[tuple[str, _NodeFn]] = [
        ("triage", _triage_with_match),
        ("investigation", investigation.run),
        ("validation", validation.run),
        ("response", response.run),
        ("rule_update", rule_update.run),
        ("report", report.run),
    ]
```

with:

```python
    nodes: list[tuple[str, _NodeFn]] = [
        ("triage", _triage_with_match),
        ("investigation", investigation.run),
    ]
    if active_hunt is not None:
        nodes.append(("active_hunt", active_hunt.run))
    nodes.extend(
        [
            ("validation", validation.run),
            ("response", response.run),
            ("rule_update", rule_update.run),
            ("report", report.run),
        ]
    )
```

Replace the edge:

```python
    graph.add_edge("investigation", "validation")
```

with:

```python
    if active_hunt is not None:
        graph.add_edge("investigation", "active_hunt")
        graph.add_edge("active_hunt", "validation")
    else:
        graph.add_edge("investigation", "validation")
```

- [ ] **Step 6: Run graph tests**

Run:

```bash
pytest tests/__tests__/test_active_hunt_graph.py -v
```

Expected: PASS.

- [ ] **Step 7: Run focused existing graph/report tests**

Run:

```bash
pytest tests/__tests__/test_soc_agents.py tests/__tests__/test_hunt.py -v
```

Expected: PASS.

- [ ] **Step 8: Format and commit**

Run:

```bash
black agents/graph.py tests/__tests__/test_active_hunt_graph.py
ruff check agents/graph.py tests/__tests__/test_active_hunt_graph.py
```

Expected: both commands PASS.

Commit:

```bash
git add agents/graph.py tests/__tests__/test_active_hunt_graph.py
git commit -m "feat: active hunt 그래프 opt-in 배선"
```

---

### Task 6: Final Verification

**Files:**
- No new source files.
- May update: `docs/superpowers/plans/2026-07-09-active-hunt-agent.md` only if execution reveals a plan typo.

**Interfaces:**
- Consumes all previous task deliverables.
- Produces verified active hunt implementation branch.

- [ ] **Step 1: Run focused active hunt suite**

Run:

```bash
pytest \
  tests/__tests__/test_active_hunt_policy.py \
  tests/__tests__/test_sentinel_query_tool.py \
  tests/__tests__/test_active_hunt_agent.py \
  tests/__tests__/test_active_hunt_report.py \
  tests/__tests__/test_active_hunt_graph.py \
  -v
```

Expected: PASS.

- [ ] **Step 2: Run full required project checks**

Run:

```bash
black .
ruff check .
mypy .
pytest
```

Expected: all commands PASS.

- [ ] **Step 3: Inspect final diff**

Run:

```bash
git diff --stat HEAD~5..HEAD
git status --short
```

Expected: diff includes only active hunt implementation files and tests; no unrelated user work is staged or modified by the active hunt tasks.

- [ ] **Step 4: Commit verification note if needed**

If Task 6 required only running checks, do not create an empty commit. If a typo or missed import was fixed, commit only that fix:

```bash
git add docs/superpowers/plans/2026-07-09-active-hunt-agent.md
git commit -m "fix: active hunt 검증 보완"
```

---

## Self-Review

- Spec coverage: opt-in graph node, forward/backward hunt, CPCON/mission-risk threshold, template-only KQL, bounded windows, row/query limits, Sentinel protocol, report evidence-only exposure, and no validation influence are covered by Tasks 1-5.
- Placeholder scan: no task depends on unspecified functions; all introduced interfaces are named with signatures.
- Type consistency: `ActiveHuntFinding`, `HuntQuery`, `ActiveHuntPolicy`, `ActiveHuntPlanner`, `SentinelQueryResult`, and `SentinelQueryClient` names are consistent across tasks.
