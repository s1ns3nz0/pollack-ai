# Defense Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a dark, story-first cyber operations staff dashboard that renders SOC snapshots as story rail, UAV ATT&CK navigator, BLUF advice, and UAS asset topology.

**Architecture:** Keep analysis logic in `core/dashboard.py` as deterministic view-model builders. Keep transport/UI in `app/dashboard.py` and `app/dashboard_static/`, using one shared snapshot JSON schema for replay files and SSE. Store topology as static policy in `core/policy/asset-topology.yaml`; the dashboard does not depend on `uav-sim-env` at runtime.

**Tech Stack:** Python 3.11+, Pydantic v2, PyYAML, FastAPI, uvicorn, vanilla HTML/CSS/JS, pytest.

## Global Constraints

- Public Python functions and methods must have type hints and Google-style docstrings.
- Do not use `Any`; use precise `object`, Pydantic models, or type guards.
- Do not use `print()`; use `get_logger()` if runtime logging is needed.
- Do not introduce hardcoded secrets, endpoints, API keys, or live Azure dependencies.
- Dashboard is a rendering layer only; it must not create new verdict, severity, CAT, or mission impact decisions.
- Snapshot JSON is the shared wire format for replay and SSE live mode.
- UI must be dark, dense, decision-first, and story-first; alert-first analyst mode is out of v1 scope.
- After implementation run, in order: `black .`, `ruff check .`, `mypy .`, `pytest`.

---

## File Structure

- Create `core/policy/asset-topology.yaml`: static topology policy extracted from latest `uav-sim-env` Helm values. Owns node, edge, display label, plane, metadata, and degradation mapping.
- Create `core/dashboard.py`: Pydantic dashboard view models, topology loader, coverage loader, and deterministic snapshot builder.
- Create `app/dashboard.py`: FastAPI app factory, replay snapshot repository, JSON APIs, SSE endpoint, and static file mounting.
- Create `app/dashboard_static/index.html`: single dashboard shell.
- Create `app/dashboard_static/dashboard.css`: dark command-center layout and responsive behavior.
- Create `app/dashboard_static/dashboard.js`: fetch/replay/SSE adapter and DOM rendering.
- Create `tests/__tests__/test_dashboard_topology.py`: topology policy and loader tests.
- Create `tests/__tests__/test_dashboard_snapshot.py`: SOCState/report fixture to dashboard snapshot tests.
- Create `tests/__tests__/test_dashboard_app.py`: FastAPI endpoint and degraded-state smoke tests.
- Create `tests/__tests__/test_dashboard_static.py`: static asset smoke tests.
- Modify `pyproject.toml`: add `fastapi` and `uvicorn` runtime dependencies.

---

### Task 1: Topology Policy And Loader

**Files:**
- Create: `core/policy/asset-topology.yaml`
- Create: `core/dashboard.py`
- Test: `tests/__tests__/test_dashboard_topology.py`

**Interfaces:**
- Produces: `TopologyPolicy.from_yaml(path: str | Path | None = None) -> TopologyPolicy`
- Produces: `TopologyPolicy.to_view_model() -> DashboardTopology`
- Produces: `TopologyPolicy.node_for_degradation(asset_id: str) -> str | None`
- Later tasks consume: `DashboardTopology`, `DashboardNode`, `DashboardEdge`

- [ ] **Step 1: Write the failing topology tests**

Create `tests/__tests__/test_dashboard_topology.py`:

```python
"""Dashboard topology policy tests."""

from pathlib import Path

from core.dashboard import TopologyPolicy


def test_asset_topology_loads_enabled_uav_sim_assets() -> None:
    """Topology policy exposes representative uav-sim-env assets."""
    policy = TopologyPolicy.from_yaml()
    node_ids = {node.id for node in policy.nodes}

    assert "av-muav" in node_ids
    assert "datalink-satcom" in node_ids
    assert "gcs-qgc" in node_ids
    assert "telemetry-tap" in node_ids
    assert "weapon-stub" in node_ids
    assert "ai-soc" in node_ids


def test_asset_topology_edges_reference_existing_nodes() -> None:
    """Every topology edge must point at known nodes."""
    policy = TopologyPolicy.from_yaml()
    node_ids = {node.id for node in policy.nodes}

    for edge in policy.edges:
        assert edge.source in node_ids
        assert edge.target in node_ids


def test_degradation_asset_mapping_targets_existing_nodes() -> None:
    """Degradation asset ids map onto deployable topology nodes."""
    policy = TopologyPolicy.from_yaml()
    node_ids = {node.id for node in policy.nodes}

    for asset_id in ["GNSS", "AUTOPILOT", "C2_LINK", "SATCOM", "GCS", "AI_SOC"]:
        mapped = policy.node_for_degradation(asset_id)
        assert mapped in node_ids


def test_to_view_model_preserves_planes_and_labels() -> None:
    """UI topology contains plane and display label metadata."""
    topology = TopologyPolicy.from_yaml().to_view_model()
    av = next(node for node in topology.nodes if node.id == "av-muav")

    assert av.plane == "air"
    assert "MUAV" in av.label
    assert topology.edges


def test_from_yaml_rejects_unknown_edge_endpoint(tmp_path: Path) -> None:
    """Malformed topology policies fail closed."""
    bad_policy = tmp_path / "asset-topology.yaml"
    bad_policy.write_text(
        """
version: 0.1
nodes:
  - id: av-muav
    label: KUS-FS MUAV
    plane: air
    kind: air_vehicle
edges:
  - source: av-muav
    target: missing-node
    kind: depends_on
degradation_map: {}
""",
        encoding="utf-8",
    )

    try:
        TopologyPolicy.from_yaml(bad_policy)
    except ValueError as exc:
        assert "unknown topology edge endpoint" in str(exc)
    else:
        raise AssertionError("expected ValueError")
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
pytest tests/__tests__/test_dashboard_topology.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'core.dashboard'`.

- [ ] **Step 3: Add the static topology policy**

Create `core/policy/asset-topology.yaml`:

```yaml
# Static dashboard topology, derived from s1ns3nz0/uav-sim-env
# local-k8s/helm/uav-sim/values.yaml as of 2026-07-10.
# Helm values are the naming authority. uav-sim-env docs only inform labels.
version: 0.1
source:
  repo: "s1ns3nz0/uav-sim-env"
  file: "local-k8s/helm/uav-sim/values.yaml"
  captured_at: "2026-07-10"

nodes:
  - id: av-muav
    label: "KUS-FS MUAV 편대 / Air Vehicle"
    plane: air
    kind: air_vehicle
    degradation_asset_ids: [GNSS, AUTOPILOT, PAYLOAD_EOIR]
    metadata:
      replicas: "3"
      home: "39.2239,125.6700,35"
  - id: datalink-los
    label: "LOS Data Link / GDT"
    plane: link
    kind: data_link
    degradation_asset_ids: [C2_LINK, TELEMETRY]
    metadata:
      status: "enabled in AKS values"
  - id: datalink-satcom
    label: "BLOS SATCOM Link"
    plane: link
    kind: data_link
    degradation_asset_ids: [SATCOM, C2_LINK]
  - id: gcs-qgc
    label: "GCS/MCE QGroundControl"
    plane: ground
    kind: ground_control_station
    degradation_asset_ids: [GCS]
  - id: telemetry-tap
    label: "SOC Telemetry Tap"
    plane: soc
    kind: sensor
    degradation_asset_ids: [TELEMETRY, AI_SOC]
  - id: ground-truth-tap
    label: "Ground Truth Tap"
    plane: soc
    kind: sensor
    degradation_asset_ids: [TELEMETRY]
  - id: counter-uas
    label: "Counter-UAS Site"
    plane: ground
    kind: defensive_system
  - id: service-audit
    label: "Kubernetes Service Audit"
    plane: soc
    kind: sensor
    degradation_asset_ids: [AI_SOC]
  - id: mps-stub
    label: "Mission Planning System"
    plane: ground
    kind: mission_system
  - id: pgse-stub
    label: "PGSE Launch/Maintenance"
    plane: ground
    kind: support_equipment
  - id: weapon-stub
    label: "Weapon Control Interface"
    plane: ground
    kind: weapon_control
  - id: ti-stub
    label: "Threat Intelligence Interface"
    plane: soc
    kind: threat_intel
    degradation_asset_ids: [AI_SOC]
  - id: auth-stub
    label: "Operator Authentication"
    plane: ground
    kind: identity
  - id: cyber-posture-stub
    label: "Cyber Posture Service"
    plane: soc
    kind: posture
    degradation_asset_ids: [AI_SOC]
  - id: sar-stub
    label: "SAR Payload Service"
    plane: ground
    kind: payload
    degradation_asset_ids: [PAYLOAD_EOIR]
  - id: web-stub
    label: "UAS Web Attack Surface"
    plane: ground
    kind: application
  - id: rc-link-stub
    label: "RC / WiFi Link Surface"
    plane: link
    kind: data_link
    degradation_asset_ids: [C2_LINK]
  - id: supply-chain-stub
    label: "Supply Chain Interface"
    plane: ground
    kind: supply_chain
  - id: file-audit-stub
    label: "File Audit Sensor"
    plane: soc
    kind: sensor
    degradation_asset_ids: [AI_SOC]
  - id: companion-stub
    label: "Companion / ROS Surface"
    plane: ground
    kind: companion_computer
  - id: devops-stub
    label: "DevOps / Build Pipeline"
    plane: ground
    kind: devops
  - id: fleet-infra-stub
    label: "Fleet API / Swarm Infra"
    plane: ground
    kind: fleet_infra
  - id: c4i-stub
    label: "C4I Handoff Interface"
    plane: c4i
    kind: c4i
  - id: ai-soc
    label: "AI SOC Decision Layer"
    plane: soc
    kind: soc
    degradation_asset_ids: [AI_SOC]

edges:
  - { source: av-muav, target: datalink-los, kind: mavlink_los }
  - { source: av-muav, target: datalink-satcom, kind: blos_satcom }
  - { source: datalink-los, target: gcs-qgc, kind: command_telemetry }
  - { source: datalink-los, target: telemetry-tap, kind: telemetry_mirror }
  - { source: av-muav, target: ground-truth-tap, kind: direct_truth_tap }
  - { source: telemetry-tap, target: ai-soc, kind: detection_stream }
  - { source: ground-truth-tap, target: ai-soc, kind: detection_stream }
  - { source: datalink-satcom, target: ai-soc, kind: link_observability }
  - { source: gcs-qgc, target: mps-stub, kind: mission_workflow }
  - { source: mps-stub, target: c4i-stub, kind: mission_handoff }
  - { source: c4i-stub, target: weapon-stub, kind: fire_control_handoff }
  - { source: pgse-stub, target: av-muav, kind: launch_maintenance }
  - { source: weapon-stub, target: av-muav, kind: payload_command }
  - { source: auth-stub, target: gcs-qgc, kind: operator_identity }
  - { source: ti-stub, target: ai-soc, kind: enrichment }
  - { source: cyber-posture-stub, target: ai-soc, kind: posture }
  - { source: service-audit, target: ai-soc, kind: platform_audit }
  - { source: counter-uas, target: ai-soc, kind: defensive_observation }
  - { source: sar-stub, target: ai-soc, kind: payload_observation }
  - { source: web-stub, target: ai-soc, kind: audit_stream }
  - { source: rc-link-stub, target: ai-soc, kind: audit_stream }
  - { source: supply-chain-stub, target: ai-soc, kind: audit_stream }
  - { source: file-audit-stub, target: ai-soc, kind: audit_stream }
  - { source: companion-stub, target: ai-soc, kind: audit_stream }
  - { source: devops-stub, target: ai-soc, kind: audit_stream }
  - { source: fleet-infra-stub, target: ai-soc, kind: audit_stream }

degradation_map:
  GNSS: av-muav
  AUTOPILOT: av-muav
  PAYLOAD_EOIR: av-muav
  C2_LINK: datalink-los
  SATCOM: datalink-satcom
  GCS: gcs-qgc
  TELEMETRY: telemetry-tap
  AI_SOC: ai-soc
```

- [ ] **Step 4: Add topology models and loader**

Create `core/dashboard.py` with this initial content:

```python
"""Dashboard view models and deterministic snapshot builders.

The dashboard is a rendering layer. It reshapes authoritative SOC report fields
for a staff-facing UI and does not create new verdicts, severities, CAT labels,
or mission impact decisions.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field
import yaml

from core.exceptions import PolicyError

_POLICY_DIR = Path(__file__).resolve().parent / "policy"
_TOPOLOGY_POLICY = _POLICY_DIR / "asset-topology.yaml"


class DashboardNode(BaseModel):
    """Topology node rendered by the dashboard."""

    id: str
    label: str
    plane: str
    kind: str = ""
    status: str = "UNKNOWN"
    active: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)


class DashboardEdge(BaseModel):
    """Topology edge rendered by the dashboard."""

    source: str
    target: str
    kind: str = ""
    active: bool = False


class DashboardTopology(BaseModel):
    """Dashboard topology view model."""

    nodes: list[DashboardNode] = Field(default_factory=list)
    edges: list[DashboardEdge] = Field(default_factory=list)


class TopologyNode(BaseModel):
    """Static topology node from policy."""

    id: str
    label: str
    plane: str
    kind: str = ""
    degradation_asset_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class TopologyEdge(BaseModel):
    """Static topology edge from policy."""

    source: str
    target: str
    kind: str = ""


class TopologyPolicy(BaseModel):
    """Static asset topology policy."""

    version: float | str
    nodes: list[TopologyNode] = Field(default_factory=list)
    edges: list[TopologyEdge] = Field(default_factory=list)
    degradation_map: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> TopologyPolicy:
        """Load and validate the dashboard topology policy.

        Args:
            path: Optional policy path. Defaults to core/policy/asset-topology.yaml.

        Returns:
            Validated topology policy.

        Raises:
            PolicyError: Policy file cannot be read or parsed.
            ValueError: Policy references unknown nodes.
        """
        policy_path = Path(path) if path is not None else _TOPOLOGY_POLICY
        try:
            raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise PolicyError(f"asset topology policy load failed: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError("asset topology policy must be a mapping")
        policy = cls.model_validate(raw)
        policy._validate_references()
        return policy

    def _validate_references(self) -> None:
        """Validate edge and degradation-map node references.

        Raises:
            ValueError: Any reference points to an unknown node.
        """
        node_ids = {node.id for node in self.nodes}
        for edge in self.edges:
            if edge.source not in node_ids or edge.target not in node_ids:
                raise ValueError(
                    "unknown topology edge endpoint: "
                    f"{edge.source}->{edge.target}"
                )
        for asset_id, node_id in self.degradation_map.items():
            if node_id not in node_ids:
                raise ValueError(
                    f"unknown degradation mapping endpoint: {asset_id}->{node_id}"
                )

    def node_for_degradation(self, asset_id: str) -> str | None:
        """Return topology node id for a degradation asset id.

        Args:
            asset_id: Degradation matrix asset id such as GNSS or C2_LINK.

        Returns:
            Matching topology node id, or None when unmapped.
        """
        return self.degradation_map.get(asset_id)

    def to_view_model(self) -> DashboardTopology:
        """Convert the static policy to a dashboard topology view model.

        Returns:
            Topology view model with inactive UNKNOWN nodes.
        """
        return DashboardTopology(
            nodes=[
                DashboardNode(
                    id=node.id,
                    label=node.label,
                    plane=node.plane,
                    kind=node.kind,
                    metadata=dict(node.metadata),
                )
                for node in self.nodes
            ],
            edges=[
                DashboardEdge(source=edge.source, target=edge.target, kind=edge.kind)
                for edge in self.edges
            ],
        )
```

- [ ] **Step 5: Run tests and commit**

Run:

```bash
pytest tests/__tests__/test_dashboard_topology.py -v
black core/dashboard.py tests/__tests__/test_dashboard_topology.py
ruff check core/dashboard.py tests/__tests__/test_dashboard_topology.py
mypy core/dashboard.py tests/__tests__/test_dashboard_topology.py
```

Expected: all PASS.

Commit:

```bash
git add core/dashboard.py core/policy/asset-topology.yaml tests/__tests__/test_dashboard_topology.py
git commit -m "feat: add dashboard topology policy"
```

---

### Task 2: Snapshot View Models And Builder

**Files:**
- Modify: `core/dashboard.py`
- Test: `tests/__tests__/test_dashboard_snapshot.py`

**Interfaces:**
- Consumes: `TopologyPolicy.from_yaml()`, `TopologyPolicy.to_view_model()`
- Produces: `build_dashboard_snapshot(state: SOCState, *, step: int = 0, mode: str = "replay", topology: TopologyPolicy | None = None) -> DashboardSnapshot`
- Produces: Pydantic models `DashboardSnapshot`, `DashboardStory`, `DashboardNavigatorCell`, `DashboardBluf`, `DashboardSummary`
- Later tasks consume: `DashboardSnapshot.model_dump(mode="json")`

- [ ] **Step 1: Write failing snapshot tests**

Create `tests/__tests__/test_dashboard_snapshot.py`:

```python
"""Dashboard snapshot builder tests."""

from core.dashboard import TopologyPolicy, build_dashboard_snapshot
from core.models import (
    Alert,
    ApprovalResult,
    CampaignMatch,
    CommanderBrief,
    MissionContinuity,
    ResponseResult,
    Severity,
    SOCReport,
    SOCState,
    Verdict,
)


def _state() -> SOCState:
    alert = Alert(
        id="alert-001",
        scenario_id="S24-DATALINK-C2-TAKEOVER",
        title="비인가 C2 링크 장악",
        severity_baseline=Severity.HIGH,
        asset_id="C2_LINK",
        actor_id="RED-01",
        mitre={"tactic": "CommandAndControl", "technique": "T1071"},
        signals=["operator command anomaly"],
    )
    continuity = MissionContinuity(
        asset_id="C2_LINK",
        level="MINIMAL",
        capability_lost="실시간 지상 지휘통제",
        fallback="자율 페일세이프 모드 + 대체 링크 시도",
        sustains=False,
    )
    report = SOCReport(
        alert_id=alert.id,
        scenario_id=alert.scenario_id,
        title=alert.title,
        severity=Severity.HIGH,
        verdict=Verdict.TRUE_POSITIVE,
        action_taken="HITL 승인 대기",
        hitl="HITL_REQUIRED",
        mitre={"tactic": "CommandAndControl", "technique": "T1071"},
        mission_continuity=continuity,
        campaign_matches=[
            CampaignMatch(
                chain_id="C2",
                name="C2 takeover",
                matched=2,
                total=4,
                next_expected="S117-BLOS-SATCOM-MITM",
                severity="critical",
            )
        ],
        commander_brief=CommanderBrief(
            bluf="[결심필요] C2_LINK TRUE_POSITIVE/HIGH 임무 MINIMAL",
            confidence="authoritative",
            decision_required=["지휘관 결심: C2_LINK"],
            key_facts=["임무 지속성 MINIMAL"],
            caveats=["결심 여유 lower-bound"],
        ),
    )
    return {
        "alert": alert,
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
        "approval": ApprovalResult(required=True, approved=False, note="승인 대기"),
        "response": ResponseResult(
            hitl="HITL_REQUIRED",
            mission_continuity=continuity,
            cacao_steps=[{"name": "대체 링크 전환"}, {"name": "RTB 준비"}],
        ),
        "report": report,
        "trace": ["triage", "investigation", "validation", "approval", "response"],
    }


def test_snapshot_summary_and_story_are_decision_first() -> None:
    """Snapshot exposes story summary before alert details."""
    snap = build_dashboard_snapshot(_state(), step=3, mode="replay")

    assert snap.schema_version == "dashboard.snapshot.v1"
    assert snap.summary.active_story_count == 1
    assert snap.summary.max_mission_impact == "MINIMAL"
    assert snap.summary.hitl_pending_count == 1
    assert snap.stories[0].story_id == "RED-01"
    assert snap.stories[0].alerts[0].alert_id == "alert-001"


def test_snapshot_uses_commander_brief_for_bluf() -> None:
    """BLUF card preserves commander brief language and caveats."""
    snap = build_dashboard_snapshot(_state())

    assert snap.bluf.confidence == "authoritative"
    assert "C2_LINK" in snap.bluf.situation
    assert snap.bluf.caveats == ["결심 여유 lower-bound"]


def test_navigator_marks_current_predicted_and_gap() -> None:
    """Navigator exposes tactic states for the selected story."""
    snap = build_dashboard_snapshot(_state())
    by_tactic = {cell.tactic: cell for cell in snap.navigator}

    assert by_tactic["CommandAndControl"].current is True
    assert by_tactic["CommandAndControl"].observed is True
    assert any(cell.predicted for cell in snap.navigator)
    assert by_tactic["CommandAndControl"].gap is True


def test_topology_highlights_degraded_asset_node() -> None:
    """C2_LINK mission continuity maps to datalink topology node."""
    snap = build_dashboard_snapshot(_state(), topology=TopologyPolicy.from_yaml())
    nodes = {node.id: node for node in snap.topology.nodes}

    assert nodes["datalink-los"].active is True
    assert nodes["datalink-los"].status == "MINIMAL"
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
pytest tests/__tests__/test_dashboard_snapshot.py -v
```

Expected: FAIL with `ImportError` for `build_dashboard_snapshot`.

- [ ] **Step 3: Add snapshot models**

Append to `core/dashboard.py`:

```python
from datetime import UTC, datetime
from typing import Literal

from core.models import SOCReport, SOCState

DashboardMode = Literal["replay", "live"]


class DashboardSummary(BaseModel):
    """Top strip summary values."""

    active_story_count: int = 0
    max_mission_impact: str = "UNKNOWN"
    hitl_pending_count: int = 0
    decision_advantage: str = "unknown"


class DashboardAlertRef(BaseModel):
    """Alert reference nested under a story card."""

    alert_id: str
    scenario_id: str
    title: str = ""
    tactic: str = ""
    order: int = 0


class DashboardStory(BaseModel):
    """Story rail card view model."""

    story_id: str
    actor: str = ""
    campaign_id: str = ""
    campaign_name: str = ""
    matched: int = 0
    total: int = 0
    next_expected: str = ""
    target_asset: str = ""
    mission_impact: str = "UNKNOWN"
    hitl_status: str = "NOT_REQUIRED"
    alerts: list[DashboardAlertRef] = Field(default_factory=list)


class DashboardNavigatorCell(BaseModel):
    """UAV ATT&CK navigator cell."""

    tactic: str
    order: int
    observed: bool = False
    current: bool = False
    predicted: bool = False
    gap: bool = False
    observed_order: int | None = None
    note: str = ""


class DashboardBluf(BaseModel):
    """BLUF staff advice card view model."""

    situation: str = ""
    mission_impact: str = ""
    recommendation: str = ""
    next_move: str = ""
    confidence: str = "unknown"
    hitl_badge: str = "NOT_REQUIRED"
    caveats: list[str] = Field(default_factory=list)


class DashboardSource(BaseModel):
    """Audit pointer for a dashboard snapshot."""

    alert_id: str = ""
    scenario_id: str = ""
    trace: list[str] = Field(default_factory=list)


class DashboardSnapshot(BaseModel):
    """Dashboard wire-format snapshot."""

    schema_version: str = "dashboard.snapshot.v1"
    step: int = 0
    mode: DashboardMode = "replay"
    generated_at: str = ""
    summary: DashboardSummary = Field(default_factory=DashboardSummary)
    stories: list[DashboardStory] = Field(default_factory=list)
    selected_story_id: str = ""
    navigator: list[DashboardNavigatorCell] = Field(default_factory=list)
    topology: DashboardTopology = Field(default_factory=DashboardTopology)
    bluf: DashboardBluf = Field(default_factory=DashboardBluf)
    source: DashboardSource = Field(default_factory=DashboardSource)
```

- [ ] **Step 4: Add coverage and builder helpers**

Append to `core/dashboard.py`:

```python
_ATTACK_COVERAGE = Path(__file__).resolve().parents[1] / "data" / "attack_coverage.yaml"


def _now_iso() -> str:
    """Return current UTC timestamp for snapshot metadata."""
    return datetime.now(UTC).isoformat()


def _report(state: SOCState) -> SOCReport | None:
    """Return SOC report from state if present."""
    return state.get("report")


def _tactic_from_report(report: SOCReport | None) -> str:
    """Extract current tactic from report MITRE mapping."""
    if report is None:
        return ""
    tactic = report.mitre.get("tactic", "")
    return tactic if isinstance(tactic, str) else ""


def _coverage_cells() -> list[DashboardNavigatorCell]:
    """Load tactic order and gap status from attack_coverage.yaml.

    Returns:
        Navigator cells in authoritative tactic order.
    """
    raw = yaml.safe_load(_ATTACK_COVERAGE.read_text(encoding="utf-8"))
    tactics = raw.get("tactics", []) if isinstance(raw, dict) else []
    cells: list[DashboardNavigatorCell] = []
    for item in tactics:
        if not isinstance(item, dict):
            continue
        name = item.get("name", "")
        order = item.get("order", 0)
        if not isinstance(name, str) or not isinstance(order, int):
            continue
        uncovered = item.get("uncovered", [])
        planned = item.get("planned", [])
        cells.append(
            DashboardNavigatorCell(
                tactic=name,
                order=order,
                gap=bool(uncovered) or bool(planned),
            )
        )
    cells.sort(key=lambda cell: cell.order)
    return cells


def _next_expected_tactic(report: SOCReport | None) -> str:
    """Return predicted next tactic from available report fields."""
    if report is None:
        return ""
    if report.staged_defenses:
        return report.staged_defenses[0].tactic
    if report.hunt_candidates:
        return str(report.hunt_candidates[0])
    if report.campaign_matches and report.campaign_matches[0].next_expected:
        scenario = report.campaign_matches[0].next_expected
        if "SATCOM" in scenario or "C2" in scenario:
            return "CommandAndControl"
        if "GNSS" in scenario or "SPOOF" in scenario:
            return "Collection"
        if "WEAPON" in scenario or "IMPACT" in scenario:
            return "Impact"
    return ""


def _build_story(state: SOCState, report: SOCReport | None) -> DashboardStory:
    """Build a single story card from the current SOC state."""
    alert = state["alert"]
    campaign = report.campaign_matches[0] if report and report.campaign_matches else None
    continuity = report.mission_continuity if report is not None else None
    approval = state.get("approval")
    hitl_status = "PENDING" if approval and approval.required and not approval.approved else "NOT_REQUIRED"
    actor = alert.actor_id or "UNKNOWN-ACTOR"
    tactic = _tactic_from_report(report) or str(alert.mitre.get("tactic", ""))
    return DashboardStory(
        story_id=actor,
        actor=actor,
        campaign_id=campaign.chain_id if campaign else "",
        campaign_name=campaign.name if campaign else "",
        matched=campaign.matched if campaign else 0,
        total=campaign.total if campaign else 0,
        next_expected=campaign.next_expected if campaign else "",
        target_asset=alert.asset_id,
        mission_impact=continuity.level if continuity else "UNKNOWN",
        hitl_status=hitl_status,
        alerts=[
            DashboardAlertRef(
                alert_id=alert.id,
                scenario_id=alert.scenario_id,
                title=alert.title,
                tactic=tactic,
                order=1,
            )
        ],
    )


def _build_navigator(report: SOCReport | None) -> list[DashboardNavigatorCell]:
    """Build UAV ATT&CK navigator cells for the selected story."""
    current = _tactic_from_report(report)
    predicted = _next_expected_tactic(report)
    cells = _coverage_cells()
    for cell in cells:
        if cell.tactic == current:
            cell.current = True
            cell.observed = True
            cell.observed_order = 1
        if cell.tactic == predicted:
            cell.predicted = True
        if cell.predicted and cell.gap:
            cell.note = "다음 예상 수순이 현재 미커버 전술입니다."
    return cells


def _build_bluf(state: SOCState, report: SOCReport | None, story: DashboardStory) -> DashboardBluf:
    """Build the BLUF staff advice card."""
    response = state.get("response")
    brief = report.commander_brief if report is not None else None
    continuity = report.mission_continuity if report is not None else None
    steps: list[str] = []
    if response is not None and response.cacao_steps:
        for step in response.cacao_steps[:2]:
            name = step.get("name", "")
            if isinstance(name, str) and name:
                steps.append(name)
    recommendation = " / ".join(steps) if steps else (report.action_taken if report else "")
    next_move = story.next_expected or "UNKNOWN"
    return DashboardBluf(
        situation=brief.bluf if brief is not None else f"{story.actor} -> {story.target_asset}",
        mission_impact=(
            f"{continuity.level}: {continuity.fallback}" if continuity else "UNKNOWN"
        ),
        recommendation=recommendation,
        next_move=next_move,
        confidence=brief.confidence if brief is not None else "unknown",
        hitl_badge=story.hitl_status,
        caveats=list(brief.caveats) if brief is not None else [],
    )


def _overlay_topology(
    topology: TopologyPolicy,
    report: SOCReport | None,
) -> DashboardTopology:
    """Overlay report mission continuity onto topology nodes."""
    view = topology.to_view_model()
    continuity = report.mission_continuity if report is not None else None
    if continuity is None:
        return view
    node_id = topology.node_for_degradation(continuity.asset_id)
    if node_id is None:
        return view
    active_nodes = {node_id}
    node_by_id = {node.id: node for node in view.nodes}
    if node_id in node_by_id:
        node_by_id[node_id].active = True
        node_by_id[node_id].status = continuity.level
    for edge in view.edges:
        if edge.source in active_nodes or edge.target in active_nodes:
            edge.active = True
    return view


def build_dashboard_snapshot(
    state: SOCState,
    *,
    step: int = 0,
    mode: DashboardMode = "replay",
    topology: TopologyPolicy | None = None,
) -> DashboardSnapshot:
    """Build a dashboard snapshot from one SOC state.

    Args:
        state: Completed or partial SOC state.
        step: Replay/live sequence number.
        mode: Snapshot source mode.
        topology: Optional preloaded topology policy.

    Returns:
        Dashboard snapshot view model.
    """
    report = _report(state)
    policy = topology or TopologyPolicy.from_yaml()
    story = _build_story(state, report)
    bluf = _build_bluf(state, report, story)
    decision = (
        report.decision_advantage.verdict
        if report is not None and report.decision_advantage is not None
        else "unknown"
    )
    trace = state.get("trace", [])
    alert = state["alert"]
    return DashboardSnapshot(
        step=step,
        mode=mode,
        generated_at=_now_iso(),
        summary=DashboardSummary(
            active_story_count=1,
            max_mission_impact=story.mission_impact,
            hitl_pending_count=1 if story.hitl_status == "PENDING" else 0,
            decision_advantage=decision,
        ),
        stories=[story],
        selected_story_id=story.story_id,
        navigator=_build_navigator(report),
        topology=_overlay_topology(policy, report),
        bluf=bluf,
        source=DashboardSource(
            alert_id=alert.id,
            scenario_id=alert.scenario_id,
            trace=list(trace),
        ),
    )
```

- [ ] **Step 5: Run tests and fix line length if needed**

Run:

```bash
pytest tests/__tests__/test_dashboard_snapshot.py -v
black core/dashboard.py tests/__tests__/test_dashboard_snapshot.py
ruff check core/dashboard.py tests/__tests__/test_dashboard_snapshot.py
mypy core/dashboard.py tests/__tests__/test_dashboard_snapshot.py
```

Expected: all PASS. If `ruff` reports long lines, split only the reported lines without changing behavior.

- [ ] **Step 6: Commit**

```bash
git add core/dashboard.py tests/__tests__/test_dashboard_snapshot.py
git commit -m "feat: build dashboard snapshots"
```

---

### Task 3: FastAPI Dashboard Server

**Files:**
- Modify: `pyproject.toml`
- Create: `app/dashboard.py`
- Test: `tests/__tests__/test_dashboard_app.py`

**Interfaces:**
- Consumes: `DashboardSnapshot`, `TopologyPolicy`
- Produces: `create_app(snapshot_dir: str | Path | None = None) -> FastAPI`
- Produces: `load_snapshots(snapshot_dir: Path) -> list[DashboardSnapshot]`
- Later tasks consume: `/`, `/api/snapshots`, `/api/topology`, `/events`

- [ ] **Step 1: Write failing FastAPI tests**

Create `tests/__tests__/test_dashboard_app.py`:

```python
"""Dashboard FastAPI app tests."""

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.dashboard import create_app


def _snapshot() -> dict[str, object]:
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
```

- [ ] **Step 2: Run tests to verify dependency/server failure**

Run:

```bash
pytest tests/__tests__/test_dashboard_app.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'fastapi'` or `No module named 'app.dashboard'`.

- [ ] **Step 3: Add FastAPI dependencies**

Modify `pyproject.toml` dependencies list by adding:

```toml
    # Dashboard API
    "fastapi>=0.115.0",
    "uvicorn>=0.30.0",
```

Place them after the HTTP / async comment block so dependency grouping remains readable.

- [ ] **Step 4: Add dashboard static placeholder**

Create directory `app/dashboard_static/` and file `app/dashboard_static/index.html`:

```html
<!doctype html>
<html lang="ko">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>UAV AI SOC Defense Dashboard</title>
  </head>
  <body>
    <main id="app">UAV AI SOC Defense Dashboard</main>
  </body>
</html>
```

- [ ] **Step 5: Implement FastAPI server**

Create `app/dashboard.py`:

```python
"""FastAPI dashboard server for replay and SSE snapshot delivery."""

from __future__ import annotations

from pathlib import Path
import json
from collections.abc import Iterator

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from core.dashboard import DashboardSnapshot, TopologyPolicy
from utils.logging import get_logger

_logger = get_logger("dashboard")
_STATIC_DIR = Path(__file__).resolve().parent / "dashboard_static"


def load_snapshots(snapshot_dir: Path) -> list[DashboardSnapshot]:
    """Load replay snapshots from a directory.

    Args:
        snapshot_dir: Directory containing dashboard snapshot JSON files.

    Returns:
        Valid snapshots sorted by filename. Invalid files are skipped and logged.
    """
    if not snapshot_dir.exists():
        return []
    snapshots: list[DashboardSnapshot] = []
    for path in sorted(snapshot_dir.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            snapshots.append(DashboardSnapshot.model_validate(raw))
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            _logger.warning("dashboard snapshot skipped path=%s error=%s", path, exc)
    return snapshots


def _sse_events(snapshot_dir: Path) -> Iterator[str]:
    """Yield replay snapshots as SSE events.

    Args:
        snapshot_dir: Replay snapshot directory.

    Yields:
        SSE event strings.
    """
    for snapshot in load_snapshots(snapshot_dir):
        data = snapshot.model_dump_json()
        yield f"event: snapshot\ndata: {data}\n\n"


def create_app(snapshot_dir: str | Path | None = None) -> FastAPI:
    """Create the dashboard FastAPI app.

    Args:
        snapshot_dir: Optional replay snapshot directory.

    Returns:
        Configured FastAPI app.
    """
    replay_dir = Path(snapshot_dir) if snapshot_dir is not None else Path("demo_snapshots")
    app = FastAPI(title="UAV AI SOC Defense Dashboard")
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="dashboard_static")

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        """Return dashboard HTML shell."""
        html = (_STATIC_DIR / "index.html").read_text(encoding="utf-8")
        return HTMLResponse(html)

    @app.get("/api/snapshots")
    async def snapshots() -> dict[str, list[dict[str, object]]]:
        """Return replay snapshots."""
        return {
            "snapshots": [
                snapshot.model_dump(mode="json")
                for snapshot in load_snapshots(replay_dir)
            ]
        }

    @app.get("/api/topology")
    async def topology() -> dict[str, object]:
        """Return static topology view model."""
        return TopologyPolicy.from_yaml().to_view_model().model_dump(mode="json")

    @app.get("/events")
    async def events() -> StreamingResponse:
        """Stream replay snapshots as SSE events."""
        return StreamingResponse(
            _sse_events(replay_dir),
            media_type="text/event-stream",
        )

    return app


app = create_app()
```

- [ ] **Step 6: Run focused verification**

Run:

```bash
pytest tests/__tests__/test_dashboard_app.py -v
black app/dashboard.py tests/__tests__/test_dashboard_app.py
ruff check app/dashboard.py tests/__tests__/test_dashboard_app.py
mypy app/dashboard.py tests/__tests__/test_dashboard_app.py
```

Expected: all PASS after installing updated dependencies if the environment is not already synced.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml app/dashboard.py app/dashboard_static/index.html tests/__tests__/test_dashboard_app.py
git commit -m "feat: serve dashboard snapshots"
```

---

### Task 4: Static Dashboard UI

**Files:**
- Modify: `app/dashboard_static/index.html`
- Create: `app/dashboard_static/dashboard.css`
- Create: `app/dashboard_static/dashboard.js`
- Test: `tests/__tests__/test_dashboard_static.py`

**Interfaces:**
- Consumes: `/api/snapshots`, `/api/topology`, `/events`
- Produces: DOM sections with ids `top-strip`, `story-rail`, `navigator`, `bluf-card`, `topology-map`, `replay-controls`

- [ ] **Step 1: Write static asset tests**

Create `tests/__tests__/test_dashboard_static.py`:

```python
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
    assert "new EventSource('/events')" in js
    assert "renderSnapshot" in js
    assert "selectStory" in js
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
pytest tests/__tests__/test_dashboard_static.py -v
```

Expected: FAIL because CSS/JS references and dashboard regions are missing.

- [ ] **Step 3: Replace HTML shell**

Replace `app/dashboard_static/index.html`:

```html
<!doctype html>
<html lang="ko">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>UAV AI SOC Defense Dashboard</title>
    <link rel="stylesheet" href="/static/dashboard.css" />
  </head>
  <body>
    <main class="dashboard-shell">
      <header class="top-strip" id="top-strip" aria-label="상태 요약"></header>
      <section class="workbench">
        <aside class="story-rail" id="story-rail" aria-label="진행 중 story"></aside>
        <section class="main-panel">
          <section class="navigator-panel">
            <div class="panel-title">UAV ATT&amp;CK Navigator</div>
            <div class="navigator-grid" id="navigator"></div>
          </section>
          <section class="bluf-card" id="bluf-card" aria-label="참모 조언"></section>
        </section>
      </section>
      <section class="topology-panel">
        <div class="panel-title">UAS Asset Topology</div>
        <div class="topology-map" id="topology-map"></div>
      </section>
      <footer class="replay-controls" id="replay-controls"></footer>
    </main>
    <script src="/static/dashboard.js" defer></script>
  </body>
</html>
```

- [ ] **Step 4: Add dark CSS**

Create `app/dashboard_static/dashboard.css`:

```css
:root {
  color-scheme: dark;
  --bg: #08111f;
  --panel: #101a2b;
  --panel-2: #14243a;
  --line: #2b3d58;
  --text: #e8eef7;
  --muted: #8da2bd;
  --good: #26d9a8;
  --warn: #f2c94c;
  --bad: #ef476f;
  --info: #4ea1ff;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--text);
  font-family:
    Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI",
    sans-serif;
  letter-spacing: 0;
}

.dashboard-shell {
  display: grid;
  grid-template-rows: auto minmax(360px, 1fr) minmax(180px, 26vh) auto;
  gap: 12px;
  min-height: 100vh;
  padding: 14px;
}

.top-strip,
.workbench,
.topology-panel,
.replay-controls {
  border: 1px solid var(--line);
  background: var(--panel);
}

.top-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(120px, 1fr));
  gap: 1px;
  overflow: hidden;
}

.metric {
  min-height: 64px;
  padding: 10px 12px;
  background: var(--panel-2);
}

.metric-label {
  color: var(--muted);
  font-size: 12px;
}

.metric-value {
  margin-top: 6px;
  font-size: 22px;
  font-weight: 700;
}

.workbench {
  display: grid;
  grid-template-columns: minmax(260px, 320px) 1fr;
  min-height: 0;
}

.story-rail {
  border-right: 1px solid var(--line);
  overflow: auto;
}

.story-card {
  width: 100%;
  padding: 12px;
  border: 0;
  border-bottom: 1px solid var(--line);
  background: transparent;
  color: var(--text);
  text-align: left;
  cursor: pointer;
}

.story-card.active {
  background: #183250;
  box-shadow: inset 3px 0 0 var(--info);
}

.story-title {
  display: flex;
  justify-content: space-between;
  gap: 8px;
  font-weight: 700;
}

.story-meta,
.alert-ref,
.bluf-row,
.node-meta {
  color: var(--muted);
  font-size: 12px;
  line-height: 1.45;
}

.badge {
  display: inline-flex;
  align-items: center;
  min-height: 22px;
  padding: 2px 7px;
  border: 1px solid var(--line);
  border-radius: 4px;
  font-size: 11px;
  color: var(--text);
}

.badge.pending,
.cell.gap {
  border-color: var(--warn);
  color: var(--warn);
}

.badge.abort {
  border-color: var(--bad);
  color: var(--bad);
}

.main-panel {
  display: grid;
  grid-template-rows: 1fr minmax(150px, auto);
  min-width: 0;
}

.navigator-panel,
.bluf-card,
.topology-panel {
  padding: 12px;
}

.navigator-panel {
  border-bottom: 1px solid var(--line);
}

.panel-title {
  margin-bottom: 10px;
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
}

.navigator-grid {
  display: grid;
  grid-template-columns: repeat(5, minmax(120px, 1fr));
  gap: 8px;
}

.cell {
  position: relative;
  min-height: 82px;
  padding: 9px;
  border: 1px solid var(--line);
  background: #0d1727;
}

.cell.current {
  border-color: var(--info);
}

.cell.observed {
  box-shadow: inset 0 3px 0 var(--good);
}

.cell.predicted {
  outline: 2px solid var(--warn);
}

.cell-title {
  font-size: 13px;
  font-weight: 700;
}

.cell-order {
  position: absolute;
  top: 6px;
  right: 7px;
  color: var(--good);
  font-size: 12px;
}

.bluf-card {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
}

.bluf-block {
  min-height: 106px;
  padding: 10px;
  border: 1px solid var(--line);
  background: #0d1727;
}

.bluf-label {
  margin-bottom: 7px;
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
}

.topology-map {
  display: grid;
  grid-template-columns: repeat(5, minmax(130px, 1fr));
  gap: 8px;
}

.node {
  min-height: 74px;
  padding: 9px;
  border: 1px solid var(--line);
  background: #0d1727;
}

.node.active {
  border-color: var(--warn);
  box-shadow: inset 0 3px 0 var(--warn);
}

.node.SUSTAINED {
  border-color: var(--good);
}

.node.MINIMAL {
  border-color: var(--warn);
}

.node.ABORT {
  border-color: var(--bad);
}

.node-title {
  font-size: 13px;
  font-weight: 700;
}

.replay-controls {
  display: flex;
  align-items: center;
  gap: 8px;
  min-height: 48px;
  padding: 8px 12px;
}

button.control {
  min-width: 38px;
  min-height: 32px;
  border: 1px solid var(--line);
  border-radius: 4px;
  background: var(--panel-2);
  color: var(--text);
  cursor: pointer;
}

.status-line {
  margin-left: auto;
  color: var(--muted);
  font-size: 12px;
}

@media (max-width: 900px) {
  .top-strip,
  .workbench,
  .bluf-card,
  .topology-map,
  .navigator-grid {
    grid-template-columns: 1fr;
  }

  .story-rail {
    border-right: 0;
    border-bottom: 1px solid var(--line);
    max-height: 260px;
  }
}
```

- [ ] **Step 5: Add vanilla JS renderer**

Create `app/dashboard_static/dashboard.js`:

```javascript
const state = {
  snapshots: [],
  index: 0,
  selectedStoryId: "",
  live: false,
};

function text(value) {
  return value === undefined || value === null || value === "" ? "UNKNOWN" : String(value);
}

function currentSnapshot() {
  return state.snapshots[state.index] || null;
}

function setHtml(id, html) {
  const el = document.getElementById(id);
  if (el) {
    el.innerHTML = html;
  }
}

function renderTopStrip(snapshot) {
  const summary = snapshot.summary || {};
  setHtml(
    "top-strip",
    `
      <div class="metric"><div class="metric-label">Active Stories</div><div class="metric-value">${text(summary.active_story_count)}</div></div>
      <div class="metric"><div class="metric-label">Max Mission Impact</div><div class="metric-value">${text(summary.max_mission_impact)}</div></div>
      <div class="metric"><div class="metric-label">HITL Pending</div><div class="metric-value">${text(summary.hitl_pending_count)}</div></div>
      <div class="metric"><div class="metric-label">Decision Margin</div><div class="metric-value">${text(summary.decision_advantage)}</div></div>
    `,
  );
}

function selectStory(storyId) {
  state.selectedStoryId = storyId;
  renderSnapshot(currentSnapshot());
}

function renderStoryRail(snapshot) {
  const stories = snapshot.stories || [];
  if (!state.selectedStoryId && snapshot.selected_story_id) {
    state.selectedStoryId = snapshot.selected_story_id;
  }
  if (stories.length === 0) {
    setHtml("story-rail", '<div class="story-card">No active stories</div>');
    return;
  }
  setHtml(
    "story-rail",
    stories
      .map((story) => {
        const active = story.story_id === state.selectedStoryId ? " active" : "";
        const pending = story.hitl_status === "PENDING" ? " pending" : "";
        const alerts = (story.alerts || [])
          .map((alert) => `<div class="alert-ref">${text(alert.alert_id)} · ${text(alert.scenario_id)} · ${text(alert.tactic)}</div>`)
          .join("");
        return `
          <button class="story-card${active}" onclick="selectStory('${story.story_id}')">
            <div class="story-title"><span>${text(story.story_id)}</span><span class="badge${pending}">${text(story.hitl_status)}</span></div>
            <div class="story-meta">Campaign ${text(story.campaign_id)} ${text(story.matched)}/${text(story.total)}</div>
            <div class="story-meta">Target ${text(story.target_asset)} · Impact ${text(story.mission_impact)}</div>
            ${alerts}
          </button>
        `;
      })
      .join(""),
  );
}

function renderNavigator(snapshot) {
  const cells = snapshot.navigator || [];
  if (cells.length === 0) {
    setHtml("navigator", '<div class="cell">No navigator data</div>');
    return;
  }
  setHtml(
    "navigator",
    cells
      .map((cell) => {
        const classes = ["cell"];
        if (cell.observed) classes.push("observed");
        if (cell.current) classes.push("current");
        if (cell.predicted) classes.push("predicted");
        if (cell.gap) classes.push("gap");
        return `
          <div class="${classes.join(" ")}">
            <div class="cell-title">${text(cell.tactic)}</div>
            ${cell.observed_order ? `<div class="cell-order">${cell.observed_order}</div>` : ""}
            <div class="story-meta">${cell.predicted ? "Predicted" : ""} ${cell.gap ? "Gap" : ""}</div>
            <div class="story-meta">${text(cell.note)}</div>
          </div>
        `;
      })
      .join(""),
  );
}

function renderBluf(snapshot) {
  const bluf = snapshot.bluf || {};
  setHtml(
    "bluf-card",
    `
      <div class="bluf-block"><div class="bluf-label">Situation</div><div>${text(bluf.situation)}</div><div class="bluf-row">${text(bluf.confidence)}</div></div>
      <div class="bluf-block"><div class="bluf-label">Mission Impact</div><div>${text(bluf.mission_impact)}</div></div>
      <div class="bluf-block"><div class="bluf-label">Recommendation</div><div>${text(bluf.recommendation)}</div><div class="bluf-row">${text(bluf.hitl_badge)}</div></div>
      <div class="bluf-block"><div class="bluf-label">Next Move</div><div>${text(bluf.next_move)}</div><div class="bluf-row">${(bluf.caveats || []).join(" / ")}</div></div>
    `,
  );
}

function renderTopology(snapshot) {
  const topology = snapshot.topology || { nodes: [] };
  const nodes = topology.nodes || [];
  if (nodes.length === 0) {
    setHtml("topology-map", '<div class="node">No topology data</div>');
    return;
  }
  setHtml(
    "topology-map",
    nodes
      .map((node) => {
        const classes = ["node", text(node.status)];
        if (node.active) classes.push("active");
        return `
          <div class="${classes.join(" ")}">
            <div class="node-title">${text(node.label)}</div>
            <div class="node-meta">${text(node.plane)} · ${text(node.kind)}</div>
            <div class="node-meta">${text(node.status)}</div>
          </div>
        `;
      })
      .join(""),
  );
}

function renderControls() {
  setHtml(
    "replay-controls",
    `
      <button class="control" onclick="previousSnapshot()">◀</button>
      <button class="control" onclick="nextSnapshot()">▶</button>
      <button class="control" onclick="connectLive()">LIVE</button>
      <span>Step ${state.index + 1} / ${state.snapshots.length || 0}</span>
      <span class="status-line">${state.live ? "SSE connected" : "Replay mode"}</span>
    `,
  );
}

function renderSnapshot(snapshot) {
  if (!snapshot) {
    setHtml("top-strip", '<div class="metric"><div class="metric-value">No replay snapshots loaded</div></div>');
    renderControls();
    return;
  }
  renderTopStrip(snapshot);
  renderStoryRail(snapshot);
  renderNavigator(snapshot);
  renderBluf(snapshot);
  renderTopology(snapshot);
  renderControls();
}

function previousSnapshot() {
  state.index = Math.max(0, state.index - 1);
  renderSnapshot(currentSnapshot());
}

function nextSnapshot() {
  state.index = Math.min(state.snapshots.length - 1, state.index + 1);
  renderSnapshot(currentSnapshot());
}

async function loadReplay() {
  const response = await fetch('/api/snapshots');
  const payload = await response.json();
  state.snapshots = payload.snapshots || [];
  state.index = 0;
  renderSnapshot(currentSnapshot());
}

function connectLive() {
  const events = new EventSource('/events');
  state.live = true;
  events.addEventListener('snapshot', (event) => {
    const snapshot = JSON.parse(event.data);
    state.snapshots.push(snapshot);
    state.index = state.snapshots.length - 1;
    renderSnapshot(snapshot);
  });
  events.onerror = () => {
    state.live = false;
    renderControls();
  };
}

window.selectStory = selectStory;
window.previousSnapshot = previousSnapshot;
window.nextSnapshot = nextSnapshot;
window.connectLive = connectLive;

loadReplay();
```

- [ ] **Step 6: Run tests and commit**

Run:

```bash
pytest tests/__tests__/test_dashboard_static.py tests/__tests__/test_dashboard_app.py -v
```

Expected: all PASS.

Commit:

```bash
git add app/dashboard_static/index.html app/dashboard_static/dashboard.css app/dashboard_static/dashboard.js tests/__tests__/test_dashboard_static.py
git commit -m "feat: add dashboard static UI"
```

---

### Task 5: Replay Snapshot Fixture Writer

**Files:**
- Modify: `core/dashboard.py`
- Create: `tests/__tests__/test_dashboard_replay.py`

**Interfaces:**
- Consumes: `build_dashboard_snapshot(...) -> DashboardSnapshot`
- Produces: `write_dashboard_snapshot(snapshot: DashboardSnapshot, directory: str | Path) -> Path`
- Later tasks and demo scripts can call this writer to emit replay files.

- [ ] **Step 1: Write failing replay writer test**

Create `tests/__tests__/test_dashboard_replay.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
pytest tests/__tests__/test_dashboard_replay.py -v
```

Expected: FAIL with `ImportError` for `write_dashboard_snapshot`.

- [ ] **Step 3: Add snapshot writer**

Append to `core/dashboard.py`:

```python
def write_dashboard_snapshot(snapshot: DashboardSnapshot, directory: str | Path) -> Path:
    """Write a dashboard snapshot JSON file for replay.

    Args:
        snapshot: Snapshot to write.
        directory: Output directory.

    Returns:
        Path to the written JSON file.

    Raises:
        OSError: Directory or file write fails.
    """
    output_dir = Path(directory)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{snapshot.step:03d}-dashboard.snapshot.json"
    path.write_text(
        snapshot.model_dump_json(indent=2),
        encoding="utf-8",
    )
    return path
```

- [ ] **Step 4: Run focused verification**

Run:

```bash
pytest tests/__tests__/test_dashboard_replay.py tests/__tests__/test_dashboard_snapshot.py -v
black core/dashboard.py tests/__tests__/test_dashboard_replay.py
ruff check core/dashboard.py tests/__tests__/test_dashboard_replay.py
mypy core/dashboard.py tests/__tests__/test_dashboard_replay.py
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add core/dashboard.py tests/__tests__/test_dashboard_replay.py
git commit -m "feat: write dashboard replay snapshots"
```

---

### Task 6: End-To-End Verification And Run Instructions

**Files:**
- Modify: `docs/demo-runbook-learning-loop.md`
- Test: existing dashboard tests

**Interfaces:**
- Consumes: `uvicorn app.dashboard:app`
- Produces: documented local run command and verification sequence

- [ ] **Step 1: Add runbook section**

Append to `docs/demo-runbook-learning-loop.md`:

```markdown

## 방어 대시보드 실행

대시보드는 `dashboard.snapshot.v1` JSON을 파일 리플레이 또는 SSE로 표시한다. 기본 리플레이
디렉터리는 `demo_snapshots/`다.

```bash
uvicorn app.dashboard:app --host 127.0.0.1 --port 8088
```

브라우저에서 `http://127.0.0.1:8088/`을 연다.

검증 포인트:

- 좌측은 alert 목록이 아니라 story 카드가 1급으로 표시된다.
- UAV ATT&CK navigator는 observed/current/predicted/gap 상태를 같은 matrix에 표시한다.
- BLUF 카드는 `SOCReport.commander_brief`의 confidence/caveat를 숨기지 않는다.
- topology는 `core/policy/asset-topology.yaml` 기준 UAS 자산 구성도를 표시한다.
- `LIVE` 버튼은 `/events` SSE snapshot을 같은 렌더 경로로 표시한다.
```

- [ ] **Step 2: Run full required automation**

Run:

```bash
black .
ruff check .
mypy .
pytest
```

Expected: all commands PASS. If a pre-existing unrelated failure appears, capture the exact failing test or type error and do not broaden dashboard scope.

- [ ] **Step 3: Optional manual server smoke**

Run:

```bash
uvicorn app.dashboard:app --host 127.0.0.1 --port 8088
```

Expected: server starts and logs Uvicorn startup. Open `http://127.0.0.1:8088/`; page renders the dark dashboard shell. Stop the server with `Ctrl-C` before ending the task.

- [ ] **Step 4: Commit**

```bash
git add docs/demo-runbook-learning-loop.md
git commit -m "docs: add dashboard run instructions"
```

---

## Self-Review Checklist

- Spec coverage:
  - Story-first UI: Task 2 model + Task 4 UI.
  - ATT&CK navigator: Task 2 builder + Task 4 UI.
  - BLUF card: Task 2 builder + Task 4 UI.
  - asset topology: Task 1 policy/loader + Task 4 UI.
  - replay and SSE common wire format: Task 3 server + Task 5 writer.
  - degraded behavior: Task 3 empty snapshot test, Task 2 fallback behavior, Task 4 empty UI states.
- Placeholder scan: no unresolved markers, "similar to", or unspecified implementation steps.
- Type consistency:
  - `TopologyPolicy.from_yaml()` returns `TopologyPolicy`.
  - `build_dashboard_snapshot()` returns `DashboardSnapshot`.
  - `write_dashboard_snapshot()` consumes `DashboardSnapshot`.
  - FastAPI endpoints return `model_dump(mode="json")` payloads matching the snapshot schema.
