"""Dashboard view models and deterministic snapshot builders.

The dashboard is a rendering layer. It reshapes authoritative SOC report fields
for a staff-facing UI and does not create new verdicts, severities, CAT labels,
or mission impact decisions.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError
import yaml

from core.cacao import scenario_tactic_map
from core.exceptions import PolicyError
from core.models import ApprovalResult, ResponseResult, SOCReport, SOCState

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


DashboardMode = Literal["replay", "live"]


class DashboardSummary(BaseModel):
    """Top strip summary values."""

    active_story_count: int = 0
    max_mission_impact: str = "UNKNOWN"
    hitl_pending_count: int = 0
    decision_advantage: str = "unknown"
    cpcon_level: int = 0


class DashboardAlertRef(BaseModel):
    """Alert reference nested under a story card."""

    alert_id: str
    scenario_id: str
    title: str = ""
    tactic: str = ""
    technique: str = ""
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
    decision_options: list[str] = Field(default_factory=list)
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


class TopologyNode(BaseModel):
    """Static topology node from policy."""

    id: str
    label: str
    plane: str
    kind: str = ""
    degradation_asset_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)

    @property
    def implementation_status(self) -> str:
        """Return explicit implementation status for the topology node."""
        status = self.metadata.get("implementation_status", "").strip().lower()
        if status:
            return status
        if self.id.endswith("-stub"):
            return "stub"
        return "enabled"


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
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"asset topology policy load failed: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError("asset topology policy must be a mapping")
        try:
            policy = cls.model_validate(raw)
        except ValidationError as exc:
            raise PolicyError(
                f"asset topology policy validation failed: {exc}"
            ) from exc
        policy._validate_references()
        return policy

    def _validate_references(self) -> None:
        """Validate edge and degradation-map node references.

        Raises:
            ValueError: Any reference points to an unknown node.
            PolicyError: Duplicate node ids are declared.
        """
        node_id_counts = Counter(node.id for node in self.nodes)
        duplicates = sorted(
            node_id for node_id, count in node_id_counts.items() if count > 1
        )
        if duplicates:
            raise PolicyError(f"duplicate topology node id(s): {', '.join(duplicates)}")

        node_ids = set(node_id_counts)
        for edge in self.edges:
            if edge.source not in node_ids or edge.target not in node_ids:
                raise ValueError(
                    "unknown topology edge endpoint: " f"{edge.source}->{edge.target}"
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

        def _metadata(node: TopologyNode) -> dict[str, str]:
            metadata = dict(node.metadata)
            if node.implementation_status == "stub":
                metadata.setdefault("implementation_status", "stub")
            return metadata

        return DashboardTopology(
            nodes=[
                DashboardNode(
                    id=node.id,
                    label=node.label,
                    plane=node.plane,
                    kind=node.kind,
                    status=(
                        "STUB" if node.implementation_status == "stub" else "UNKNOWN"
                    ),
                    metadata=_metadata(node),
                )
                for node in self.nodes
            ],
            edges=[
                DashboardEdge(source=edge.source, target=edge.target, kind=edge.kind)
                for edge in self.edges
            ],
        )


_ATTACK_COVERAGE = Path(__file__).resolve().parents[1] / "data" / "attack_coverage.yaml"
_COVERAGE_DEGRADED_CAVEAT = "Navigator degraded: coverage overlay unavailable."


def _now_iso() -> str:
    """Return current UTC timestamp for snapshot metadata."""
    return datetime.now(UTC).isoformat()


def _report(state: SOCState) -> SOCReport | None:
    """Return SOC report from state if present.

    Args:
        state: Current SOC pipeline state.

    Returns:
        SOC report when available, otherwise None.
    """
    if "report" not in state:
        return None
    return state["report"]


def _tactic_from_report(report: SOCReport | None) -> str:
    """Extract current tactic from report MITRE mapping.

    Args:
        report: Final SOC report.

    Returns:
        MITRE tactic string or an empty string when unavailable.
    """
    if report is None:
        return ""
    tactic = report.mitre.get("tactic", "")
    return tactic if isinstance(tactic, str) else ""


def _coverage_cells() -> list[DashboardNavigatorCell]:
    """Load tactic order and gap status from attack_coverage.yaml.

    Returns:
        Navigator cells in authoritative tactic order.

    Raises:
        PolicyError: Coverage policy cannot be read or parsed.
    """
    try:
        raw = yaml.safe_load(_ATTACK_COVERAGE.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"attack coverage load failed: {exc}") from exc
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
    """Return predicted next tactic from available report fields.

    Args:
        report: Final SOC report.

    Returns:
        Predicted next tactic string or empty string when unavailable.
    """
    if report is None:
        return ""
    for staged in report.staged_defenses:
        tactic = staged.tactic.strip()
        if tactic:
            return tactic
    if report.campaign_matches and report.campaign_matches[0].next_expected:
        return scenario_tactic_map().get(report.campaign_matches[0].next_expected, "")
    return ""


def _has_hitl_signal(value: str | None) -> bool:
    """Return whether a HITL string authoritatively signals requirement.

    Args:
        value: HITL-like status string from report or response.

    Returns:
        True when the value indicates HITL is required.
    """
    if value is None:
        return False
    normalized = value.strip().upper()
    if not normalized:
        return False
    return normalized in {"HITL_REQUIRED", "REQUIRED"}


def _hitl_status(
    approval: ApprovalResult | None,
    report: SOCReport | None,
    response: ResponseResult | None,
) -> str:
    """Build dashboard HITL status from authoritative requirement and approval.

    Args:
        approval: Approval state from the SOC pipeline when present.
        report: Final SOC report when available.
        response: Response output when available.

    Returns:
        HITL status for the story card and BLUF badge.
    """
    if approval is not None and approval.required:
        return "APPROVED" if approval.approved else "PENDING"
    if _has_hitl_signal(report.hitl if report is not None else None):
        return "REQUIRED"
    if _has_hitl_signal(response.hitl if response is not None else None):
        return "REQUIRED"
    return "NOT_REQUIRED"


def _build_story(state: SOCState, report: SOCReport | None) -> DashboardStory:
    """Build a single story card from the current SOC state.

    Args:
        state: Current SOC pipeline state.
        report: Final SOC report when available.

    Returns:
        One story card for the dashboard rail.
    """
    alert = state["alert"]
    campaign = None
    if report is not None and report.campaign_matches:
        campaign = report.campaign_matches[0]
    continuity = report.mission_continuity if report is not None else None
    approval = state["approval"] if "approval" in state else None
    response = state["response"] if "response" in state else None
    hitl_status = _hitl_status(approval, report, response)
    decision_options = (
        list(response.actions)
        if response is not None and hitl_status in {"PENDING", "REQUIRED"}
        else []
    )
    actor = alert.actor_id or "UNKNOWN-ACTOR"
    tactic = _tactic_from_report(report) or str(alert.mitre.get("tactic", ""))
    technique = str(alert.mitre.get("technique", ""))
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
        decision_options=decision_options,
        alerts=[
            DashboardAlertRef(
                alert_id=alert.id,
                scenario_id=alert.scenario_id,
                title=alert.title,
                tactic=tactic,
                technique=technique,
                order=1,
            )
        ],
    )


def _build_navigator(
    report: SOCReport | None,
) -> tuple[list[DashboardNavigatorCell], str | None]:
    """Build UAV ATT&CK navigator cells for the selected story.

    Args:
        report: Final SOC report.

    Returns:
        Ordered tactic cells with current/predicted/gap flags and an optional
        degradation caveat.
    """
    current = _tactic_from_report(report)
    predicted = _next_expected_tactic(report)
    try:
        cells = _coverage_cells()
    except PolicyError:
        return [], _COVERAGE_DEGRADED_CAVEAT
    for cell in cells:
        if cell.tactic == current:
            cell.current = True
            cell.observed = True
            cell.observed_order = 1
        if cell.tactic == predicted:
            cell.predicted = True
        if cell.predicted and cell.gap:
            cell.note = "다음 예상 수순이 현재 미커버 전술입니다."
    return cells, None


def _build_bluf(
    state: SOCState,
    report: SOCReport | None,
    story: DashboardStory,
    extra_caveats: list[str] | None = None,
) -> DashboardBluf:
    """Build the BLUF staff advice card.

    Args:
        state: Current SOC pipeline state.
        report: Final SOC report when available.
        story: Selected story card.

    Returns:
        BLUF card view model.
    """
    response = state["response"] if "response" in state else None
    brief = report.commander_brief if report is not None else None
    continuity = report.mission_continuity if report is not None else None
    steps: list[str] = []
    if response is not None and response.cacao_steps:
        for step in response.cacao_steps[:2]:
            name = step.get("name", "")
            if isinstance(name, str) and name:
                steps.append(name)
    if steps:
        recommendation = " / ".join(steps)
    elif report is not None:
        recommendation = report.recommended_action
    else:
        recommendation = ""
    next_move = story.next_expected or "UNKNOWN"
    return DashboardBluf(
        situation=(
            brief.bluf
            if brief is not None
            else f"{story.actor} -> {story.target_asset}"
        ),
        mission_impact=(
            f"{continuity.level}: {continuity.fallback}" if continuity else "UNKNOWN"
        ),
        recommendation=recommendation,
        next_move=next_move,
        confidence=brief.confidence if brief is not None else "unknown",
        hitl_badge=story.hitl_status,
        caveats=(list(brief.caveats) if brief is not None else [])
        + (extra_caveats or []),
    )


def _overlay_topology(
    topology: TopologyPolicy,
    report: SOCReport | None,
) -> DashboardTopology:
    """Overlay report mission continuity onto topology nodes.

    Args:
        topology: Static topology policy.
        report: Final SOC report when available.

    Returns:
        Dashboard topology with active mission-impact nodes highlighted.
    """
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
    cpcon_level: int = 0,
) -> DashboardSnapshot:
    """Build a dashboard snapshot from one SOC state.

    Args:
        state: Completed or partial SOC state.
        step: Replay/live sequence number.
        mode: Snapshot source mode.
        topology: Optional preloaded topology policy.
        cpcon_level: Global cyber posture level (1-5, 0 when unknown);
            callers pass settings.cyber_posture_level.

    Returns:
        Dashboard snapshot view model.
    """
    report = _report(state)
    policy = topology or TopologyPolicy.from_yaml()
    story = _build_story(state, report)
    navigator, navigator_caveat = _build_navigator(report)
    bluf = _build_bluf(
        state,
        report,
        story,
        extra_caveats=[navigator_caveat] if navigator_caveat else None,
    )
    decision = (
        report.decision_advantage.verdict
        if report is not None and report.decision_advantage is not None
        else "unknown"
    )
    trace = list(state["trace"]) if "trace" in state else []
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
            cpcon_level=cpcon_level,
        ),
        stories=[story],
        selected_story_id=story.story_id,
        navigator=navigator,
        topology=_overlay_topology(policy, report),
        bluf=bluf,
        source=DashboardSource(
            alert_id=alert.id,
            scenario_id=alert.scenario_id,
            trace=trace,
        ),
    )


def write_dashboard_snapshot(
    snapshot: DashboardSnapshot,
    directory: str | Path,
) -> Path:
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
    path.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
    return path
