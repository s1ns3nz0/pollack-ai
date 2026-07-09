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
