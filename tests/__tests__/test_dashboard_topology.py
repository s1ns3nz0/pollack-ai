"""Dashboard topology policy tests."""

from pathlib import Path

import pytest

from core.dashboard import TopologyPolicy
from core.exceptions import PolicyError


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


def test_stub_nodes_are_explicitly_marked_in_view_model() -> None:
    """Dashboard must not present simulated integration nodes as fully enabled."""
    topology = TopologyPolicy.from_yaml().to_view_model()
    weapon = next(node for node in topology.nodes if node.id == "weapon-stub")

    assert weapon.status == "STUB"
    assert weapon.metadata["implementation_status"] == "stub"


def test_non_stub_nodes_default_to_policy_status() -> None:
    """Deployable nodes remain normal policy nodes, not implicit stubs."""
    topology = TopologyPolicy.from_yaml().to_view_model()
    av = next(node for node in topology.nodes if node.id == "av-muav")

    assert av.status == "UNKNOWN"
    assert av.metadata.get("implementation_status") != "stub"


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


def test_from_yaml_rejects_malformed_yaml(tmp_path: Path) -> None:
    """Broken YAML syntax is converted into PolicyError."""
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
    target: datalink-los
    kind: depends_on
degradation_map: {]
""",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="asset topology policy load failed"):
        TopologyPolicy.from_yaml(bad_policy)


def test_from_yaml_rejects_schema_validation_error(tmp_path: Path) -> None:
    """Invalid topology schema data is converted into PolicyError."""
    bad_policy = tmp_path / "asset-topology.yaml"
    bad_policy.write_text(
        """
version: 0.1
nodes:
  - id: av-muav
    plane: air
edges: []
degradation_map: {}
""",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="asset topology policy validation failed"):
        TopologyPolicy.from_yaml(bad_policy)


def test_from_yaml_rejects_duplicate_node_ids(tmp_path: Path) -> None:
    """Duplicate topology node ids are rejected."""
    bad_policy = tmp_path / "asset-topology.yaml"
    bad_policy.write_text(
        """
version: 0.1
nodes:
  - id: av-muav
    label: KUS-FS MUAV
    plane: air
  - id: av-muav
    label: Duplicate MUAV
    plane: air
edges: []
degradation_map: {}
""",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="duplicate topology node id"):
        TopologyPolicy.from_yaml(bad_policy)
