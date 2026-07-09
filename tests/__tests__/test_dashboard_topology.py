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
