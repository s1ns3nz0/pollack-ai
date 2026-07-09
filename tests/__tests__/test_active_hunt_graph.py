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


def test_active_hunt_enabled_wires_node_between_investigation_and_validation() -> None:
    graph = build_soc_graph(
        settings=Settings(active_hunt_enabled=True, sentinel_workspace_id="ws-test")
    )
    drawn = graph.get_graph()
    edges = {(edge.source, edge.target) for edge in drawn.edges}
    assert "active_hunt" in drawn.nodes
    assert ("investigation", "active_hunt") in edges
    assert ("active_hunt", "validation") in edges
    assert ("investigation", "validation") not in edges
