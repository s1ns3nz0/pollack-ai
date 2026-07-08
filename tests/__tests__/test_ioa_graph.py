"""IoA Graph Builder — actor/predictions/causal → Cytoscape JSON."""

from __future__ import annotations

from core.ioa_graph import IoAGraph, IoAGraphBuilder
from core.models import (
    ActorKillChainStep,
    ActorProfile,
    ActorTtpStat,
    AttackPrediction,
    CausalChain,
    CausalStep,
    InvestigationResult,
)


def _profile(
    actor_id: str = "team-red",
    is_explicit: bool = True,
    ttps: list[tuple[str, str, int]] | None = None,
    chain: list[str] | None = None,
) -> ActorProfile:
    stats = [
        ActorTtpStat(
            tactic=tac,
            technique=tech,
            count=cnt,
            last_seen="2026-07-02T00:00:00Z",
        )
        for (tac, tech, cnt) in (ttps or [])
    ]
    kill = [
        ActorKillChainStep(
            ts=f"2026-07-02T00:00:0{i}Z",
            alert_id=f"a{i}",
            scenario_id="s",
            technique=t,
        )
        for i, t in enumerate(chain or [])
    ]
    return ActorProfile(
        actor_id=actor_id,
        is_explicit=is_explicit,
        alert_count=sum(s.count for s in stats),
        ttp_stats=stats,
        kill_chain=kill,
    )


class TestActorGraph:
    def test_actor_and_techniques(self) -> None:
        profile = _profile(ttps=[("TA0002", "T1059", 3), ("TA0008", "T1021", 1)])
        graph = IoAGraphBuilder().build_from_actor(profile)
        node_ids = {n.id for n in graph.nodes}
        assert "actor:team-red" in node_ids
        assert "technique:T1059" in node_ids
        assert "tactic:TA0002" in node_ids
        # used_by 엣지 확인
        used_by = [e for e in graph.edges if e.type == "used_by"]
        assert len(used_by) == 2
        # belongs_to (technique → tactic)
        belongs = [e for e in graph.edges if e.type == "belongs_to"]
        assert {e.source for e in belongs} == {"technique:T1059", "technique:T1021"}

    def test_kill_chain_sequence_edges(self) -> None:
        profile = _profile(chain=["A", "B", "C"])
        graph = IoAGraphBuilder().build_from_actor(profile)
        seq = [e for e in graph.edges if e.type == "sequence"]
        assert len(seq) == 2  # A→B, B→C
        assert (seq[0].source, seq[0].target) == (
            "technique:A",
            "technique:B",
        )
        assert (seq[1].source, seq[1].target) == (
            "technique:B",
            "technique:C",
        )

    def test_kill_chain_creates_missing_technique_nodes(self) -> None:
        # ttp_stats 없이 kill_chain 만 있어도 노드 생성.
        profile = _profile(ttps=[], chain=["X", "Y"])
        graph = IoAGraphBuilder().build_from_actor(profile)
        ids = {n.id for n in graph.nodes}
        assert "technique:X" in ids
        assert "technique:Y" in ids


class TestPredictions:
    def test_predictions_attach_to_last_kill_chain(self) -> None:
        profile = _profile(chain=["A", "B"])
        inv = InvestigationResult(
            predictions=[
                AttackPrediction(
                    next_technique="C",
                    probability=0.8,
                    support_count=3,
                    basis_actor_id="team-red",
                )
            ]
        )
        graph = IoAGraphBuilder().build_from_state(profile, inv)
        pred_nodes = [n for n in graph.nodes if n.type == "prediction"]
        assert len(pred_nodes) == 1
        predicts = [e for e in graph.edges if e.type == "predicts"]
        assert predicts[0].source == "technique:B"  # kill_chain 마지막
        assert predicts[0].target.startswith("pred:")

    def test_predictions_attach_to_actor_if_no_chain(self) -> None:
        profile = _profile(chain=[])
        inv = InvestigationResult(
            predictions=[
                AttackPrediction(
                    next_technique="C",
                    probability=0.5,
                    support_count=3,
                    basis_actor_id="team-red",
                )
            ]
        )
        graph = IoAGraphBuilder().build_from_state(profile, inv)
        predicts = [e for e in graph.edges if e.type == "predicts"]
        assert predicts[0].source == "actor:team-red"


class TestCausal:
    def test_causal_chain_adds_effect_nodes(self) -> None:
        causal = CausalChain(
            steps=[
                CausalStep(
                    signal="s1", effect="e1", next_step="e2", mitre_technique="T1"
                ),
                CausalStep(
                    signal="s2", effect="e2", next_step="", mitre_technique="T2"
                ),
            ]
        )
        graph = IoAGraphBuilder().build_from_state(None, None, causal)
        effects = [n for n in graph.nodes if n.type == "effect"]
        assert {n.label for n in effects} == {"e1", "e2"}
        causal_edges = [e for e in graph.edges if e.type == "causal"]
        # T1→e1, T2→e2, e1→e2
        assert len(causal_edges) == 3

    def test_causal_creates_technique_if_missing(self) -> None:
        causal = CausalChain(
            steps=[
                CausalStep(signal="s", effect="e", next_step="", mitre_technique="T999")
            ]
        )
        graph = IoAGraphBuilder().build_from_state(None, None, causal)
        ids = {n.id for n in graph.nodes}
        assert "technique:T999" in ids


class TestCytoscapeSerialization:
    def test_to_cytoscape_shape(self) -> None:
        profile = _profile(ttps=[("TA0002", "T1059", 2)])
        graph = IoAGraphBuilder().build_from_actor(profile)
        data = graph.to_cytoscape()
        assert "nodes" in data and "edges" in data
        # 각 노드는 data 래핑
        for n in data["nodes"]:
            assert "data" in n
            node_data = n["data"]
            assert isinstance(node_data, dict)
            assert "id" in node_data and "type" in node_data
        # edges 도 id 자동 생성
        for e in data["edges"]:
            assert "data" in e
            edge_data = e["data"]
            assert isinstance(edge_data, dict)
            assert "id" in edge_data

    def test_empty_graph_returns_empty_arrays(self) -> None:
        empty = IoAGraph()
        data = empty.to_cytoscape()
        assert data == {"nodes": [], "edges": []}


class TestEdgeDedupe:
    def test_same_edge_added_once(self) -> None:
        profile = _profile(ttps=[("TA0002", "T1059", 1), ("TA0002", "T1059", 1)])
        # ttp_stats 는 중복 X, count 만 누적된다 가정 — used_by 는 unique.
        graph = IoAGraphBuilder().build_from_actor(profile)
        used = [
            e
            for e in graph.edges
            if e.type == "used_by" and e.target == "technique:T1059"
        ]
        # 두 stat 이므로 두 개 add 시도 — dedupe 로 1개
        # 하지만 count 는 첫 값 유지 (attrs 는 첫 add 우선, edge dedupe)
        assert len(used) == 1
