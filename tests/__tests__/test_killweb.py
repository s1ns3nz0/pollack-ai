"""Mosaic/Kill Web — 커버리지 breadth 분류·정직성·scope·degrade."""

from core.killweb import KillWebBuilder
from tools.coverage import Archetype, CoverageMatrix, GapTechnique, TacticCoverage


def _tac(
    name: str, order: int, cov: int, unc: int = 0, plan: int = 0
) -> TacticCoverage:
    return TacticCoverage(
        name=name,
        order=order,
        covered=[f"T{name}{i}" for i in range(cov)],
        planned=[f"P{name}{i}" for i in range(plan)],
        uncovered=[
            GapTechnique(id=f"U{name}{i}", name="x", tactic=name, archetype="E")
            for i in range(unc)
        ],
    )


def _matrix(tactics: list[TacticCoverage]) -> CoverageMatrix:
    return CoverageMatrix(tactics, {"E": Archetype(id="E")})


class TestBuckets:
    def test_multi_single_uncovered_empty(self) -> None:
        m = _matrix(
            [
                _tac("Exec", 4, cov=2),  # multi
                _tac("Persist", 5, cov=1),  # single
                _tac("Impact", 15, cov=0, unc=3),  # uncovered
                _tac("Empty", 10, cov=0),  # empty(기법 0)
            ]
        )
        r = KillWebBuilder(m).resilience()
        assert r.multi_technique_stages == ["Exec"]
        assert r.single_technique_stages == ["Persist"]
        assert r.uncovered_stages == ["Impact"]
        assert r.empty_stages == ["Empty"]

    def test_planned_not_counted_as_covered(self) -> None:
        """planned 만 있는 단계는 covered 0 → uncovered(활성 탐지 아님)."""
        m = _matrix([_tac("X", 5, cov=0, plan=3)])
        r = KillWebBuilder(m).resilience()
        assert r.uncovered_stages == ["X"] and r.multi_technique_stages == []

    def test_breadth_ratio_excludes_empty(self) -> None:
        m = _matrix(
            [
                _tac("A", 4, cov=2),  # multi
                _tac("B", 5, cov=1),  # single
                _tac("C", 6, cov=0),  # empty(분모 제외)
            ]
        )
        r = KillWebBuilder(m).resilience()
        # in_scope = multi(1)+single(1)=2, ratio = 1/2 = 0.5.
        assert r.coverage_breadth_ratio == 0.5


class TestScope:
    def test_pre_compromise_excluded(self) -> None:
        """order ≤ 2(정찰·자원개발) breadth 분모·분류에서 제외."""
        m = _matrix(
            [
                _tac("Recon", 1, cov=2),  # order 1 — 제외
                _tac("ResDev", 2, cov=1),  # order 2 — 제외
                _tac("Exec", 4, cov=2),  # 범위내
            ]
        )
        r = KillWebBuilder(m).resilience()
        assert r.multi_technique_stages == ["Exec"]  # Recon 제외
        assert "ResDev" not in r.single_technique_stages
        assert r.coverage_breadth_ratio == 1.0  # 1 multi / 1 in-scope


class TestHonesty:
    def test_rationale_disclaims_sensor_independence(self) -> None:
        """기법 수 ≠ 독립 센서 명시(과장 금지, Codex Critical)."""
        r = KillWebBuilder(_matrix([_tac("X", 5, cov=1)])).resilience()
        assert any("독립 센서" in x for x in r.rationale)

    def test_ground_blind_surfaced(self) -> None:
        r = KillWebBuilder(_matrix([_tac("X", 5, cov=2)]), ground_blind=14).resilience()
        assert r.blind_surface_count == 14


class TestDegrade:
    def test_degraded_when_no_matrix(self) -> None:
        r = KillWebBuilder(None, degraded=True, degraded_reason="boom").resilience()
        assert r.degraded is True and r.degraded_reason == "boom"
        assert r.multi_technique_stages == []

    def test_load_default_ok(self) -> None:
        r = KillWebBuilder.load().resilience()
        assert r.degraded is False  # 기본 정책 로드됨

    def test_cytoscape_shape(self) -> None:
        m = _matrix([_tac("Exec", 4, cov=1, unc=1)])
        g = KillWebBuilder(m).to_cytoscape()
        assert "nodes" in g and "edges" in g
        kinds = [d["kind"] for n in g["nodes"] if isinstance(d := n["data"], dict)]
        assert "tactic" in kinds
        types = [d["type"] for e in g["edges"] if isinstance(d := e["data"], dict)]
        assert types and all(t == "belongs" for t in types)

    def test_cytoscape_empty_when_degraded(self) -> None:
        assert KillWebBuilder(None).to_cytoscape() == {"nodes": [], "edges": []}

    def test_cytoscape_dedups_shared_technique_node(self) -> None:
        """같은 기법이 여러 tactic 소속 → 노드 1개, belongs 엣지는 별개 id(Codex)."""
        t1 = TacticCoverage(name="A", order=4, covered=["Tshared"])
        t2 = TacticCoverage(name="B", order=5, covered=["Tshared"])
        g = KillWebBuilder(_matrix([t1, t2])).to_cytoscape()
        node_ids = [d["id"] for n in g["nodes"] if isinstance(d := n["data"], dict)]
        assert node_ids.count("technique:Tshared") == 1  # 노드 중복 제거
        edge_ids = [d["id"] for e in g["edges"] if isinstance(d := e["data"], dict)]
        assert len(edge_ids) == len(set(edge_ids))  # 엣지 id 고유
        assert "technique:Tshared->tactic:A:belongs" in edge_ids
