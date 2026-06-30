"""GraphRAG — KnowledgeGraph 적재·GraphRetriever 매칭·CompositeRetriever 병합."""

from pathlib import Path

import pytest

from core.exceptions import GraphRetrievalError
from core.models import RetrievedChunk
from tools.graph_retriever import (
    CompositeRetriever,
    GraphRetriever,
    KnowledgeGraph,
)

_SEED = """
techniques:
  T0830: {name: "Adversary-in-the-Middle", framework: "ICS"}
  T0815: {name: "Denial of View", framework: "ICS"}
scenarios:
  - id: S1
    name: "GNSS 스푸핑"
    asset: GNSS
    tier: T1
    severity: high
    techniques: [T0830, T0815]
    tactics: [Collection]
    signals: ["GNSS-INS 잔차 급증"]
    detection_rule: S1_GNSS_Spoofing
    watchlist: GNSS_Exception_List
    playbook: PB-NAV-RTB-01
  - id: S6
    name: "GCS 침해"
    asset: GCS
    tier: T1
    severity: high
    techniques: [T0830]
    tactics: [LateralMovement]
    signals: ["비정상 로그인"]
    detection_rule: S6_Operator_BruteForce
"""


def _graph(tmp_path: Path) -> KnowledgeGraph:
    p = tmp_path / "g.yaml"
    p.write_text(_SEED, encoding="utf-8")
    return KnowledgeGraph.from_yaml(p)


class TestGraphRetriever:
    @pytest.mark.asyncio
    async def test_matches_by_signal(self, tmp_path: Path) -> None:
        gr = GraphRetriever(_graph(tmp_path))
        out = await gr.aretrieve("GNSS-INS 잔차 급증 관측", k=5)
        assert out[0].source == "graph/S1"
        assert "T0830(Adversary-in-the-Middle)" in out[0].text

    @pytest.mark.asyncio
    async def test_matches_by_technique_id(self, tmp_path: Path) -> None:
        gr = GraphRetriever(_graph(tmp_path))
        out = await gr.aretrieve("T0830", k=5)
        sources = {c.source for c in out}
        assert sources == {"graph/S1", "graph/S6"}  # 둘 다 T0830 사용

    @pytest.mark.asyncio
    async def test_ranks_more_specific_higher(self, tmp_path: Path) -> None:
        gr = GraphRetriever(_graph(tmp_path))
        out = await gr.aretrieve("GNSS T0830 T0815 잔차", k=5)
        assert out[0].source == "graph/S1"  # 더 많은 매칭
        assert out[0].score >= out[-1].score

    @pytest.mark.asyncio
    async def test_no_match_empty(self, tmp_path: Path) -> None:
        gr = GraphRetriever(_graph(tmp_path))
        assert await gr.aretrieve("관련없는 질의 xyz", k=5) == []

    def test_bad_seed_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.yaml"
        p.write_text("scenarios: []", encoding="utf-8")  # 시나리오 없음
        with pytest.raises(GraphRetrievalError):
            KnowledgeGraph.from_yaml(p)


class _StubRetriever:
    def __init__(self, chunks: list[RetrievedChunk]) -> None:
        self._chunks = chunks

    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        return self._chunks


class _FailRetriever:
    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        from core.exceptions import RagflowQueryError

        raise RagflowQueryError("down")


class TestCompositeRetriever:
    @pytest.mark.asyncio
    async def test_merges_and_sorts(self, tmp_path: Path) -> None:
        flat = _StubRetriever([RetrievedChunk(text="a", source="kb/a", score=0.9)])
        graph = GraphRetriever(_graph(tmp_path))
        comp = CompositeRetriever([flat, graph])
        out = await comp.aretrieve("GNSS-INS 잔차 급증", k=5)
        sources = [c.source for c in out]
        assert "kb/a" in sources and "graph/S1" in sources
        # 점수 내림차순.
        assert out == sorted(out, key=lambda c: c.score, reverse=True)

    @pytest.mark.asyncio
    async def test_dedup_by_source_keeps_higher(self) -> None:
        r1 = _StubRetriever([RetrievedChunk(text="x", source="kb/a", score=0.3)])
        r2 = _StubRetriever([RetrievedChunk(text="x", source="kb/a", score=0.8)])
        out = await CompositeRetriever([r1, r2]).aretrieve("q", k=5)
        assert len(out) == 1
        assert out[0].score == 0.8

    @pytest.mark.asyncio
    async def test_failing_retriever_skipped(self, tmp_path: Path) -> None:
        graph = GraphRetriever(_graph(tmp_path))
        comp = CompositeRetriever([_FailRetriever(), graph])
        out = await comp.aretrieve("GNSS-INS 잔차 급증", k=5)
        assert any(c.source == "graph/S1" for c in out)  # 실패한 건 건너뜀
