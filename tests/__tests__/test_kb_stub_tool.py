"""KbStubRetriever 단위 테스트 — 오프라인 결정론 RAG 스텁."""

import pytest

from core.models import RetrievedChunk
from tools.kb_stub_tool import KbStubRetriever


class TestKbStubRetriever:
    """kb/ 마크다운 기반 결정론 리트리버 테스트."""

    @pytest.fixture
    def retriever(self) -> KbStubRetriever:
        return KbStubRetriever()

    @pytest.mark.asyncio
    async def test_aretrieve_returns_trusted_kb_chunks(
        self, retriever: KbStubRetriever
    ) -> None:
        """관련 질의 시 kb/ 출처 청크 반환 확인 (신뢰 가드레일 통과 형식)."""
        chunks = await retriever.aretrieve("S1 GNSS 스푸핑 EKF 잔차", k=5)

        assert chunks, "관련 kb 문서가 있으므로 최소 1건 반환"
        for chunk in chunks:
            assert isinstance(chunk, RetrievedChunk)
            assert chunk.source.startswith("kb/")
            assert 0.0 <= chunk.score <= 1.0
            assert chunk.text.strip()

    @pytest.mark.asyncio
    async def test_aretrieve_respects_k_limit(self, retriever: KbStubRetriever) -> None:
        """k 상한 준수 확인."""
        chunks = await retriever.aretrieve("UAV", k=2)

        assert len(chunks) <= 2

    @pytest.mark.asyncio
    async def test_aretrieve_is_deterministic(self, retriever: KbStubRetriever) -> None:
        """동일 질의 반복 시 동일 결과(순서·점수) 확인 — CI 게이트 전제."""
        first = await retriever.aretrieve("GNSS 스푸핑", k=5)
        second = await retriever.aretrieve("GNSS 스푸핑", k=5)

        assert [(c.source, c.score) for c in first] == [
            (c.source, c.score) for c in second
        ]

    @pytest.mark.asyncio
    async def test_aretrieve_unrelated_query_returns_empty(
        self, retriever: KbStubRetriever
    ) -> None:
        """kb 와 무관한 질의는 빈 리스트 — 무근거 컨텍스트 주입 방지."""
        chunks = await retriever.aretrieve("zzz qqq 무관토큰 xyzzy", k=5)

        assert chunks == []

    @pytest.mark.asyncio
    async def test_relevant_doc_ranks_first(self, retriever: KbStubRetriever) -> None:
        """GNSS 질의 시 gnss-spoof 인시던트 문서가 최상위 확인."""
        chunks = await retriever.aretrieve("GNSS 스푸핑 EKF 잔차 PosHorizVariance", k=5)

        assert chunks
        assert "gnss" in chunks[0].source.lower()
