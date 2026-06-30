"""GraphRAG — MITRE TTP 지식그래프 기반 결정론 검색.

팀의 시나리오↔MITRE 매핑(`data/mitre_attack_graph.yaml`)을 그래프로 적재해, 경보
신호/자산/기법ID 를 그래프 노드에 매칭하고 *이웃(기법·전술·룰·플레이북·워치리스트)*
까지 펼친 컨텍스트를 반환한다. LLM 추출 없이 큐레이션 그래프를 그대로 검색하므로
결정론·무환각이며(핫패스 LLM 회피 철학과 일치), 외부 서비스 없이 오프라인 동작한다.

평면 RAG(`RagflowRetrievalTool`)와 동일한 `RetrievedChunk` 계약을 반환하므로
Investigation 의 `ContextRetriever` 에 그대로 꽂히고, `CompositeRetriever` 로 둘을
합쳐 쓸 수 있다(그래프 구조 + 자유 텍스트 동시 활용).
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from pathlib import Path
import re
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field
import yaml

from core.exceptions import GraphRetrievalError, SOCPlatformError
from core.models import RetrievedChunk
from utils.logging import get_logger

_logger = get_logger("graph_retriever")

_TOKEN_RE = re.compile(r"[0-9a-z가-힣.]+")
_MIN_TOKEN = 3  # 이보다 짧은 토큰은 부분매칭에서 제외(노이즈 억제)


@runtime_checkable
class Retriever(Protocol):
    """컨텍스트 검색 계약(Investigation 의 ContextRetriever 와 구조 동일)."""

    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        """질의 관련 컨텍스트 청크를 반환한다."""
        ...


class Technique(BaseModel):
    """MITRE 기법 노드."""

    id: str
    name: str = ""
    framework: str = ""


class Scenario(BaseModel):
    """시나리오 노드(+이웃 엣지: 기법/전술/룰/플레이북/워치리스트/자산)."""

    id: str
    name: str = ""
    asset: str = ""
    tier: str = ""
    severity: str = ""
    kill_chain: str = ""
    techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)
    detection_rule: str | None = None
    sigma: str | None = None
    watchlist: str | None = None
    playbook: str | None = None


class KnowledgeGraph:
    """시나리오·기법 노드와 매칭 인덱스를 보유하는 TTP 지식그래프.

    Args:
        scenarios: 시나리오 노드 목록.
        techniques: 기법 ID→노드 매핑.
    """

    def __init__(
        self, scenarios: list[Scenario], techniques: dict[str, Technique]
    ) -> None:
        self.scenarios = scenarios
        self.techniques = techniques
        # 시나리오별 검색어 집합(소문자) — name/asset/signals/기법ID·이름/전술/룰.
        self._terms: dict[str, set[str]] = {
            s.id: self._scenario_terms(s) for s in scenarios
        }

    def _scenario_terms(self, s: Scenario) -> set[str]:
        terms: set[str] = {s.name, s.asset, s.severity, s.tier}
        terms.update(s.signals)
        terms.update(s.tactics)
        for opt in (s.detection_rule, s.sigma, s.watchlist, s.playbook):
            if opt:
                terms.add(opt)
        for tid in s.techniques:
            terms.add(tid)
            tech = self.techniques.get(tid)
            if tech and tech.name:
                terms.add(tech.name)
        return {t.lower() for t in terms if t}

    @classmethod
    def from_yaml(cls, path: str | Path) -> KnowledgeGraph:
        """YAML 그래프 씨앗을 적재한다.

        Raises:
            GraphRetrievalError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        p = Path(path)
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise GraphRetrievalError(f"그래프 씨앗 적재 실패: {exc}") from exc
        if not isinstance(raw, dict):
            raise GraphRetrievalError("그래프 씨앗 구조 검증 실패(최상위 dict 아님).")
        techniques = {
            tid: Technique(id=tid, **(meta if isinstance(meta, dict) else {}))
            for tid, meta in (raw.get("techniques") or {}).items()
        }
        scenarios = [
            Scenario.model_validate(s)
            for s in (raw.get("scenarios") or [])
            if isinstance(s, dict)
        ]
        if not scenarios:
            raise GraphRetrievalError("그래프 씨앗에 시나리오가 없음.")
        return cls(scenarios, techniques)

    def score(self, scenario_id: str, query_lower: str, q_tokens: set[str]) -> int:
        """질의와 시나리오 검색어의 매칭 수(부분/토큰 매칭)를 센다."""
        hits = 0
        for term in self._terms[scenario_id]:
            if term in query_lower:
                hits += 1
                continue
            if any(
                len(w) >= _MIN_TOKEN and w in q_tokens for w in _TOKEN_RE.findall(term)
            ):
                hits += 1
        return hits

    def neighborhood(self, s: Scenario) -> str:
        """시나리오의 그래프 이웃을 사람이 읽을 컨텍스트로 직렬화한다."""
        techs = ", ".join(
            f"{tid}({self.techniques[tid].name})" if tid in self.techniques else tid
            for tid in s.techniques
        )
        rule = s.detection_rule or s.sigma or "-"
        return (
            f"[{s.id} {s.name}] 자산:{s.asset}({s.tier}) 심각도:{s.severity}\n"
            f"기법: {techs}\n"
            f"전술: {', '.join(s.tactics) or '-'}\n"
            f"탐지룰: {rule} / 워치리스트: {s.watchlist or '-'} / "
            f"플레이북: {s.playbook or '-'}\n"
            f"신호: {', '.join(s.signals) or '-'}\n"
            f"킬체인: {s.kill_chain or '-'}"
        )


class GraphRetriever:
    """TTP 지식그래프 결정론 검색기(`Retriever` 계약).

    Args:
        graph: 적재된 지식그래프.
    """

    def __init__(self, graph: KnowledgeGraph) -> None:
        self._graph = graph

    @classmethod
    def from_yaml(cls, path: str | Path) -> GraphRetriever:
        """YAML 씨앗에서 검색기를 만든다."""
        return cls(KnowledgeGraph.from_yaml(path))

    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        """질의를 그래프 노드에 매칭해 이웃 펼침 컨텍스트를 반환한다(결정론).

        Args:
            query: 자연어 질의(경보 신호/자산/기법ID 등).
            k: 반환할 최대 청크 수.

        Returns:
            매칭 점수 내림차순의 `RetrievedChunk`(source=`graph/<시나리오ID>`).
        """
        q_lower = query.lower()
        q_tokens = {w for w in _TOKEN_RE.findall(q_lower) if len(w) >= _MIN_TOKEN}
        scored: list[tuple[int, Scenario]] = []
        for s in self._graph.scenarios:
            hits = self._graph.score(s.id, q_lower, q_tokens)
            if hits > 0:
                scored.append((hits, s))
        # 점수 내림차순, 동점은 시나리오 ID 로 안정 정렬.
        scored.sort(key=lambda x: (-x[0], x[1].id))
        chunks: list[RetrievedChunk] = []
        for hits, s in scored[:k]:
            chunks.append(
                RetrievedChunk(
                    text=self._graph.neighborhood(s),
                    source=f"graph/{s.id}",
                    score=round(min(1.0, 0.4 + 0.15 * hits), 3),
                )
            )
        _logger.info("graph 검색: query=%s hits=%d", query[:50], len(chunks))
        return chunks


class CompositeRetriever:
    """여러 검색기를 합쳐 결과를 병합한다(평면 RAG + 그래프 동시 활용).

    동시 검색 후 source 중복을 제거하고 점수 내림차순으로 상위 k 를 반환한다. 한
    검색기 실패는 건너뛰고 나머지로 계속한다(가용성).

    Args:
        retrievers: 합칠 검색기들.
    """

    def __init__(self, retrievers: Sequence[Retriever]) -> None:
        self._retrievers = list(retrievers)

    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        """모든 검색기를 동시 호출 후 병합·정렬해 상위 k 를 반환한다."""
        if not self._retrievers:
            return []
        results = await asyncio.gather(
            *(self._safe(r, query, k) for r in self._retrievers)
        )
        merged: dict[str, RetrievedChunk] = {}
        for chunks in results:
            for chunk in chunks:
                cur = merged.get(chunk.source)
                if cur is None or chunk.score > cur.score:
                    merged[chunk.source] = chunk
        ranked = sorted(merged.values(), key=lambda c: c.score, reverse=True)
        return ranked[:k]

    async def _safe(
        self, retriever: Retriever, query: str, k: int
    ) -> list[RetrievedChunk]:
        """한 검색기 호출. 실패 시 빈 목록으로 강등."""
        try:
            return await retriever.aretrieve(query, k)
        except SOCPlatformError as exc:
            _logger.warning(
                "검색기 실패, 건너뜀: %s (%s)", type(retriever).__name__, exc
            )
            return []
