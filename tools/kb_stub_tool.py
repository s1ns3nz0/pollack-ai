"""오프라인 결정론 KB 리트리버 스텁 — RAGFlow 부재 시 Investigation 대체 주입.

레포에 커밋된 `kb/**/*.md` 를 그대로 읽어 토큰 겹침 점수로 상위 k 청크를 돌려준다.
목적은 검색 품질 근사가 아니라 **결정론**: 같은 질의 → 같은 청크·같은 점수. 오프라인
KPI 벤치마크(`benchmarks/run_kpi.py`)와 CI 게이트가 재현 가능해야 하기 때문.
출처는 `kb/<상대경로>` 로 정규화되어 Investigation 의 신뢰 출처 가드레일을 통과한다.
"""

from __future__ import annotations

from pathlib import Path
import re

from core.models import RetrievedChunk
from utils.logging import get_logger

_logger = get_logger("kb_stub_tool")

# 유니코드 단어 토큰(한글 포함). 대소문자 무시.
_TOKEN_RE = re.compile(r"\w+", re.UNICODE)

# 청크 본문 상한 — Investigation 요약 입력 폭주 방지.
_MAX_CHUNK_CHARS = 1200


def _tokenize(text: str) -> set[str]:
    """소문자 유니코드 단어 토큰 집합을 반환한다.

    Args:
        text: 원문 텍스트.

    Returns:
        중복 제거된 소문자 토큰 집합.
    """
    return {tok.lower() for tok in _TOKEN_RE.findall(text)}


class KbStubRetriever:
    """`kb/` 마크다운 기반 결정론 ContextRetriever 구현.

    초기화 시 kb 문서를 한 번 스캔·토큰화해 메모리에 든다(문서 수 적음).
    점수 = |질의 토큰 ∩ 문서 토큰| / |질의 토큰| (0.0~1.0). 겹침 0 은 제외 —
    무근거 컨텍스트 주입 방지. 정렬은 (점수 내림, 출처 오름) 으로 결정론 보장.
    """

    backend = "kb-stub"

    def __init__(self, kb_dir: Path | None = None) -> None:
        """kb 문서를 스캔해 인덱스를 구성한다.

        Args:
            kb_dir: kb 루트 디렉토리. 생략 시 레포 루트의 `kb/`.
        """
        root = kb_dir or Path(__file__).resolve().parents[1] / "kb"
        self._docs: list[tuple[str, str, set[str]]] = []
        for path in sorted(root.rglob("*.md")):
            text = path.read_text(encoding="utf-8")
            source = f"kb/{path.relative_to(root).as_posix()}"
            self._docs.append((source, text, _tokenize(text)))
        _logger.debug("KB 스텁 인덱스 구성: %d개 문서 (%s)", len(self._docs), root)

    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        """질의 토큰 겹침 상위 k 문서를 청크로 반환한다.

        Args:
            query: 검색 질의(시나리오 id·제목·신호 연접).
            k: 반환 청크 수 상한.

        Returns:
            점수 내림차순 청크 목록. 겹치는 문서가 없으면 빈 리스트.
        """
        q_tokens = _tokenize(query)
        if not q_tokens:
            return []
        scored: list[tuple[float, str, str]] = []
        for source, text, doc_tokens in self._docs:
            overlap = len(q_tokens & doc_tokens)
            if overlap == 0:
                continue
            score = round(overlap / len(q_tokens), 3)
            scored.append((score, source, text))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [
            RetrievedChunk(
                text=text[:_MAX_CHUNK_CHARS],
                source=source,
                score=score,
            )
            for score, source, text in scored[:k]
        ]
