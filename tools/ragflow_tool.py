"""RAGFlow 지식베이스 검색 도구.

로컬 RAGFlow(`/api/v1/retrieval`)를 LangChain `BaseTool` 로 래핑한다. UAV 보안
도메인 지식(incident case, MITRE ATT&CK for ICS, IEC 62443 대응 템플릿, 데이터셋
실측 분석)을 비동기로 검색하며, 결과 청크의 출처를 `kb/<문서명>` 으로 정규화해
Investigation Agent 의 출처 가드레일(신뢰 출처 `kb/` 만 채택)을 통과시킨다.

GraphRAG(Azure) 로 교체하더라도 Agent 계층은 동일한 `RetrievedChunk` 계약만
의존하므로 이 도구만 갈아끼우면 된다.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

import httpx
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from core.exceptions import RagflowQueryError
from core.models import RetrievedChunk
from core.settings import Settings, get_settings
from utils.logging import get_logger

if TYPE_CHECKING:
    from langchain_core.callbacks import (
        AsyncCallbackManagerForToolRun,
        CallbackManagerForToolRun,
    )

_logger = get_logger("ragflow_tool")


class KbCategory(StrEnum):
    """KB 데이터 구성도 범주(문서 메타데이터 `category`)."""

    INCIDENT_CASES = "incident_cases"
    ATTACK_TECHNIQUES = "attack_techniques"
    STANDARDS = "standards"
    DATASETS = "datasets"


class RagflowQueryInput(BaseModel):
    """RAGFlow 검색 도구 입력 스키마."""

    query: str = Field(..., description="검색 질의 문자열.")
    k: int = Field(default=5, gt=0, le=50, description="반환할 청크 수.")
    category: KbCategory | None = Field(
        default=None,
        description="검색 범주 한정(미지정 시 전체 KB 검색).",
    )


class RagflowRetrievalTool(BaseTool):
    """RAGFlow 지식베이스에서 UAV 보안 컨텍스트를 검색하는 비동기 도구.

    Attributes:
        settings: RAGFlow 접속/검색 설정. 미지정 시 환경변수에서 로드.
    """

    name: str = "ragflow_retrieval"
    description: str = (
        "UAV/GPS/네트워크/OT 보안 지식베이스에서 질의와 관련된 사례·기법·대응 "
        "템플릿을 검색한다. 입력은 자연어 질의, 출력은 출처가 표기된 컨텍스트 청크."
    )
    args_schema: type[BaseModel] = RagflowQueryInput
    settings: Settings = Field(default_factory=get_settings)

    def _make_client(self) -> httpx.AsyncClient:
        """검색에 사용할 비동기 HTTP 클라이언트를 생성한다(테스트에서 주입 가능)."""
        return httpx.AsyncClient(timeout=self.settings.ragflow_timeout_seconds)

    async def aretrieve(
        self, query: str, k: int = 5, category: KbCategory | None = None
    ) -> list[RetrievedChunk]:
        """질의에 대한 컨텍스트 청크를 검색한다(타입 안전 API).

        Args:
            query: 검색 질의 문자열.
            k: 반환할 최대 청크 수.
            category: 지정 시 해당 범주 문서로만 검색을 한정한다(서버단
                metadata 필터). 미지정이면 전체 KB 검색.

        Returns:
            유사도 내림차순의 `RetrievedChunk` 목록. 결과가 없으면 빈 목록.

        Raises:
            RagflowQueryError: 네트워크 오류, 비정상 응답, 인증 실패 시.
        """
        if (
            not self.settings.ragflow_api_token.get_secret_value()
            or not self.settings.ragflow_dataset_id
        ):
            raise RagflowQueryError(
                "RAGFlow 설정이 비어 있습니다(RAGFLOW_API_TOKEN/RAGFLOW_DATASET_ID)."
            )

        payload: dict[str, object] = {
            "question": query,
            "dataset_ids": [self.settings.ragflow_dataset_id],
            "page": 1,
            "page_size": k,
            "similarity_threshold": self.settings.ragflow_similarity_threshold,
            "vector_similarity_weight": self.settings.ragflow_vector_weight,
            "top_k": self.settings.ragflow_top_k,
        }
        if category is not None:
            payload["metadata_condition"] = {
                "logic": "and",
                "conditions": [
                    {
                        "name": "category",
                        "comparison_operator": "is",
                        "value": category.value,
                    }
                ],
            }
        token = self.settings.ragflow_api_token.get_secret_value()
        headers = {"Authorization": f"Bearer {token}"}

        try:
            async with self._make_client() as client:
                response = await client.post(
                    self.settings.ragflow_retrieval_url, json=payload, headers=headers
                )
                response.raise_for_status()
                body = response.json()
        except httpx.TimeoutException as exc:
            raise RagflowQueryError(f"RAGFlow 검색 타임아웃: {query[:50]}") from exc
        except httpx.HTTPStatusError as exc:
            raise RagflowQueryError(
                f"RAGFlow HTTP 오류 {exc.response.status_code}"
            ) from exc
        except httpx.HTTPError as exc:
            raise RagflowQueryError(f"RAGFlow 연결 오류: {exc}") from exc
        except ValueError as exc:
            raise RagflowQueryError("RAGFlow 응답 JSON 파싱 실패") from exc

        if body.get("code") != 0:
            raise RagflowQueryError(f"RAGFlow API 오류 응답: {body.get('message')}")

        return self._parse_chunks(body, k)

    @staticmethod
    def _parse_chunks(body: dict[str, object], k: int) -> list[RetrievedChunk]:
        """RAGFlow 응답 본문을 `RetrievedChunk` 목록으로 변환한다."""
        data = body.get("data")
        raw_chunks: list[dict[str, object]] = []
        if isinstance(data, dict):
            candidate = data.get("chunks")
            if isinstance(candidate, list):
                raw_chunks = [c for c in candidate if isinstance(c, dict)]

        chunks: list[RetrievedChunk] = []
        for chunk in raw_chunks[:k]:
            doc = chunk.get("document_keyword") or chunk.get("docnm_kwd") or "unknown"
            content = chunk.get("content")
            similarity = chunk.get("similarity")
            chunks.append(
                RetrievedChunk(
                    text=str(content).strip() if content is not None else "",
                    source=f"kb/{doc}",
                    score=(
                        float(similarity)
                        if isinstance(similarity, (int, float))
                        else 0.0
                    ),
                )
            )
        return chunks

    async def _arun(
        self,
        query: str,
        k: int = 5,
        category: KbCategory | None = None,
        run_manager: AsyncCallbackManagerForToolRun | None = None,
    ) -> str:
        """LangChain 비동기 진입점. 검색 결과를 사람이 읽을 텍스트로 반환한다."""
        del run_manager  # 추적 콜백 미사용
        chunks = await self.aretrieve(query, k, category)
        _logger.info(
            "ragflow 검색: query=%s, category=%s, hits=%d",
            query[:60],
            category.value if category else "all",
            len(chunks),
        )
        if not chunks:
            return "관련 컨텍스트를 찾지 못했습니다."
        return "\n\n".join(f"[{c.score:.3f}] {c.source}\n{c.text}" for c in chunks)

    def _run(
        self,
        query: str,
        k: int = 5,
        category: KbCategory | None = None,
        run_manager: CallbackManagerForToolRun | None = None,
    ) -> str:
        """동기 진입점은 지원하지 않는다(비동기 전용 도구)."""
        del query, k, category, run_manager
        raise NotImplementedError(
            "RagflowRetrievalTool 은 비동기 전용입니다. ainvoke() 를 사용하세요."
        )
