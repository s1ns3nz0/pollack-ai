#!/usr/bin/env python3
"""KB 적재 — 로컬 `kb/` 문서를 RAGFlow 데이터셋에 업로드(+category 메타).

검색기(`RagflowRetrievalTool`)가 읽을 지식을 채운다. `kb/` 하위 폴더명이 곧
`KbCategory`(incident_cases/attack_techniques/standards/datasets)이며, 업로드 후 각
문서에 `category` 메타를 설정해 서버단 범주 필터를 가능하게 한다.

사용:  python scripts/ingest_kb.py [kb_root]   (기본 kb_root=./kb)
설정:  RAGFLOW_BASE_URL / RAGFLOW_API_TOKEN / RAGFLOW_DATASET_ID
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys

import httpx
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.exceptions import RagflowQueryError  # noqa: E402
from core.settings import Settings, get_settings  # noqa: E402
from tools.ragflow_tool import KbCategory  # noqa: E402
from utils.logging import get_logger  # noqa: E402

_logger = get_logger("ingest_kb")

# `kb/` 하위 폴더명 → 범주. 폴더명이 곧 메타데이터 category 값이다.
_CATEGORY_DIRS: dict[str, KbCategory] = {c.value: c for c in KbCategory}

# 적재 대상 문서 확장자.
_DOC_SUFFIXES = frozenset({".md", ".txt", ".pdf", ".json", ".csv"})


class IngestReport(BaseModel):
    """적재 결과 요약."""

    uploaded: int = 0
    skipped: int = 0
    failed: int = 0


def infer_category(path: Path, kb_root: Path) -> KbCategory | None:
    """문서 경로의 최상위 하위폴더로 범주를 추론한다(미매칭 시 None)."""
    rel = path.relative_to(kb_root)
    if len(rel.parts) < 2:
        return None
    return _CATEGORY_DIRS.get(rel.parts[0])


def iter_documents(kb_root: Path) -> list[tuple[Path, KbCategory]]:
    """`kb/` 하위에서 적재 가능한 (문서, 범주) 쌍을 수집한다."""
    out: list[tuple[Path, KbCategory]] = []
    for path in sorted(kb_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _DOC_SUFFIXES:
            continue
        category = infer_category(path, kb_root)
        if category is not None:
            out.append((path, category))
    return out


class _Ingestor:
    """RAGFlow 적재기 — 업로드 후 category 메타 설정(주입형 클라이언트)."""

    def __init__(
        self, settings: Settings, client_factory: object | None = None
    ) -> None:
        self._settings = settings
        self._client_factory = client_factory

    def _client(self) -> httpx.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory()  # type: ignore[operator,no-any-return]
        return httpx.AsyncClient(timeout=self._settings.ragflow_timeout_seconds)

    def _headers(self) -> dict[str, str]:
        token = self._settings.ragflow_api_token.get_secret_value()
        return {"Authorization": f"Bearer {token}"}

    def _docs_url(self) -> str:
        base = self._settings.ragflow_base_url.rstrip("/")
        return f"{base}/api/v1/datasets/{self._settings.ragflow_dataset_id}/documents"

    async def upload(
        self, client: httpx.AsyncClient, path: Path, category: KbCategory
    ) -> None:
        """문서 1건을 업로드하고 category 메타를 설정한다.

        Raises:
            RagflowQueryError: 업로드/메타설정 응답 검증 실패 시.
        """
        files = {"file": (path.name, path.read_bytes(), "application/octet-stream")}
        resp = await client.post(self._docs_url(), headers=self._headers(), files=files)
        resp.raise_for_status()
        body = resp.json()
        if not isinstance(body, dict) or body.get("code") != 0:
            raise RagflowQueryError(f"업로드 거부: {path.name}")
        doc_id = _first_doc_id(body)
        if doc_id is None:
            raise RagflowQueryError(f"업로드 응답에 문서 id 없음: {path.name}")
        await self._set_category(client, doc_id, category)

    async def _set_category(
        self, client: httpx.AsyncClient, doc_id: str, category: KbCategory
    ) -> None:
        url = f"{self._docs_url()}/{doc_id}"
        resp = await client.put(
            url,
            headers=self._headers(),
            json={"meta_fields": {"category": category.value}},
        )
        resp.raise_for_status()
        body = resp.json()
        if not isinstance(body, dict) or body.get("code") != 0:
            raise RagflowQueryError(f"메타 설정 거부: doc={doc_id}")


async def ingest(
    settings: Settings, kb_root: Path, client_factory: object | None = None
) -> IngestReport:
    """`kb/` 전체를 적재하고 결과 요약을 반환한다(개별 실패는 건너뜀)."""
    if not (
        settings.ragflow_api_token.get_secret_value() and settings.ragflow_dataset_id
    ):
        raise RagflowQueryError("RAGFlow 설정 누락(RAGFLOW_API_TOKEN/DATASET_ID).")
    docs = iter_documents(kb_root)
    report = IngestReport()
    ingestor = _Ingestor(settings, client_factory)
    async with ingestor._client() as client:
        for path, category in docs:
            try:
                await ingestor.upload(client, path, category)
                report.uploaded += 1
                _logger.info("적재: %s [%s]", path.name, category.value)
            except (httpx.HTTPError, RagflowQueryError, ValueError) as exc:
                report.failed += 1
                _logger.warning("적재 실패(건너뜀): %s (%s)", path.name, exc)
    return report


def _first_doc_id(body: dict[str, object]) -> str | None:
    """업로드 응답에서 첫 문서 id 를 추출한다."""
    data = body.get("data")
    items: object = data if isinstance(data, list) else None
    if isinstance(data, dict):
        items = data.get("docs") or data.get("documents")
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                return item["id"]
    return None


async def _main() -> int:
    kb_root = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "kb"
    if not kb_root.is_dir():
        _logger.error("kb 디렉토리 없음: %s", kb_root)
        return 1
    report = await ingest(get_settings(), kb_root)
    _logger.info("적재 완료: uploaded=%d failed=%d", report.uploaded, report.failed)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
