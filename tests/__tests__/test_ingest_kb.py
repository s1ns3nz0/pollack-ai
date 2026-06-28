"""KB 적재 — 범주 추론·수집 + RAGFlow 업로드 흐름(MockTransport)."""

from pathlib import Path

import httpx
from pydantic import SecretStr
import pytest

from core.settings import Settings
from scripts.ingest_kb import infer_category, ingest, iter_documents
from tools.ragflow_tool import KbCategory


def _make_kb(root: Path) -> None:
    (root / "incident_cases").mkdir(parents=True)
    (root / "attack_techniques").mkdir(parents=True)
    (root / "incident_cases" / "case1.md").write_text("사례", encoding="utf-8")
    (root / "attack_techniques" / "t0830.md").write_text("기법", encoding="utf-8")
    (root / "loose.md").write_text("범주없음", encoding="utf-8")  # 최상위 → 제외


class TestCategoryInference:
    def test_infer_from_subfolder(self, tmp_path: Path) -> None:
        _make_kb(tmp_path)
        cat = infer_category(tmp_path / "incident_cases" / "case1.md", tmp_path)
        assert cat == KbCategory.INCIDENT_CASES

    def test_top_level_file_has_no_category(self, tmp_path: Path) -> None:
        _make_kb(tmp_path)
        assert infer_category(tmp_path / "loose.md", tmp_path) is None

    def test_iter_collects_only_categorized(self, tmp_path: Path) -> None:
        _make_kb(tmp_path)
        docs = iter_documents(tmp_path)
        assert len(docs) == 2  # loose.md 제외
        cats = {c for _, c in docs}
        assert cats == {KbCategory.INCIDENT_CASES, KbCategory.ATTACK_TECHNIQUES}


class _FakeRagflow:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.uploads = 0
        self.meta_sets = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path.endswith("/documents"):
            self.uploads += 1
            if self.fail:
                return httpx.Response(200, json={"code": 1, "message": "no"})
            return httpx.Response(200, json={"code": 0, "data": [{"id": "doc-1"}]})
        if request.method == "PUT" and "/documents/" in path:
            self.meta_sets += 1
            return httpx.Response(200, json={"code": 0, "data": True})
        return httpx.Response(404, json={"code": 1})


def _settings() -> Settings:
    return Settings(ragflow_api_token=SecretStr("t"), ragflow_dataset_id="ds")


class TestIngest:
    @pytest.mark.asyncio
    async def test_uploads_each_and_sets_category(self, tmp_path: Path) -> None:
        _make_kb(tmp_path)
        fake = _FakeRagflow()

        def factory() -> httpx.AsyncClient:
            return httpx.AsyncClient(transport=httpx.MockTransport(fake.handler))

        report = await ingest(_settings(), tmp_path, client_factory=factory)
        assert report.uploaded == 2
        assert report.failed == 0
        assert fake.meta_sets == 2  # 각 문서에 category 메타 설정

    @pytest.mark.asyncio
    async def test_failures_are_counted_not_raised(self, tmp_path: Path) -> None:
        _make_kb(tmp_path)
        fake = _FakeRagflow(fail=True)

        def factory() -> httpx.AsyncClient:
            return httpx.AsyncClient(transport=httpx.MockTransport(fake.handler))

        report = await ingest(_settings(), tmp_path, client_factory=factory)
        assert report.uploaded == 0
        assert report.failed == 2

    @pytest.mark.asyncio
    async def test_missing_config_raises(self, tmp_path: Path) -> None:
        from core.exceptions import RagflowQueryError

        _make_kb(tmp_path)
        with pytest.raises(RagflowQueryError):
            await ingest(Settings(), tmp_path)
