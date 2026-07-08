"""테스트 데이터 생성기 — 스키마 일치·공격행 포함·POST URL/적재."""

import httpx
import pytest

from scripts.gen_table_testdata import (
    _GENERATORS,
    build_rows,
    post_rows,
    table_columns,
)


class TestBuildRows:
    @pytest.mark.parametrize("table", sorted(_GENERATORS))
    def test_rows_conform_to_schema(self, table: str) -> None:
        cols = table_columns(table)
        rows = build_rows(table, n_normal=10, n_attack=3)
        assert len(rows) == 13
        for r in rows:
            assert set(r) <= cols  # 스키마 밖 컬럼 없음
            assert "TimeGenerated" in r

    def test_counts(self) -> None:
        assert len(build_rows("UAVImagery_CL", 7, 2)) == 9


class TestAttackRowsPresent:
    def test_router_crc_spike(self) -> None:
        rows = build_rows("UAVRouterStats_CL", 20, 5)
        assert any(r["CrcErrors"] >= 1000 for r in rows)  # C2/프록시 신호

    def test_fileaudit_delete(self) -> None:
        rows = build_rows("UAVFileAudit_CL", 20, 5)
        assert any(r["Operation"] == "delete" for r in rows)  # 데이터 파괴

    def test_imagery_gap(self) -> None:
        rows = build_rows("UAVImagery_CL", 20, 5)
        assert any(r["EventType"] in {"gap", "degraded"} for r in rows)

    def test_gcs_foreign_ip(self) -> None:
        rows = build_rows("UAVGcsAccess_CL", 20, 5)
        assert any(r["ClientIp"] == "203.0.113.66" for r in rows)


class TestPost:
    def test_post_builds_stream_url(self) -> None:
        seen: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["auth"] = request.headers.get("Authorization")
            return httpx.Response(204)

        def factory() -> httpx.Client:
            return httpx.Client(transport=httpx.MockTransport(handler))

        rows = build_rows("UAVGcsAccess_CL", 2, 1)
        code = post_rows(
            "https://dce.example.com",
            "dcr-immutable-xyz",
            "tok123",
            "UAVGcsAccess_CL",
            rows,
            client_factory=factory,
        )
        assert code == 204
        assert "/dataCollectionRules/dcr-immutable-xyz/" in str(seen["url"])
        assert "streams/Custom-UAVGcsAccess_CL" in str(seen["url"])
        assert seen["auth"] == "Bearer tok123"
