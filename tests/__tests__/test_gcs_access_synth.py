"""GCS 세션 emitter — 스키마 일치 + 공격 신호 발화 + POST 통로."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
from pydantic import ValidationError
import pytest

from scripts.gen_table_testdata import post_rows, table_columns
from sim_bridge.gcs_access_synth import (
    benign_session,
    brute_force_session,
    emit_stream,
    hijack_session,
    records_to_rows,
    synth_records,
)
from sim_bridge.models import GcsAccessRecord

TABLE = "UAVGcsAccess_CL"
SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "deploy" / "sentinel-tables" / f"{TABLE}.json"
)


def _schema_types() -> dict[str, str]:
    arm = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    cols = arm["resources"][0]["properties"]["schema"]["columns"]
    return {c["name"]: c["type"] for c in cols}


class TestSchemaConformance:
    def test_record_columns_equal_arm(self) -> None:
        record = benign_session(0)
        row = record.to_row()
        assert set(row.keys()) == set(table_columns(TABLE))

    def test_types_match_arm(self) -> None:
        row = benign_session(0).to_row()
        types = _schema_types()
        # datetime / string / long / real 만 사용 — pydantic 직렬화 후 기본 형 검사.
        assert isinstance(row["TimeGenerated"], str)  # ISO8601 string
        assert types["TimeGenerated"] == "datetime"
        for col in (
            "SessionId",
            "ClientIp",
            "Transport",
            "Operator",
            "Action",
            "UserAgent",
            "Result",
        ):
            assert isinstance(row[col], str)
            assert types[col] == "string"
        for col in ("BytesSent", "BytesReceived"):
            assert isinstance(row[col], int)
            assert types[col] == "long"
        assert isinstance(row["DurationSec"], float)
        assert types["DurationSec"] == "real"

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            GcsAccessRecord.model_validate({**benign_session(0).to_row(), "Extra": 1})


class TestAttackSignals:
    def test_hijack_external_ip_and_reused_session(self) -> None:
        row = hijack_session().to_row()
        assert row["ClientIp"] == "203.0.113.66"
        assert row["SessionId"] == "sess-1001"  # 정상 세션과 동일 ID 재사용
        assert int(row["BytesSent"]) >= 100 * 1024 * 1024  # Exfil 임계

    def test_brute_force_auth_fail(self) -> None:
        row = brute_force_session(0).to_row()
        assert row["Action"] == "auth"
        assert row["Result"] == "fail"


class TestSynthRecords:
    def test_default_counts_include_hijack(self) -> None:
        records = synth_records(benign_n=4, seed=1)
        assert len(records) == 5  # 4 정상 + 1 하이재킹

    def test_no_hijack_disables(self) -> None:
        records = synth_records(benign_n=4, include_hijack=False, seed=1)
        assert len(records) == 4
        assert all(r.client_ip != "203.0.113.66" for r in records)

    def test_brute_force_adds_three(self) -> None:
        records = synth_records(
            benign_n=4, include_hijack=False, include_brute_force=True, seed=1
        )
        assert sum(1 for r in records if r.result == "fail") == 3

    def test_seed_determinism(self) -> None:
        a = [r.to_row() for r in synth_records(benign_n=6, seed=42)]
        b = [r.to_row() for r in synth_records(benign_n=6, seed=42)]
        # ts 가 wall-clock 이라 다를 수 있어 비교에서 제외.
        for ra, rb in zip(a, b, strict=True):
            ra.pop("TimeGenerated")
            rb.pop("TimeGenerated")
            assert ra == rb


@pytest.mark.asyncio
async def test_emit_stream_yields_records() -> None:
    items = []
    async for record in emit_stream(benign_n=3, seed=7):
        items.append(record)
    assert len(items) == 4
    assert items[-1].client_ip == "203.0.113.66"  # 하이재킹 마지막


class TestPostIntegration:
    def test_post_uses_custom_stream_url(self) -> None:
        seen: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["body"] = request.read()
            return httpx.Response(204)

        def factory() -> httpx.Client:
            return httpx.Client(transport=httpx.MockTransport(handler))

        rows = records_to_rows(synth_records(benign_n=2, seed=3))
        code = post_rows(
            "https://dce.example.com",
            "dcr-xyz",
            "tok",
            TABLE,
            rows,
            client_factory=factory,
        )
        assert code == 204
        assert "streams/Custom-UAVGcsAccess_CL" in str(seen["url"])
        body = json.loads(seen["body"])  # type: ignore[arg-type]
        assert len(body) == 3  # 2 benign + 1 hijack
