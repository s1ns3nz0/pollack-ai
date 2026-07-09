"""Sentinel query tool tests — Azure boundary stays thin and normalized."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from core.settings import Settings
from tools.sentinel_query_tool import (
    AzureMonitorSentinelQueryClient,
    SentinelQueryResult,
    normalize_rows,
)


@dataclass
class _FakeColumn:
    name: str


@dataclass
class _FakeTable:
    columns: list[_FakeColumn]
    rows: list[list[object]]


@dataclass
class _FakePartialError:
    message: str


@dataclass
class _FakeResponse:
    tables: list[_FakeTable] = field(default_factory=list)
    partial_data: _FakeResponse | None = None
    partial_error: object | None = None


@dataclass
class _FakeLogsClient:
    response: _FakeResponse
    calls: list[tuple[str, str, object, int]] = field(default_factory=list)
    closed: bool = False

    async def query_workspace(
        self,
        workspace_id: str,
        query: str,
        *,
        timespan: object,
        server_timeout: int,
    ) -> object:
        self.calls.append((workspace_id, query, timespan, server_timeout))
        return self.response

    async def close(self) -> None:
        self.closed = True


@dataclass
class _FakeCredential:
    closed: bool = False

    async def close(self) -> None:
        self.closed = True


def _settings() -> Settings:
    return Settings(sentinel_workspace_id="workspace-123")


def test_result_model_stringifies_sample_values() -> None:
    rows = normalize_rows([{"A": 1, "B": None, "C": True}], limit=20)
    assert rows == [{"A": "1", "B": "", "C": "True"}]


def test_result_model_applies_limit() -> None:
    rows = normalize_rows([{"A": index} for index in range(30)], limit=2)
    assert rows == [{"A": "0"}, {"A": "1"}]


def test_sentinel_query_result_counts_original_rows() -> None:
    result = SentinelQueryResult.from_raw([{"A": 1}, {"A": 2}], limit=1)
    assert result.row_count == 2
    assert result.rows == [{"A": "1"}]


def test_azure_client_requires_workspace_id() -> None:
    settings = Settings(sentinel_workspace_id="")
    with pytest.raises(ValueError, match="SENTINEL_WORKSPACE_ID"):
        AzureMonitorSentinelQueryClient(settings)


@pytest.mark.asyncio
async def test_azure_client_enforces_default_sample_cap() -> None:
    fake_client = _FakeLogsClient(
        response=_FakeResponse(
            tables=[
                _FakeTable(
                    columns=[_FakeColumn("A")],
                    rows=[[index] for index in range(25)],
                )
            ]
        )
    )
    client = AzureMonitorSentinelQueryClient(
        _settings(),
        logs_client=fake_client,
        credential=_FakeCredential(),
    )

    result = await client.aquery("StormEvents | take 25", timeout_seconds=5.0)

    assert result.row_count == 25
    assert len(result.rows) == 20
    assert result.rows[0] == {"A": "0"}
    assert result.rows[-1] == {"A": "19"}


@pytest.mark.asyncio
async def test_azure_client_returns_partial_data_and_error() -> None:
    fake_client = _FakeLogsClient(
        response=_FakeResponse(
            partial_data=_FakeResponse(
                tables=[
                    _FakeTable(
                        columns=[_FakeColumn("Computer"), _FakeColumn("Count")],
                        rows=[["uav-node-1", 3]],
                    )
                ]
            ),
            partial_error=_FakePartialError("partial query failure"),
        )
    )
    client = AzureMonitorSentinelQueryClient(
        _settings(),
        logs_client=fake_client,
        credential=_FakeCredential(),
    )

    result = await client.aquery("Heartbeat | summarize count() by Computer", 8.0)

    assert result.row_count == 1
    assert result.rows == [{"Computer": "uav-node-1", "Count": "3"}]
    assert result.error == "partial query failure"


@pytest.mark.asyncio
async def test_azure_client_normalizes_tables_and_propagates_timeout() -> None:
    fake_client = _FakeLogsClient(
        response=_FakeResponse(
            tables=[
                _FakeTable(
                    columns=[_FakeColumn("ClientIp"), _FakeColumn("Severity")],
                    rows=[["203.0.113.10", None]],
                )
            ]
        )
    )
    client = AzureMonitorSentinelQueryClient(
        _settings(),
        logs_client=fake_client,
        credential=_FakeCredential(),
    )

    result = await client.aquery("SigninLogs | take 1", timeout_seconds=12.7)

    assert result.rows == [{"ClientIp": "203.0.113.10", "Severity": ""}]
    assert fake_client.calls == [("workspace-123", "SigninLogs | take 1", None, 12)]


@pytest.mark.asyncio
async def test_azure_client_aclose_closes_client_and_credential() -> None:
    fake_logs_client = _FakeLogsClient(response=_FakeResponse())
    fake_credential = _FakeCredential()
    client = AzureMonitorSentinelQueryClient(
        _settings(),
        logs_client=fake_logs_client,
        credential=fake_credential,
    )

    await client.aclose()

    assert fake_logs_client.closed is True
    assert fake_credential.closed is True
