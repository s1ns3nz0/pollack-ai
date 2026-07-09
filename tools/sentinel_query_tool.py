"""Sentinel/Log Analytics read-only query boundary for ActiveHuntAgent."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, runtime_checkable

from azure.identity.aio import DefaultAzureCredential
from azure.monitor.query.aio import LogsQueryClient
from pydantic import BaseModel, Field

from core.settings import Settings


class SentinelQueryResult(BaseModel):
    """Normalized Sentinel query result."""

    rows: list[dict[str, str]] = Field(default_factory=list)
    row_count: int = 0

    @classmethod
    def from_raw(
        cls, rows: Sequence[Mapping[str, object]], limit: int
    ) -> SentinelQueryResult:
        """Create normalized result from raw row mappings."""
        return cls(rows=normalize_rows(rows, limit), row_count=len(rows))


@runtime_checkable
class SentinelQueryClient(Protocol):
    """Read-only KQL query client contract."""

    async def aquery(self, kql: str, timeout_seconds: float) -> SentinelQueryResult:
        """Run a KQL query and return normalized rows."""
        ...


def normalize_rows(
    rows: Sequence[Mapping[str, object]], limit: int
) -> list[dict[str, str]]:
    """Stringify and bound raw rows for report-safe samples."""
    out: list[dict[str, str]] = []
    for row in rows[:limit]:
        out.append({str(k): "" if v is None else str(v) for k, v in row.items()})
    return out


class AzureMonitorSentinelQueryClient:
    """Azure Monitor Logs implementation of SentinelQueryClient.

    Args:
        settings: Settings with `sentinel_workspace_id`.
    """

    def __init__(self, settings: Settings) -> None:
        if not settings.sentinel_workspace_id:
            raise ValueError("SENTINEL_WORKSPACE_ID is required for active hunt")
        self._workspace_id = settings.sentinel_workspace_id
        self._credential = DefaultAzureCredential()
        self._client = LogsQueryClient(self._credential)

    async def aquery(self, kql: str, timeout_seconds: float) -> SentinelQueryResult:
        """Run KQL against the configured Log Analytics workspace."""
        response = await self._client.query_workspace(
            self._workspace_id,
            kql,
            timespan=None,
            server_timeout=int(timeout_seconds),
        )
        rows: list[dict[str, object]] = []
        for table in getattr(response, "tables", []):
            columns = [str(c) for c in table.columns]
            for raw_row in table.rows:
                rows.append(dict(zip(columns, raw_row, strict=False)))
        return SentinelQueryResult.from_raw(rows, limit=len(rows))
