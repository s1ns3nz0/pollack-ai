"""Sentinel/Log Analytics read-only query boundary for ActiveHuntAgent."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from inspect import isawaitable
from typing import Protocol, cast, runtime_checkable

from azure.core.credentials_async import AsyncTokenCredential
from azure.identity.aio import DefaultAzureCredential
from azure.monitor.query.aio import LogsQueryClient
from pydantic import BaseModel, Field

from core.settings import Settings

DEFAULT_SAMPLE_LIMIT = 20


class SentinelQueryResult(BaseModel):
    """Normalized Sentinel query result."""

    rows: list[dict[str, str]] = Field(default_factory=list)
    row_count: int = 0
    error: str = ""

    @classmethod
    def from_raw(
        cls,
        rows: Sequence[Mapping[str, object]],
        limit: int = DEFAULT_SAMPLE_LIMIT,
        error: str = "",
    ) -> SentinelQueryResult:
        """Create a normalized result from raw row mappings.

        Args:
            rows: Raw row mappings to normalize for downstream use.
            limit: Maximum number of sample rows to retain in the result.
            error: Optional error string returned with the sampled rows.

        Returns:
            SentinelQueryResult: Normalized result with full row count preserved.
        """

        return cls(rows=normalize_rows(rows, limit), row_count=len(rows), error=error)


@runtime_checkable
class SentinelQueryClient(Protocol):
    """Read-only KQL query client contract."""

    async def aquery(self, kql: str, timeout_seconds: float) -> SentinelQueryResult:
        """Run a KQL query and return normalized rows.

        Args:
            kql: KQL query string to execute.
            timeout_seconds: Server-side timeout in seconds.

        Returns:
            SentinelQueryResult: Normalized query result.
        """


class SupportsAsyncClose(Protocol):
    """Protocol for async closeable Azure helpers."""

    async def close(self) -> None:
        """Release resources held by the object.

        Returns:
            None: Returned when the object is closed.
        """


class LogsQueryClientLike(Protocol):
    """Subset of LogsQueryClient used by the Sentinel boundary."""

    async def query_workspace(
        self,
        workspace_id: str,
        query: str,
        *,
        timespan: object,
        server_timeout: int,
    ) -> object:
        """Run a workspace query.

        Args:
            workspace_id: Log Analytics workspace identifier.
            query: KQL query string.
            timespan: Azure Monitor timespan parameter.
            server_timeout: Server-side timeout in seconds.

        Returns:
            object: Azure Monitor response object.
        """


def normalize_rows(
    rows: Sequence[Mapping[str, object]], limit: int
) -> list[dict[str, str]]:
    """Stringify and bound raw rows for report-safe samples.

    Args:
        rows: Raw row mappings to normalize.
        limit: Maximum number of rows to keep.

    Returns:
        list[dict[str, str]]: Stringified, bounded sample rows.
    """

    out: list[dict[str, str]] = []
    for row in rows[:limit]:
        out.append(
            {
                str(key): "" if value is None else str(value)
                for key, value in row.items()
            }
        )
    return out


def _column_name(column: object) -> str:
    if isinstance(column, Mapping):
        name = column.get("name")
        return str(name) if name is not None else str(column)
    return str(getattr(column, "name", column))


def _extract_tables(payload: object) -> list[object]:
    tables = getattr(payload, "tables", None)
    if not isinstance(tables, Sequence) or isinstance(tables, (str, bytes, bytearray)):
        return []
    return list(tables)


def _table_to_dict_rows(table: object) -> list[dict[str, object]]:
    columns_obj = getattr(table, "columns", None)
    rows_obj = getattr(table, "rows", None)
    if not isinstance(columns_obj, Sequence) or not isinstance(rows_obj, Sequence):
        return []

    columns = [_column_name(column) for column in columns_obj]
    normalized_rows: list[dict[str, object]] = []
    for row in rows_obj:
        if not isinstance(row, Sequence) or isinstance(row, (str, bytes, bytearray)):
            continue
        normalized_rows.append(dict(zip(columns, row, strict=False)))
    return normalized_rows


def _response_rows(payload: object) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for table in _extract_tables(payload):
        rows.extend(_table_to_dict_rows(table))
    return rows


def _partial_error_message(partial_error: object) -> str:
    if partial_error is None:
        return ""
    if isinstance(partial_error, str):
        return partial_error

    message = getattr(partial_error, "message", None)
    if isinstance(message, str) and message:
        return message

    return str(partial_error)


async def _aclose_if_supported(resource: object) -> None:
    close_method = getattr(resource, "close", None)
    if not callable(close_method):
        return

    close_callable = cast(Callable[[], object], close_method)
    close_result = close_callable()
    if isawaitable(close_result):
        await cast(Awaitable[object], close_result)


class AzureMonitorSentinelQueryClient:
    """Azure Monitor Logs implementation of SentinelQueryClient.

    Args:
        settings: Settings with `sentinel_workspace_id`.
        logs_client: Optional injected LogsQueryClient-compatible double.
        credential: Optional injected credential double.

    Raises:
        ValueError: Raised when `sentinel_workspace_id` is empty.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        logs_client: LogsQueryClientLike | None = None,
        credential: SupportsAsyncClose | None = None,
    ) -> None:
        if not settings.sentinel_workspace_id:
            raise ValueError("SENTINEL_WORKSPACE_ID is required for active hunt")

        self._workspace_id = settings.sentinel_workspace_id
        self._credential = credential or DefaultAzureCredential()
        self._client = logs_client or LogsQueryClient(
            cast(AsyncTokenCredential, self._credential)
        )

    async def aquery(self, kql: str, timeout_seconds: float) -> SentinelQueryResult:
        """Run KQL against the configured Log Analytics workspace.

        Args:
            kql: KQL query string to execute.
            timeout_seconds: Server-side timeout in seconds.

        Returns:
            SentinelQueryResult: Normalized result including partial data errors.
        """

        response = await self._client.query_workspace(
            self._workspace_id,
            kql,
            timespan=None,
            server_timeout=int(timeout_seconds),
        )
        rows = _response_rows(response)

        partial_data = getattr(response, "partial_data", None)
        if partial_data is not None:
            rows.extend(_response_rows(partial_data))

        partial_error = _partial_error_message(getattr(response, "partial_error", None))
        return SentinelQueryResult.from_raw(
            rows,
            limit=DEFAULT_SAMPLE_LIMIT,
            error=partial_error,
        )

    async def aclose(self) -> None:
        """Close Azure client resources when supported.

        Returns:
            None: Returned when close hooks have completed.
        """

        await _aclose_if_supported(self._client)
        await _aclose_if_supported(self._credential)
