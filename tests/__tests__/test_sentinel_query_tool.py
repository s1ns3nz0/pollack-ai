"""Sentinel query tool tests — Azure boundary stays thin and normalized."""

from __future__ import annotations

import pytest

from core.settings import Settings
from tools.sentinel_query_tool import (
    AzureMonitorSentinelQueryClient,
    SentinelQueryResult,
    normalize_rows,
)


def test_result_model_stringifies_sample_values() -> None:
    rows = normalize_rows([{"A": 1, "B": None, "C": True}], limit=20)
    assert rows == [{"A": "1", "B": "", "C": "True"}]


def test_result_model_applies_limit() -> None:
    rows = normalize_rows([{"A": i} for i in range(30)], limit=2)
    assert rows == [{"A": "0"}, {"A": "1"}]


def test_sentinel_query_result_counts_original_rows() -> None:
    result = SentinelQueryResult.from_raw([{"A": 1}, {"A": 2}], limit=1)
    assert result.row_count == 2
    assert result.rows == [{"A": "1"}]


def test_azure_client_requires_workspace_id() -> None:
    settings = Settings(sentinel_workspace_id="")
    with pytest.raises(ValueError, match="SENTINEL_WORKSPACE_ID"):
        AzureMonitorSentinelQueryClient(settings)
