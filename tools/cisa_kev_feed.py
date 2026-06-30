"""CISA KEV JSON 피드 어댑터(spec T1)."""

from __future__ import annotations

from datetime import UTC, datetime
import json

import httpx

from core.exceptions import SOCPlatformError
from core.models import FeedSnapshot
from core.settings import Settings
from tools.feed_base import fetch_with_retry
from utils.logging import get_logger


class CisaKevFeed:
    """CISA KEV known_exploited_vulnerabilities.json."""

    source = "kev"

    def __init__(
        self, settings: Settings, client: httpx.AsyncClient | None = None
    ) -> None:
        self._settings = settings
        self._client = client
        self._logger = get_logger("CisaKevFeed")

    async def afetch(self) -> FeedSnapshot:
        body, digest = await fetch_with_retry(
            self._settings.kev_feed_url,
            user_agent=self._settings.feed_user_agent,
            client=self._client,
        )
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise SOCPlatformError(f"KEV feed 파싱 실패: {exc}") from exc
        cves = self._extract_cves(data)
        return FeedSnapshot(
            source=self.source,
            version=str(data.get("dateReleased", "")) if isinstance(data, dict) else "",
            cves=sorted(cves),
            fetched_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            raw_hash=digest,
        )

    @staticmethod
    def _extract_cves(data: object) -> set[str]:
        if not isinstance(data, dict):
            return set()
        rows = data.get("vulnerabilities", [])
        if not isinstance(rows, list):
            return set()
        out: set[str] = set()
        for row in rows:
            if isinstance(row, dict):
                cve = row.get("cveID") or row.get("cve_id")
                if isinstance(cve, str):
                    out.add(cve)
        return out
