"""MITRE ATLAS yaml 피드 어댑터(spec T1)."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import yaml

from core.exceptions import SOCPlatformError
from core.models import FeedSnapshot
from core.settings import Settings
from tools.feed_base import fetch_with_retry
from utils.logging import get_logger


class AtlasFeed:
    """MITRE ATLAS yaml."""

    source = "atlas"

    def __init__(
        self, settings: Settings, client: httpx.AsyncClient | None = None
    ) -> None:
        self._settings = settings
        self._client = client
        self._logger = get_logger("AtlasFeed")

    async def afetch(self) -> FeedSnapshot:
        if not self._settings.atlas_feed_url:
            raise SOCPlatformError("atlas feed URL 미설정")
        body, digest = await fetch_with_retry(
            self._settings.atlas_feed_url,
            user_agent=self._settings.feed_user_agent,
            client=self._client,
        )
        try:
            data = yaml.safe_load(body)
        except yaml.YAMLError as exc:
            raise SOCPlatformError(f"atlas feed yaml 파싱 실패: {exc}") from exc
        techs = self._extract_techs(data)
        return FeedSnapshot(
            source=self.source,
            techniques=sorted(techs),
            fetched_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            raw_hash=digest,
        )

    @staticmethod
    def _extract_techs(data: object) -> set[str]:
        if not isinstance(data, dict):
            return set()
        techs_raw = data.get("techniques", [])
        if not isinstance(techs_raw, list):
            return set()
        out: set[str] = set()
        for entry in techs_raw:
            if isinstance(entry, dict):
                tid = entry.get("id") or entry.get("technique_id")
                if isinstance(tid, str):
                    out.add(tid)
        return out
