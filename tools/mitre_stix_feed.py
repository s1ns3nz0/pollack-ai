"""MITRE ATT&CK STIX/TAXII 피드 어댑터(spec T1).

`mitre/cti` raw STIX JSON 직접 fetch. mitreattack-python 라이브러리 의존 X
(공급망 표면 축소). attack-pattern 객체에서 external_references 의 ATT&CK ID 만
안전 추출한다.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json

import httpx

from core.exceptions import SOCPlatformError
from core.models import FeedSnapshot
from core.settings import Settings
from tools.feed_base import fetch_with_retry
from utils.logging import get_logger


class MitreStixFeed:
    """ATT&CK STIX JSON 피드."""

    source = "attack"

    def __init__(
        self, settings: Settings, client: httpx.AsyncClient | None = None
    ) -> None:
        self._settings = settings
        self._client = client
        self._logger = get_logger("MitreStixFeed")

    async def afetch(self) -> FeedSnapshot:
        body, digest = await fetch_with_retry(
            self._settings.attack_feed_url,
            user_agent=self._settings.feed_user_agent,
            client=self._client,
        )
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise SOCPlatformError(f"attack feed JSON 파싱 실패: {exc}") from exc
        techs = self._extract_techs(data)
        return FeedSnapshot(
            source=self.source,
            version=str(data.get("modified", "")) if isinstance(data, dict) else "",
            techniques=sorted(techs),
            fetched_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            raw_hash=digest,
        )

    @staticmethod
    def _extract_techs(data: object) -> set[str]:
        if not isinstance(data, dict):
            return set()
        objects = data.get("objects", [])
        if not isinstance(objects, list):
            return set()
        out: set[str] = set()
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            if obj.get("type") != "attack-pattern":
                continue
            refs = obj.get("external_references", [])
            if not isinstance(refs, list):
                continue
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                if ref.get("source_name") == "mitre-attack":
                    eid = ref.get("external_id")
                    if isinstance(eid, str) and eid.startswith("T"):
                        out.add(eid)
        return out
