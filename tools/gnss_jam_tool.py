"""GPSJam.org 외부 GNSS 위협 컨텍스트 도구.

`Investigation` 의 결정론 보강 입력으로 사용한다. 호출 측은 (lat, lon, t) 를 주고
`list[GnssJamFinding]` 을 받는다(셀 단위 jam level 집계). 출처는 커뮤니티 피드라
*권한 있는 신뢰* 가 아니다 → severity 는 변경하지 않고 confidence 보강에만 사용한다
(spec D4).

장애·미설정 시 `SOCPlatformError` 를 잡고 빈 결과로 강등한다(핫패스 SLO 보존).

Spec: docs/superpowers/specs/2026-06-30-airspace-gnss-context-design.md
"""

from __future__ import annotations

from datetime import UTC, datetime
import math
import time
from typing import Protocol, runtime_checkable

import httpx

from core.exceptions import SOCPlatformError
from core.models import GnssJamFinding
from core.settings import Settings
from utils.logging import get_logger


@runtime_checkable
class GnssJamTool(Protocol):
    """Investigation 이 의존하는 GNSS jamming 컨텍스트 도구 계약."""

    async def aretrieve(
        self, lat: float, lon: float, when: datetime | None = None
    ) -> list[GnssJamFinding]:
        """(lat, lon) 인근 셀의 jam findings 를 반환한다."""
        ...


def _cell_key(lat: float, lon: float, date: str) -> tuple[int, int, str]:
    """1° 그리드 + 일 단위 캐시 키."""
    return (math.floor(lat), math.floor(lon), date)


class GpsJamRetriever:
    """GPSJam.org REST 어댑터(TTL 5분 in-memory 캐시 + graceful degrade)."""

    def __init__(
        self,
        settings: Settings,
        ttl_seconds: float = 300.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings
        self._ttl = ttl_seconds
        self._client = client
        self._cache: dict[tuple[int, int, str], tuple[float, list[GnssJamFinding]]] = {}
        self._logger = get_logger("GpsJamRetriever")

    async def aretrieve(
        self, lat: float, lon: float, when: datetime | None = None
    ) -> list[GnssJamFinding]:
        """(lat, lon) 인근 셀 jam findings 를 반환한다(TTL 캐시).

        Args:
            lat: WGS84 위도.
            lon: WGS84 경도.
            when: 조회 시각(UTC, 기본 now).

        Returns:
            셀 jam findings. 장애/미설정 시 빈 리스트.
        """
        when = when or datetime.now(UTC)
        date = when.strftime("%Y-%m-%d")
        key = _cell_key(lat, lon, date)
        now = time.monotonic()
        cached = self._cache.get(key)
        if cached and (now - cached[0]) < self._ttl:
            return cached[1]
        if not self._settings.gpsjam_endpoint:
            return []
        bbox = (
            f"{math.floor(lat)},{math.floor(lon)}," f"{math.ceil(lat)},{math.ceil(lon)}"
        )
        params = {"bbox": bbox, "date": date}
        try:
            data = await self._fetch(params)
        except (httpx.HTTPError, SOCPlatformError) as exc:
            self._logger.warning("gpsjam 조회 실패, 빈 결과: %s", exc)
            return []
        findings = self._parse(data, date)
        self._cache[key] = (now, findings)
        return findings

    async def _fetch(self, params: dict[str, str]) -> object:
        if self._client is None:
            async with httpx.AsyncClient(
                timeout=self._settings.gpsjam_timeout_seconds
            ) as client:
                resp = await client.get(self._settings.gpsjam_endpoint, params=params)
                resp.raise_for_status()
                payload: object = resp.json()
                return payload
        resp = await self._client.get(self._settings.gpsjam_endpoint, params=params)
        resp.raise_for_status()
        payload = resp.json()
        return payload

    def _parse(self, payload: object, date: str) -> list[GnssJamFinding]:
        """응답에서 cell/level 만 안전 추출(스키마 변경 graceful)."""
        if not isinstance(payload, dict):
            return []
        cells = payload.get("cells", [])
        if not isinstance(cells, list):
            return []
        findings: list[GnssJamFinding] = []
        for entry in cells:
            if not isinstance(entry, dict):
                continue
            cell = entry.get("cell") or entry.get("id") or ""
            level = entry.get("level", 0)
            if not isinstance(cell, str):
                continue
            try:
                lvl = int(level)
            except (TypeError, ValueError):
                continue
            lvl = max(0, min(3, lvl))
            findings.append(
                GnssJamFinding(cell=cell, level=lvl, as_of=date, source="gpsjam")
            )
        return findings


class GnssJamStub:
    """테스트/데모용 in-memory stub — 좌표·날짜 조합으로 사전 정의 결과 반환."""

    def __init__(self, fixture: dict[tuple[int, int], int] | None = None) -> None:
        """fixture[(lat_floor, lon_floor)] = level(0..3)."""
        self._fixture = fixture or {}

    async def aretrieve(
        self, lat: float, lon: float, when: datetime | None = None
    ) -> list[GnssJamFinding]:
        when = when or datetime.now(UTC)
        date = when.strftime("%Y-%m-%d")
        key = (math.floor(lat), math.floor(lon))
        level = self._fixture.get(key)
        if level is None:
            return []
        return [
            GnssJamFinding(
                cell=f"{key[0]},{key[1]}", level=level, as_of=date, source="stub"
            )
        ]
