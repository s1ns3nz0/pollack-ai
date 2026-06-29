"""OpenSky Network 외부 항적 컨텍스트 도구.

Investigation 의 결정론 보강 입력. 호출 측은 (lat, lon) 을 주고 인근 비행체 목록을
받는다. 적대(hostile) 판정은 callsign 화이트리스트 외 / 빈 callsign + 공중 기준
(spec D5). 출처는 상용 ADS-B 수집으로 *권한 있는 신뢰* 가 아니다 → severity 불변,
confidence 보강만(spec D4).

장애·미설정 시 빈 결과로 강등(핫패스 SLO 보존).

Spec: docs/superpowers/specs/2026-06-30-airspace-gnss-context-design.md
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import math
import time
from typing import Protocol, runtime_checkable

import httpx

from core.exceptions import SOCPlatformError
from core.models import AirspaceFinding
from core.settings import Settings
from utils.logging import get_logger

_EARTH_RADIUS_KM = 6371.0


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """대원 거리(km). 표준 haversine."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = (
        math.sin(dphi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(dl / 2.0) ** 2
    )
    return 2.0 * _EARTH_RADIUS_KM * math.asin(math.sqrt(a))


@runtime_checkable
class AirspaceTool(Protocol):
    """Investigation 이 의존하는 공역 컨텍스트 도구 계약."""

    async def aretrieve(
        self, lat: float, lon: float, when: datetime | None = None
    ) -> list[AirspaceFinding]:
        """(lat, lon) 인근 비행체 항적을 반환한다."""
        ...


class OpenSkyRetriever:
    """OpenSky Network REST 어댑터.

    - BBox = (lat, lon) ± `airspace_bbox_deg`(deg). 디폴트 ±0.1 ≒ ±11km.
    - 캐시 키 = (round(lat,1), round(lon,1), floor(epoch/30)). TTL 30초.
    - rate-limit: 익명 400 req/day — 캐시 적극 + 미캐시 호출 직렬화.
    """

    def __init__(
        self,
        settings: Settings,
        ttl_seconds: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings
        self._ttl = ttl_seconds
        self._client = client
        self._cache: dict[
            tuple[float, float, int], tuple[float, list[AirspaceFinding]]
        ] = {}
        self._lock = asyncio.Lock()
        self._logger = get_logger("OpenSkyRetriever")

    async def aretrieve(
        self, lat: float, lon: float, when: datetime | None = None
    ) -> list[AirspaceFinding]:
        when = when or datetime.now(UTC)
        time_bucket = int(when.timestamp() // 30)
        key = (round(lat, 1), round(lon, 1), time_bucket)
        now = time.monotonic()
        cached = self._cache.get(key)
        if cached and (now - cached[0]) < self._ttl:
            return cached[1]
        async with self._lock:
            cached = self._cache.get(key)
            if cached and (now - cached[0]) < self._ttl:
                return cached[1]
            try:
                data = await self._fetch(lat, lon)
            except (httpx.HTTPError, SOCPlatformError) as exc:
                self._logger.warning("opensky 조회 실패, 빈 결과: %s", exc)
                return []
            findings = self._parse(data, lat, lon)
            self._cache[key] = (now, findings)
            return findings

    async def _fetch(self, lat: float, lon: float) -> object:
        d = self._settings.airspace_bbox_deg
        params = {
            "lamin": str(lat - d),
            "lamax": str(lat + d),
            "lomin": str(lon - d),
            "lomax": str(lon + d),
        }
        url = f"{self._settings.opensky_base_url.rstrip('/')}/states/all"
        auth = self._auth_pair()
        if self._client is None:
            async with httpx.AsyncClient(
                timeout=self._settings.opensky_timeout_seconds, auth=auth
            ) as client:
                resp = await client.get(url, params=params)
                resp.raise_for_status()
                payload: object = resp.json()
                return payload
        resp = await self._client.get(url, params=params, auth=auth)
        resp.raise_for_status()
        payload = resp.json()
        return payload

    def _auth_pair(self) -> tuple[str, str] | None:
        user = self._settings.opensky_username.get_secret_value()
        pwd = self._settings.opensky_password.get_secret_value()
        if user and pwd:
            return (user, pwd)
        return None

    def _parse(
        self, payload: object, ref_lat: float, ref_lon: float
    ) -> list[AirspaceFinding]:
        """`states` 배열에서 안전 추출."""
        if not isinstance(payload, dict):
            return []
        states = payload.get("states", [])
        if not isinstance(states, list):
            return []
        friends = {c.strip() for c in self._settings.airspace_known_friends}
        out: list[AirspaceFinding] = []
        for row in states:
            if not isinstance(row, (list, tuple)) or len(row) < 9:
                continue
            try:
                icao24 = str(row[0])
                callsign = str(row[1] or "").strip()
                lon = float(row[5])
                lat = float(row[6])
                on_ground = bool(row[8])
            except (TypeError, ValueError):
                continue
            dist = _haversine_km(ref_lat, ref_lon, lat, lon)
            hostile = self._is_hostile(callsign, on_ground, friends)
            out.append(
                AirspaceFinding(
                    icao24=icao24,
                    callsign=callsign,
                    lat=lat,
                    lon=lon,
                    distance_km=round(dist, 3),
                    hostile=hostile,
                    on_ground=on_ground,
                    source="opensky",
                )
            )
        return out

    @staticmethod
    def _is_hostile(callsign: str, on_ground: bool, friends: set[str]) -> bool:
        if not callsign and not on_ground:
            return True
        if callsign and callsign not in friends:
            return True
        return False


class AirspaceStub:
    """테스트/데모용 in-memory stub — 사전 정의 비행체 목록."""

    def __init__(self, fixture: list[AirspaceFinding] | None = None) -> None:
        self._fixture = fixture or []

    async def aretrieve(
        self, lat: float, lon: float, when: datetime | None = None
    ) -> list[AirspaceFinding]:
        # 거리 재계산(스텁이지만 distance 일관성 유지).
        out: list[AirspaceFinding] = []
        for f in self._fixture:
            dist = _haversine_km(lat, lon, f.lat, f.lon)
            out.append(f.model_copy(update={"distance_km": round(dist, 3)}))
        return out
