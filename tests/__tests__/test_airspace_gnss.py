"""spec #1 Airspace & GNSS Context — 도구 + Investigation 통합 회귀."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from agents.investigation_agent import (
    InvestigationAgent,
    _is_s1_scenario,
    _load_asset_coords,
)
from core.models import (
    AirspaceFinding,
    Alert,
    Severity,
    SOCState,
)
from core.settings import Settings
from tools.airspace_tool import (
    AirspaceStub,
    OpenSkyRetriever,
    _haversine_km,
)
from tools.gnss_jam_tool import GnssJamStub, GpsJamRetriever


def _alert(scenario_id: str = "S1-GNSS-001", **kwargs: object) -> Alert:
    defaults: dict[str, object] = {
        "id": "a1",
        "scenario_id": scenario_id,
        "title": "GNSS 의심",
        "severity_baseline": Severity.MEDIUM,
        "signals": ["EKF_HIGH_VARIANCE"],
        "expected_detection": {"sigma_rule": "rule_x"},
        "asset_id": "GNSS",
    }
    defaults.update(kwargs)
    return Alert.model_validate(defaults)


class TestS1Helper:
    def test_match(self) -> None:
        assert _is_s1_scenario("S1-GNSS-001")
        assert _is_s1_scenario("s1")
        assert not _is_s1_scenario("S2-something")
        assert not _is_s1_scenario("")


class TestAssetCoords:
    def test_load_yaml_returns_lat_lon(self) -> None:
        coords = _load_asset_coords()
        assert "GNSS" in coords
        lat, lon = coords["GNSS"]
        assert 30.0 < lat < 40.0
        assert 120.0 < lon < 135.0


class TestGnssJamStub:
    @pytest.mark.asyncio
    async def test_returns_level_for_known_cell(self) -> None:
        stub = GnssJamStub(fixture={(36, 126): 3})
        findings = await stub.aretrieve(36.778, 126.448)
        assert len(findings) == 1
        assert findings[0].level == 3
        assert findings[0].cell == "36,126"

    @pytest.mark.asyncio
    async def test_empty_for_unknown_cell(self) -> None:
        stub = GnssJamStub(fixture={})
        assert await stub.aretrieve(0.0, 0.0) == []


class TestGpsJamRetrieverGraceful:
    @pytest.mark.asyncio
    async def test_http_5xx_returns_empty(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(503)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)
        settings = Settings()
        retriever = GpsJamRetriever(settings, client=client)
        findings = await retriever.aretrieve(36.7, 126.4)
        assert findings == []
        await client.aclose()

    @pytest.mark.asyncio
    async def test_parse_valid_response(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "cells": [
                        {"cell": "36,126", "level": 3},
                        {"cell": "36,127", "level": 0},
                        {"cell": "bad"},  # 미지원 — 무시
                    ]
                },
            )

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)
        settings = Settings()
        retriever = GpsJamRetriever(settings, client=client)
        findings = await retriever.aretrieve(36.7, 126.4)
        assert len(findings) == 3
        assert findings[0].level == 3
        await client.aclose()

    @pytest.mark.asyncio
    async def test_ttl_cache_reuses_result(self) -> None:
        call_count = 0

        def handler(req: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(200, json={"cells": [{"cell": "36,126", "level": 2}]})

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)
        settings = Settings()
        retriever = GpsJamRetriever(settings, ttl_seconds=300.0, client=client)
        when = datetime(2026, 6, 30, 12, 0, tzinfo=UTC)
        a = await retriever.aretrieve(36.7, 126.4, when=when)
        b = await retriever.aretrieve(36.7, 126.4, when=when)
        assert a == b
        assert call_count == 1
        await client.aclose()


class TestHaversine:
    def test_distance_zero(self) -> None:
        assert _haversine_km(36.0, 126.0, 36.0, 126.0) == pytest.approx(0.0)

    def test_distance_known(self) -> None:
        # 1° latitude ≈ 111km
        d = _haversine_km(36.0, 126.0, 37.0, 126.0)
        assert 110.0 < d < 112.0


class TestAirspaceStub:
    @pytest.mark.asyncio
    async def test_recomputes_distance(self) -> None:
        stub = AirspaceStub(
            fixture=[
                AirspaceFinding(
                    icao24="abc",
                    callsign="UNK01",
                    lat=36.8,
                    lon=126.5,
                    hostile=True,
                )
            ]
        )
        findings = await stub.aretrieve(36.778, 126.448)
        assert len(findings) == 1
        assert findings[0].distance_km > 0.0
        assert findings[0].distance_km < 15.0


class TestOpenSkyRetriever:
    @pytest.mark.asyncio
    async def test_parses_states(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "time": 1,
                    "states": [
                        # [icao24, callsign, origin, time_pos, last_contact,
                        #  lon, lat, baro_alt, on_ground, ...]
                        [
                            "abc1",
                            "KAF01   ",
                            "KR",
                            1,
                            1,
                            126.50,
                            36.78,
                            1000.0,
                            False,
                        ],
                        [
                            "abc2",
                            "",
                            "KR",
                            1,
                            1,
                            126.55,
                            36.80,
                            500.0,
                            False,
                        ],
                    ],
                },
            )

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)
        settings = Settings(airspace_known_friends=["KAF01"])
        retriever = OpenSkyRetriever(settings, client=client)
        findings = await retriever.aretrieve(36.778, 126.448)
        await client.aclose()
        assert len(findings) == 2
        kaf = next(f for f in findings if f.callsign == "KAF01")
        assert not kaf.hostile
        unk = next(f for f in findings if f.icao24 == "abc2")
        assert unk.hostile  # 빈 콜사인 + 공중 → hostile

    @pytest.mark.asyncio
    async def test_http_error_returns_empty(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(429)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)
        retriever = OpenSkyRetriever(Settings(), client=client)
        assert await retriever.aretrieve(36.0, 126.0) == []
        await client.aclose()


class TestInvestigationConfidenceBoost:
    @pytest.mark.asyncio
    async def test_s1_with_jam_boosts_confidence(self) -> None:
        settings = Settings()
        gnss = GnssJamStub(fixture={(36, 126): 3})
        agent = InvestigationAgent(
            settings, retriever=None, gnss_jam=gnss, airspace=None
        )
        alert = _alert(scenario_id="S1-GNSS-001")
        result: SOCState = {"alert": alert}
        out = await agent.run(result)
        inv = out["investigation"]
        assert any(f.level >= 2 for f in inv.gnss_jam_findings)
        # base=0.3 (no trusted, not degraded) + 0.2 jam boost = 0.5
        assert inv.confidence >= 0.5

    @pytest.mark.asyncio
    async def test_non_s1_no_jam_boost(self) -> None:
        settings = Settings()
        gnss = GnssJamStub(fixture={(36, 126): 3})
        agent = InvestigationAgent(
            settings, retriever=None, gnss_jam=gnss, airspace=None
        )
        alert = _alert(scenario_id="S2-OTHER")
        out = await agent.run({"alert": alert})
        inv = out["investigation"]
        # findings 들어가지만 보강은 S1 만
        assert inv.gnss_jam_findings  # 들어가긴 함
        assert inv.confidence == 0.3  # 보강 안 됨

    @pytest.mark.asyncio
    async def test_hostile_aircraft_boosts(self) -> None:
        settings = Settings()
        airspace = AirspaceStub(
            fixture=[
                AirspaceFinding(
                    icao24="x",
                    callsign="UNK",
                    lat=36.78,
                    lon=126.45,
                    hostile=True,
                )
            ]
        )
        agent = InvestigationAgent(
            settings, retriever=None, gnss_jam=None, airspace=airspace
        )
        out = await agent.run({"alert": _alert()})
        inv = out["investigation"]
        assert any(f.hostile for f in inv.airspace_findings)
        assert inv.confidence >= 0.5

    @pytest.mark.asyncio
    async def test_no_coords_drops_external(self) -> None:
        settings = Settings()
        gnss = GnssJamStub(fixture={(36, 126): 3})
        agent = InvestigationAgent(
            settings, retriever=None, gnss_jam=gnss, airspace=None
        )
        alert = _alert(asset_id="AUTOPILOT")  # asset-tiers 에 coords 없음
        out = await agent.run({"alert": alert})
        flags = out.get("guardrail_flags", [])
        assert any("좌표 부재" in f for f in flags)
        assert out["investigation"].gnss_jam_findings == []
