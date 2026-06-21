"""합성 telemetry-tap 텔레메트리 생성기(시뮬 빌드 없이 브리지 검증용).

정상 정찰 비행 텔레메트리를 흘리다가 GPS 스푸핑을 주입한다(EKF 잔차 급증 +
Eph 급증 + 위성수 급감). 출력 dict 는 telemetry-tap NDJSON 키와 동일하므로 실
시뮬 스트림으로 그대로 교체 가능.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sim_bridge.models import TelemetryRecord


def benign_ekf(uav_id: str = "MPD-001") -> dict[str, object]:
    """정상 EKF_STATUS_REPORT 레코드."""
    return {
        "TimeGenerated": "2026-06-21T00:00:00Z",
        "UAVId": uav_id,
        "MsgType": "EKF_STATUS_REPORT",
        "PosHorizVariance": 0.30,
        "VelocityVariance": 0.25,
        "CompassVariance": 0.10,
    }


def benign_gps(uav_id: str = "MPD-001") -> dict[str, object]:
    """정상 GPS_RAW_INT 레코드."""
    return {
        "TimeGenerated": "2026-06-21T00:00:00Z",
        "UAVId": uav_id,
        "MsgType": "GPS_RAW_INT",
        "FixType": 3,
        "Eph_cm": 120,
        "SatellitesVisible": 14,
    }


def spoof_ekf(uav_id: str = "MPD-001") -> dict[str, object]:
    """스푸핑 중 EKF(잔차 급증)."""
    return {
        "TimeGenerated": "2026-06-21T00:00:10Z",
        "UAVId": uav_id,
        "MsgType": "EKF_STATUS_REPORT",
        "PosHorizVariance": 1.35,
        "VelocityVariance": 1.10,
        "CompassVariance": 0.12,
    }


def spoof_gps(uav_id: str = "MPD-001") -> dict[str, object]:
    """스푸핑 중 GPS(Eph 급증 + 위성수 급감)."""
    return {
        "TimeGenerated": "2026-06-21T00:00:10Z",
        "UAVId": uav_id,
        "MsgType": "GPS_RAW_INT",
        "FixType": 3,
        "Eph_cm": 640,
        "SatellitesVisible": 5,
    }


def synth_records(uav_id: str = "MPD-001", benign_n: int = 5) -> list[TelemetryRecord]:
    """정상 N건 → 스푸핑 주입 시퀀스(리스트)."""
    raw: list[dict[str, object]] = []
    for _ in range(benign_n):
        raw.append(benign_gps(uav_id))
        raw.append(benign_ekf(uav_id))
    # 스푸핑 주입: GPS 품질 저하 → EKF 잔차 급증
    raw.append(spoof_gps(uav_id))
    raw.append(spoof_ekf(uav_id))
    return [TelemetryRecord.from_ndjson(r) for r in raw]


async def synth_stream(
    uav_id: str = "MPD-001", benign_n: int = 5
) -> AsyncIterator[TelemetryRecord]:
    """비동기 스트림 버전(run_stream 용)."""
    for record in synth_records(uav_id, benign_n):
        yield record
