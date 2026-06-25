"""MAVLink 직결 텔레메트리 소스 — telemetry-tap(docker) 없이 동작.

AirSim·실 ArduPilot 등 **어떤 MAVLink 엔드포인트**에서도 EKF_STATUS_REPORT /
GPS_RAW_INT 를 읽어 `TelemetryRecord` 스트림으로 변환한다. `SimBridge.run_stream`
에 그대로 투입 가능 — SOC 를 uav-sim-env 도커 의존에서 분리해 이식성을 확보한다.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from sim_bridge.models import TelemetryRecord


def mav_to_record(msg_type: str, data: dict[str, object]) -> TelemetryRecord:
    """MAVLink 메시지(dict) → TelemetryRecord(telemetry-tap 키로 정규화).

    Args:
        msg_type: MAVLink 메시지 타입(EKF_STATUS_REPORT / GPS_RAW_INT).
        data: `msg.to_dict()` 결과.

    Returns:
        탐지기가 소비하는 필드로 매핑된 TelemetryRecord.
    """
    if msg_type == "EKF_STATUS_REPORT":
        return TelemetryRecord.from_ndjson(
            {
                "UAVId": "MAV-001",
                "MsgType": "EKF_STATUS_REPORT",
                "PosHorizVariance": data.get("pos_horiz_variance"),
                "VelocityVariance": data.get("velocity_variance"),
                "CompassVariance": data.get("compass_variance"),
                "EkfFlags": data.get("flags"),
            }
        )
    return TelemetryRecord.from_ndjson(
        {
            "UAVId": "MAV-001",
            "MsgType": "GPS_RAW_INT",
            "FixType": data.get("fix_type"),
            "Eph_cm": data.get("eph"),
            "SatellitesVisible": data.get("satellites_visible"),
        }
    )


async def mavlink_telemetry_records(
    conn: str = "tcp:127.0.0.1:5790",
) -> AsyncIterator[TelemetryRecord]:
    """MAVLink 엔드포인트를 구독해 EKF/GPS 레코드를 비동기 방출한다.

    Args:
        conn: pymavlink 접속 문자열(예: AirSim 노트북 `udpin:0.0.0.0:14550`,
            실 ArduPilot `tcp:HOST:5790`).

    Yields:
        EKF_STATUS_REPORT / GPS_RAW_INT 에서 변환된 TelemetryRecord.
    """
    from pymavlink import mavutil

    m = mavutil.mavlink_connection(conn, source_system=255)
    await asyncio.to_thread(m.wait_heartbeat, timeout=30)
    try:
        while True:
            msg = await asyncio.to_thread(
                m.recv_match,
                type=["EKF_STATUS_REPORT", "GPS_RAW_INT"],
                blocking=True,
                timeout=5,
            )
            if msg is None:
                continue
            yield mav_to_record(msg.get_type(), msg.to_dict())
    finally:
        m.close()
