"""MAVLink 직결 텔레메트리 소스 — telemetry-tap(docker) 없이 동작.

AirSim·실 ArduPilot 등 **어떤 MAVLink 엔드포인트**에서도 EKF_STATUS_REPORT /
GPS_RAW_INT 를 읽어 `TelemetryRecord` 스트림으로 변환한다. `SimBridge.run_stream`
에 그대로 투입 가능 — SOC 를 uav-sim-env 도커 의존에서 분리해 이식성을 확보한다.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from sim_bridge.detector import EKF_GPS_GLITCHING
from sim_bridge.models import TelemetryRecord

# PX4 ESTIMATOR_STATUS_FLAGS 의 GPS 글리치 비트(ArduPilot 의 0x8000 과 값이 다름).
_PX4_ESTIMATOR_GPS_GLITCH = 1024
# PX4 정상 추정기 플래그(0x33F=ArduPilot healthy 와 동일 의미로 정규화).
_PX4_HEALTHY_FLAGS = 0x33F


def _from_estimator_status(data: dict[str, object]) -> TelemetryRecord:
    """PX4 ESTIMATOR_STATUS → 정규 TelemetryRecord(EKF_STATUS_REPORT 로 통일).

    PX4 는 ArduPilot 의 EKF_STATUS_REPORT 대신 ESTIMATOR_STATUS 를 쓴다. 혁신 테스트
    비율(pos_horiz_ratio/vel_ratio, 정상≪1·이상≳1)을 잔차로, GPS 글리치 플래그(1024)를
    ArduPilot 정규 비트(0x8000)로 변환해 **탐지기를 그대로 재사용**한다.
    """
    flags_raw = data.get("flags") or 0
    flags = int(flags_raw) if isinstance(flags_raw, (int, float)) else 0
    out_flags = _PX4_HEALTHY_FLAGS
    if flags & _PX4_ESTIMATOR_GPS_GLITCH:
        out_flags |= EKF_GPS_GLITCHING
    return TelemetryRecord.from_ndjson(
        {
            "UAVId": "MAV-001",
            "MsgType": "EKF_STATUS_REPORT",
            "PosHorizVariance": data.get("pos_horiz_ratio"),
            "VelocityVariance": data.get("vel_ratio"),
            "EkfFlags": out_flags,
        }
    )


def mav_to_record(msg_type: str, data: dict[str, object]) -> TelemetryRecord:
    """MAVLink 메시지(dict) → TelemetryRecord(telemetry-tap 키로 정규화).

    ArduPilot(EKF_STATUS_REPORT)와 PX4(ESTIMATOR_STATUS)를 모두 받아 동일한
    TelemetryRecord 로 정규화 — 탐지기 변경 없이 두 FC 를 다 지원한다.

    Args:
        msg_type: EKF_STATUS_REPORT / ESTIMATOR_STATUS / GPS_RAW_INT.
        data: `msg.to_dict()` 결과.

    Returns:
        탐지기가 소비하는 필드로 매핑된 TelemetryRecord.
    """
    if msg_type == "EKF_STATUS_REPORT":  # ArduPilot
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
    if msg_type == "ESTIMATOR_STATUS":  # PX4
        return _from_estimator_status(data)
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
        EKF_STATUS_REPORT(ArduPilot) / ESTIMATOR_STATUS(PX4) / GPS_RAW_INT 에서
        변환된 TelemetryRecord.
    """
    from pymavlink import mavutil

    m = mavutil.mavlink_connection(conn, source_system=255)
    await asyncio.to_thread(m.wait_heartbeat, timeout=30)
    try:
        while True:
            msg = await asyncio.to_thread(
                m.recv_match,
                type=["EKF_STATUS_REPORT", "ESTIMATOR_STATUS", "GPS_RAW_INT"],
                blocking=True,
                timeout=5,
            )
            if msg is None:
                continue
            yield mav_to_record(msg.get_type(), msg.to_dict())
    finally:
        m.close()
