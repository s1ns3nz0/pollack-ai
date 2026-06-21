"""uav-sim-env ↔ SOC 브리지.

시뮬레이터(`uav-sim-env`)의 telemetry-tap NDJSON 스트림을 받아 이상을 탐지하고,
`core.models.Alert` 로 변환해 6-에이전트 SOC 파이프라인에 투입한다. Azure Sentinel
경로(원래 설계)를 대체하는 직접 연결고리이며, NDJSON 필드명은 telemetry-tap 스키마
(`UAVId/MsgType/PosHorizVariance/Eph_cm/FixType/...`)와 동일해 실 시뮬에 그대로 붙는다.
"""

from sim_bridge.actuator import (
    ActuatorError,
    MavlinkActuator,
    RtbActuator,
    rtb_recommended,
)
from sim_bridge.bridge import BridgeEvent, SimBridge
from sim_bridge.detector import GpsSpoofDetector
from sim_bridge.models import TelemetryRecord

__all__ = [
    "ActuatorError",
    "BridgeEvent",
    "GpsSpoofDetector",
    "MavlinkActuator",
    "RtbActuator",
    "SimBridge",
    "TelemetryRecord",
    "rtb_recommended",
]
