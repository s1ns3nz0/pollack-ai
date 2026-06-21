#!/usr/bin/env python3
"""폐루프 RTB 수동 송신 — SOC 결정(RETURN_TO_LAUNCH)을 av-mpd 에 직접 전달.

`sim_inject_gps_spoof.py`(공격 주입)의 대칭 짝. 탐지 파이프라인과 무관하게 MAVLink
COMMAND_LONG(MAV_CMD_NAV_RETURN_TO_LAUNCH)을 송신해 폐루프 작동을 단독 검증한다.
QGroundControl(noVNC)에서 드론 복귀(RTL)가 시각화된다.

사전: uav-sim-env 기동. 실행: python scripts/sim_send_rtb.py [--conn tcp:HOST:PORT]
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sim_bridge.actuator import ActuatorError, MavlinkActuator  # noqa: E402

CONN = "tcp:127.0.0.1:5760"  # av-mpd SITL 직접 포트


def main() -> None:
    conn = CONN
    if "--conn" in sys.argv:
        conn = sys.argv[sys.argv.index("--conn") + 1]
    actuator = MavlinkActuator(connection=conn)
    print(f"[연결] {conn} → RTB(RETURN_TO_LAUNCH) 송신 시도...")
    try:
        result = actuator.send_rtb(uav_id="SIM-UAV")
    except ActuatorError as e:
        print(f"[실패] {e}")
        raise SystemExit(1) from e
    print(f"[완료] {result}")
    print("       → QGC(noVNC)에서 드론 복귀 확인.")


if __name__ == "__main__":
    main()
