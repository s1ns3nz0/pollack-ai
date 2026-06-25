#!/usr/bin/env python3
"""S1 GNSS 스푸핑 주입 — ArduPilot SITL SIM_GPS 파라미터 변조.

av-mpd(ArduPilot SITL)에 MAVLink PARAM_SET 으로 GPS 위치 글리치 + 위성수 급감 +
정확도 저하를 주입한다 → EKF 잔차(PosHorizVariance) 급증 + Eph 급증 + 위성 급감
→ telemetry-tap NDJSON → SOC 브리지가 탐지.

사전: uav-sim-env 기동. 실행: python scripts/sim_inject_gps_spoof.py [--clear] [--conn tcp:HOST:PORT]
"""
import sys
import time

from pymavlink import mavutil

CONN = "tcp:127.0.0.1:5790"  # mavlink-router 외부 진입점(5760은 라우터가 단독 점유)

# (param, spoof값, 정상복구값) — ArduPilot 버전별 후보를 모두 시도(미지원은 무시됨)
SPOOF = [
    ("SIM_GPS1_NUMSATS", 5, 14),
    ("SIM_GPS_NUMSATS", 5, 14),
    ("SIM_GPS1_ACC", 5.0, 0.3),
    ("SIM_GPS_ACC", 5.0, 0.3),
    ("SIM_GPS1_GLITCH_X", 0.0012, 0.0),
    ("SIM_GPS1_GLITCH_Y", 0.0012, 0.0),
    ("SIM_GPS_GLITCH_X", 0.0012, 0.0),
    ("SIM_GPS_GLITCH_Y", 0.0012, 0.0),
]


def main() -> None:
    clear = "--clear" in sys.argv
    conn = sys.argv[sys.argv.index("--conn") + 1] if "--conn" in sys.argv else CONN
    m = mavutil.mavlink_connection(conn)
    print(f"[연결] {conn} 대기...")
    m.wait_heartbeat(timeout=30)
    print(f"[연결] HEARTBEAT (sys={m.target_system})")
    for name, spoof_v, normal_v in SPOOF:
        value = float(normal_v if clear else spoof_v)
        m.mav.param_set_send(
            m.target_system, m.target_component,
            name.encode(), value, mavutil.mavlink.MAV_PARAM_TYPE_REAL32,
        )
        time.sleep(0.15)
    if clear:
        print("[복구] SIM_GPS 파라미터 정상값 복원 완료.")
    else:
        print("[주입] GPS 스푸핑(글리치+위성감소+정확도저하) 주입 완료.")
        print("       → telemetry-tap EKF 잔차 급증 → SOC 브리지 탐지 예상.")


if __name__ == "__main__":
    main()
