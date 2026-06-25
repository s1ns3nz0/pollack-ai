#!/usr/bin/env python3
"""시연 재촬영 원클릭 리셋 — 스푸핑 해제 → EKF 안정화 → 이륙 → 정찰지점 배치.

각 테이크 전에 한 번 실행하면 깨끗한 시작 상태(클린 GPS + 공중 정찰)가 된다.
탐지기는 자동 재무장되므로 BLUE 브리지는 재시작 없이 그대로 둬도 된다(정상 복귀 후
재무장). 단, 항적(궤적)까지 완전히 지우려면 시뮬 컨테이너 재시작이 필요하다.

실행: python scripts/sim_reset.py [--alt 60] [--north-m 1000]
사전: uav-sim-env 기동, GPS 락.
"""
import subprocess
import sys
import time
from pathlib import Path

from pymavlink import mavutil

ROOT = Path(__file__).resolve().parents[1]
CONN = "tcp:127.0.0.1:5790"
HOME_LAT, HOME_LON = 37.5326, 127.0246


def _arg(flag: str, default: str) -> str:
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default


def main() -> None:
    alt = float(_arg("--alt", "60"))
    north_m = float(_arg("--north-m", "1000"))

    # 1) 스푸핑 해제
    print("[1/4] 스푸핑 해제")
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "sim_inject_gps_spoof.py"), "--clear"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=40,
    )

    m = mavutil.mavlink_connection(CONN, source_system=255)
    m.wait_heartbeat(timeout=30)
    ts, tc = 1, 1

    # 2) EKF 안정화 대기(잔차 가라앉고 플래그 정상)
    print("[2/4] EKF 안정화 대기")
    t0 = time.time()
    while time.time() - t0 < 40:
        msg = m.recv_match(type="EKF_STATUS_REPORT", blocking=True, timeout=3)
        if msg and msg.pos_horiz_variance < 0.5:
            break
        time.sleep(1)

    # 3) GUIDED + 무장 + 이륙
    print(f"[3/4] GUIDED 이륙 → {alt:.0f}m")
    gid = m.mode_mapping()["GUIDED"]
    for _ in range(5):
        m.mav.set_mode_send(ts, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, gid)
        time.sleep(1)
        hb = m.recv_match(type="HEARTBEAT", blocking=True, timeout=2)
        if hb and mavutil.mode_string_v10(hb) == "GUIDED":
            break
    m.mav.command_long_send(
        ts, tc, mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 0, 1, 0, 0, 0, 0, 0, 0
    )
    time.sleep(2)
    m.mav.command_long_send(
        ts, tc, mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, 0, 0, 0, 0, 0, 0, 0, alt
    )
    for _ in range(15):
        msg = m.recv_match(type="GLOBAL_POSITION_INT", blocking=True, timeout=3)
        if msg and msg.relative_alt / 1000 >= alt * 0.9:
            break
        time.sleep(1)

    # 4) 정찰지점(북쪽)으로 이동 — 복귀가 길게 보이도록
    target_lat = HOME_LAT + north_m / 111000.0
    print(f"[4/4] 정찰지점 이동(발사점 북 {north_m:.0f}m)")
    m.mav.command_int_send(
        ts, tc, mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
        mavutil.mavlink.MAV_CMD_DO_REPOSITION, 0, 0,
        -1, 0, 0, float("nan"), int(target_lat * 1e7), int(HOME_LON * 1e7), alt,
    )
    print("[완료] 클린 상태 — BLUE 모니터링 확인 후 RED 주입하세요.")
    m.close()


if __name__ == "__main__":
    main()
