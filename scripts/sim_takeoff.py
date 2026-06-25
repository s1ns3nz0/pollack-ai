#!/usr/bin/env python3
"""시연 준비 — uav-sim-env 쿼드플레인을 GUIDED VTOL 이륙시킨다.

데모 전에 드론을 공중에 띄워, 폐루프 RTB 시 QGC 에서 복귀가 시각적으로 보이게 한다.
GUIDED 진입 → 무장 → NAV_TAKEOFF(쿼드플레인은 VTOL 상승) → 목표 고도 도달 대기.

사전: uav-sim-env 기동, GPS 락. 실행: python scripts/sim_takeoff.py [--alt 50] [--conn tcp:HOST:PORT]
"""
import sys
import time

from pymavlink import mavutil

CONN = "tcp:127.0.0.1:5790"  # mavlink-router 외부 진입점


def _arg(flag: str, default: str) -> str:
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default


def main() -> None:
    conn = _arg("--conn", CONN)
    alt = float(_arg("--alt", "50"))
    m = mavutil.mavlink_connection(conn, source_system=255)
    print(f"[연결] {conn} HEARTBEAT 대기...")
    m.wait_heartbeat(timeout=30)
    ts, tc = 1, 1

    def vehicle_hb() -> object | None:
        for _ in range(15):
            hb = m.recv_match(type="HEARTBEAT", blocking=True, timeout=2)
            if hb and hb.get_srcSystem() == 1 and hb.get_srcComponent() == 1:
                return hb
        return None

    print("[1/3] GUIDED 진입")
    m.set_mode("GUIDED")
    time.sleep(2)
    print("[2/3] 무장(ARM)")
    m.mav.command_long_send(
        ts, tc, mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 0, 1, 0, 0, 0, 0, 0, 0
    )
    ack = m.recv_match(type="COMMAND_ACK", blocking=True, timeout=5)
    if not ack or ack.result != 0:
        print(f"[경고] ARM 거부(result={getattr(ack, 'result', None)}) — GPS 락/사전무장 확인")
    time.sleep(2)
    print(f"[3/3] VTOL 이륙 → {alt:.0f}m")
    m.mav.command_long_send(
        ts, tc, mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, 0, 0, 0, 0, 0, 0, 0, alt
    )
    for _ in range(20):
        msg = m.recv_match(type="GLOBAL_POSITION_INT", blocking=True, timeout=3)
        if msg:
            rel = msg.relative_alt / 1000
            print(f"   alt(rel)={rel:5.1f}m")
            if rel >= alt * 0.9:
                break
        time.sleep(1)
    hb = vehicle_hb()
    mode = mavutil.mode_string_v10(hb) if hb else "?"
    print(f"[완료] 이륙 — mode={mode}. 이제 라이브 브리지/주입을 실행하세요.")
    m.close()


if __name__ == "__main__":
    main()
