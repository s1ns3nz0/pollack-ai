#!/usr/bin/env python3
"""실 uav-sim-env telemetry-tap NDJSON → SOC 브리지 (라이브).

telemetry-tap 컨테이너의 stdout(NDJSON)을 `docker logs -f` 로 받아 SimBridge 에
투입하고, GPS 스푸핑 탐지 시 6-에이전트 SOC 결과를 대시보드로 출력한다.

사전: uav-sim-env 가 `docker compose up -d` 로 기동(telemetry 흐름).
실행: python scripts/sim_live_bridge.py [--auto] [--no-rtb]
  --auto    : 운용자 승인 없이 RTB 자동 송신(무인 데모)
  --no-rtb  : 폐루프 작동 비활성(권고만 출력)
GPS 스푸핑 주입(다른 터미널):
  python scripts/sim_inject_gps_spoof.py    # SIM_GPS 파라미터 변조
"""

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
POC = ROOT / "projects" / "uav_soc_rag_poc"
TAP_CONTAINER = os.environ.get("TAP_CONTAINER", "uav-telemetry-tap")


def _load_env() -> None:
    cred = json.load(open(POC / "ragflow_credentials.json"))
    kb = json.load(open(POC / "raw_docs" / "ragflow_kb_info.json"))
    os.environ.setdefault("RAGFLOW_API_TOKEN", cred["api_token"])
    os.environ.setdefault("RAGFLOW_DATASET_ID", kb["dataset_id"])


_load_env()

from core.llm import get_llm_client  # noqa: E402
from sim_bridge.actuator import (  # noqa: E402
    ActuatorError,
    MavlinkActuator,
    RtbActuator,
    rtb_recommended,
)
from sim_bridge.bridge import BridgeEvent, SimBridge  # noqa: E402
from sim_bridge.models import TelemetryRecord  # noqa: E402
from tools.ragflow_tool import RagflowRetrievalTool  # noqa: E402


async def _telemetry_records():
    """telemetry-tap 컨테이너 stdout(NDJSON) 라인 → TelemetryRecord 스트림."""
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "logs",
        "-f",
        "--tail",
        "0",
        TAP_CONTAINER,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    assert proc.stdout is not None
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        text = line.decode("utf-8", "ignore").strip()
        if not text.startswith("{"):
            continue
        try:
            data = json.loads(text)
        except ValueError:
            continue
        if data.get("MsgType") in ("EKF_STATUS_REPORT", "GPS_RAW_INT"):
            yield TelemetryRecord.from_ndjson(data)


async def _actuate_rtb(event: BridgeEvent, actuator: RtbActuator, auto: bool) -> None:
    """RTB 권고 시 (운용자 승인 후) 폐루프 RETURN_TO_LAUNCH 를 송신한다.

    Args:
        event: SOC 처리 결과.
        actuator: RTB 명령 송신 작동기.
        auto: True 면 승인 없이 자동 송신(무인 데모).
    """
    if not rtb_recommended(event.report, event.alert.defense_playbook):
        return
    if auto:
        approved = True
        print("  [HITL] --auto: 운용자 승인 생략, RTB 자동 송신")
    else:
        ans = await asyncio.to_thread(
            input, "  [HITL] 고위험 정탐 — RTB(자동 복귀) 실행 승인? [y/N] "
        )
        approved = ans.strip().lower() in ("y", "yes")
    if not approved:
        print("  [HITL] 운용자 거부 — RTB 미실행(권고만 기록)")
        return
    try:
        result = await asyncio.to_thread(actuator.send_rtb, event.alert.asset_id)
        print(f"  ✅ 폐루프 작동 : {result}")
        print("     → QGC(noVNC)에서 드론 복귀(RTL) 시각화됨")
    except ActuatorError as e:
        print(f"  ⚠️  RTB 송신 실패: {e}")


async def main() -> None:
    auto = "--auto" in sys.argv
    no_rtb = "--no-rtb" in sys.argv
    actuator: RtbActuator | None = None if no_rtb else MavlinkActuator()

    print("█" * 66)
    print("  uav-sim-env(실 시뮬) → pollack-ai SOC  |  라이브 탐지·대응")
    print(f"  telemetry-tap: {TAP_CONTAINER}  (docker logs 스트림)")
    loop_mode = (
        "비활성(--no-rtb)" if no_rtb else ("자동(--auto)" if auto else "HITL 승인")
    )
    print(f"  폐루프 RTB    : {loop_mode}")
    print("█" * 66)
    print("\n[대기] 정상 텔레메트리 모니터링 중... (GPS 스푸핑 주입 시 탐지)")

    bridge = SimBridge(retriever=RagflowRetrievalTool(), llm=get_llm_client())
    seen = 0
    async for record in _telemetry_records():
        seen += 1
        if seen % 50 == 0:
            print(f"  ... 텔레메트리 {seen}건 정상 (PosHorizVar 정상범위)")
        event = await bridge.process(record)
        if event is None:
            continue
        r = event.report
        print("\n" + "─" * 66)
        print("  🚨 SOC 탐지·대응 (6-에이전트, 실 RAG/LLM)")
        print("─" * 66)
        print(f"  경보      : {event.alert.title}")
        print(f"  탐지 신호 : {', '.join(event.alert.signals)}")
        print(f"  심각도    : {r.severity}  ({' '.join(event.severity_rationale)})")
        print(f"  RAG 근거  : {len(event.similar_cases)}건")
        print(f"  LLM 분석  : {event.summary[:160]}...")
        print(f"  판정/대응 : {r.verdict} → {r.action_taken}")
        print("  → 권고    : INS 페일오버 + 자동 RTB")
        print("─" * 66)
        if actuator is not None:
            await _actuate_rtb(event, actuator, auto)


if __name__ == "__main__":
    asyncio.run(main())
