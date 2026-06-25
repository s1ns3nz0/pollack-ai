#!/usr/bin/env python3
"""MAVLink 직결 라이브 브리지 — AirSim / 실 ArduPilot 어디든 연결.

telemetry-tap(docker) 대신 MAVLink 엔드포인트에서 EKF/GPS 를 직접 구독해 GPS 스푸핑
(S1)을 탐지하고 6-에이전트 SOC + 폐루프 RTB 를 수행한다. AirSim(언리얼) + ArduPilot
SITL 조합으로 사실적 드론 비행 위에서 SOC 데모를 돌릴 때 사용한다.

사전: MAVLink 엔드포인트(예: AirSim 노트북 `udpin:0.0.0.0:14550`, 실 SITL `tcp:HOST:5790`).
실행: python scripts/sim_live_bridge_mav.py --conn tcp:127.0.0.1:5790 [--auto] [--no-rtb] [--no-llm]
공격 주입(다른 터미널): python scripts/sim_inject_gps_spoof.py --conn <동일 엔드포인트>
"""
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
POC = ROOT / "projects" / "uav_soc_rag_poc"


def _arg(flag: str, default: str) -> str:
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default


def _load_env() -> None:
    try:
        cred = json.load(open(POC / "ragflow_credentials.json"))
        kb = json.load(open(POC / "raw_docs" / "ragflow_kb_info.json"))
        import os

        os.environ.setdefault("RAGFLOW_API_TOKEN", cred["api_token"])
        os.environ.setdefault("RAGFLOW_DATASET_ID", kb["dataset_id"])
    except (OSError, ValueError, KeyError):
        pass  # RAG 미설정 시 Investigation 이 빈 컨텍스트로 강등


_load_env()

from core.llm import get_llm_client  # noqa: E402
from sim_bridge.actuator import ActuatorError, MavlinkActuator  # noqa: E402
from sim_bridge.bridge import SimBridge  # noqa: E402
from sim_bridge.mavlink_source import mavlink_telemetry_records  # noqa: E402
from tools.ragflow_tool import RagflowRetrievalTool  # noqa: E402


async def main() -> None:
    conn = _arg("--conn", "tcp:127.0.0.1:5790")
    auto = "--auto" in sys.argv
    no_rtb = "--no-rtb" in sys.argv
    no_llm = "--no-llm" in sys.argv

    print("█" * 66)
    print("  MAVLink 직결 SOC  |  AirSim / 실 ArduPilot  라이브 탐지·대응")
    print(f"  MAVLink   : {conn}")
    print(f"  폐루프 RTB : {'비활성' if no_rtb else ('자동' if auto else 'HITL 승인')}")
    print(f"  LLM 요약  : {'생략' if no_llm else '실연동'}")
    print("█" * 66)
    print("\n[대기] MAVLink 텔레메트리 모니터링 중... (GPS 스푸핑 주입 시 탐지)")

    bridge = SimBridge(
        retriever=RagflowRetrievalTool(),
        llm=None if no_llm else get_llm_client(),
    )
    actuator = None if no_rtb else MavlinkActuator(connection=conn)
    seen = 0
    async for record in mavlink_telemetry_records(conn):
        seen += 1
        if seen % 100 == 0:
            print(f"  ... 텔레메트리 {seen}건 정상")
        event = await bridge.process(record)
        if event is None:
            continue
        r = event.report
        print("\n" + "─" * 66)
        print("  🚨 SOC 탐지·대응 (6-에이전트, 실 RAG/LLM) — MAVLink 직결")
        print("─" * 66)
        print(f"  경보      : {event.alert.title}")
        print(f"  탐지 신호 : {', '.join(event.alert.signals)}")
        print(f"  심각도    : {r.severity}  ({' '.join(event.severity_rationale)})")
        print(f"  RAG 근거  : {len(event.similar_cases)}건")
        for src in event.similar_cases[:5]:
            print(f"            · {src}")
        print(f"  LLM 분석  : {event.summary}")
        print(f"  판정/대응 : {r.verdict} → {r.action_taken}")
        print("─" * 66)
        if actuator is not None:
            approved = auto
            if not auto:
                ans = await asyncio.to_thread(
                    input, "  [HITL] RTB(자동 복귀) 실행 승인? [y/N] "
                )
                approved = ans.strip().lower() in ("y", "yes")
            if approved:
                try:
                    result = await asyncio.to_thread(
                        actuator.send_rtb, event.alert.asset_id
                    )
                    print(f"  ✅ 폐루프 작동 : {result}")
                except ActuatorError as exc:
                    print(f"  ⚠️  RTB 송신 실패: {exc}")
            else:
                print("  [HITL] 운용자 거부 — RTB 미실행")


if __name__ == "__main__":
    asyncio.run(main())
