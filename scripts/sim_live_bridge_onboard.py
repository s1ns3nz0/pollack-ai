#!/usr/bin/env python3
"""S8 온보드 인식 AI 적대공격 → SOC 브리지 (라이브, 인식 스트림).

RED 인젝터가 append 하는 perception NDJSON 스트림 파일을 tail 해 OnboardAIDetector
로 탐지하고, 탐지 시 6-에이전트 SOC(실 RAG/LLM)를 돌려 인식 대시보드를 출력한 뒤
HITL 승인을 받아 실 SITL 드론을 LOITER hold(자율교전 차단) → 보수적 RTB 시킨다.

사전: uav-sim-env 기동 + 드론 이륙(scripts/sim_takeoff.py).
실행: python scripts/sim_live_bridge_onboard.py [--auto] [--no-rtb] [--no-llm]
  --auto    : 운용자 승인 없이 hold→RTB 자동 작동
  --no-rtb  : 폐루프 작동 비활성(대시보드만)
  --no-llm  : LLM 요약 생략(결정론 폴백)
적대 주입(다른 터미널):
  python scripts/sim_inject_onboard_evade.py
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
POC = ROOT / "projects" / "uav_soc_rag_poc"
STREAM = os.environ.get("PERCEPTION_STREAM", "/tmp/pollack_perception.ndjson")


def _load_env() -> None:
    with (POC / "ragflow_credentials.json").open(encoding="utf-8") as fh:
        cred = json.load(fh)
    with (POC / "raw_docs" / "ragflow_kb_info.json").open(encoding="utf-8") as fh:
        kb = json.load(fh)
    os.environ.setdefault("RAGFLOW_API_TOKEN", cred["api_token"])
    os.environ.setdefault("RAGFLOW_DATASET_ID", kb["dataset_id"])


_load_env()

from core.llm import get_llm_client  # noqa: E402
from sim_bridge.actuator import (  # noqa: E402
    ActuatorError,
    MavlinkActuator,
    OnboardActuator,
    hold_then_rtb,
)
from sim_bridge.bridge import BridgeEvent, SimBridge  # noqa: E402
from sim_bridge.detector import OnboardAIDetector  # noqa: E402
from sim_bridge.models import PerceptionRecord  # noqa: E402
from tools.ragflow_tool import RagflowRetrievalTool  # noqa: E402


async def _perception_records() -> AsyncIterator[PerceptionRecord]:
    """perception 스트림 파일(NDJSON)을 tail → PerceptionRecord 스트림."""
    Path(STREAM).parent.mkdir(parents=True, exist_ok=True)
    Path(STREAM).touch(exist_ok=True)
    proc = await asyncio.create_subprocess_exec(
        "tail",
        "-n",
        "0",
        "-F",
        STREAM,
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
        if data.get("MsgType") == "PERCEPTION_INFERENCE":
            yield PerceptionRecord.from_ndjson(data)


async def _actuate_hold_rtb(
    event: BridgeEvent, actuator: OnboardActuator, auto: bool
) -> None:
    """탐지 시 (운용자 승인 후) 자율교전 차단 hold → 보수적 RTB 를 작동한다."""
    if auto:
        print("  [HITL] --auto: 승인 생략, 자율교전 차단→RTB 자동 작동")
    else:
        ans = await asyncio.to_thread(
            input, "  [HITL] 인식 신뢰 불가 — 자율교전 차단 후 RTB 승인? [y/N] "
        )
        if ans.strip().lower() not in ("y", "yes"):
            print("  [HITL] 운용자 거부 — 작동 미실행(권고만 기록)")
            return
    try:
        msgs = await asyncio.to_thread(hold_then_rtb, actuator, event.alert.asset_id)
        for message in msgs:
            print(f"  ✅ 폐루프 작동 : {message}")
        print("     → QGC(noVNC)에서 정지(LOITER) 후 복귀(RTL) 시각화됨")
    except ActuatorError as exc:
        print(f"  ⚠️  작동 실패: {exc}")


async def main() -> None:
    auto = "--auto" in sys.argv
    no_rtb = "--no-rtb" in sys.argv
    no_llm = "--no-llm" in sys.argv
    actuator: OnboardActuator | None = None if no_rtb else MavlinkActuator()

    print("█" * 66)
    print("  S8 온보드 인식 AI 적대공격  |  라이브 탐지·대응")
    print(f"  perception 스트림: {STREAM}  (tail -F)")
    loop_mode = (
        "비활성(--no-rtb)" if no_rtb else ("자동(--auto)" if auto else "HITL 승인")
    )
    print(f"  폐루프 hold→RTB : {loop_mode}")
    print(f"  LLM 요약        : {'생략(--no-llm)' if no_llm else '실연동'}")
    print("█" * 66)
    print("\n[대기] 정상 인식 모니터링 중... (적대 주입 시 탐지)")

    bridge = SimBridge(
        retriever=RagflowRetrievalTool(),
        llm=None if no_llm else get_llm_client(),
    )
    detector = OnboardAIDetector()
    seen = 0
    async for record in _perception_records():
        seen += 1
        if seen % 20 == 0:
            print(f"  ... 인식 {seen}건 정상 (EO/IR 일치)")
        alert = detector.observe(record)
        if alert is None:
            continue
        event = await bridge.run_alert(alert)
        report = event.report
        print("\n" + "─" * 66)
        print("  🚨 SOC 탐지·대응 (6-에이전트, 실 RAG/LLM) — 온보드 인식 AI")
        print("─" * 66)
        print(f"  경보      : {event.alert.title}")
        print(f"  탐지 신호 : {', '.join(event.alert.signals)}")
        print(
            f"  심각도    : {report.severity}  ({' '.join(event.severity_rationale)})"
        )
        print(f"  RAG 근거  : {len(event.similar_cases)}건")
        for src in event.similar_cases[:5]:
            print(f"            · {src}")
        print(f"  LLM 분석  : {event.summary}")
        print(f"  판정/대응 : {report.verdict} → {report.action_taken}")
        print("  → 권고    : 센서융합 게이트 + 자율교전 차단 + 보수적 RTB")
        print("─" * 66)
        if actuator is not None:
            await _actuate_hold_rtb(event, actuator, auto)


if __name__ == "__main__":
    asyncio.run(main())
