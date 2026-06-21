#!/usr/bin/env python3
"""시뮬 텔레메트리 → SOC 가시화 데모 (합성 스트림 + 실 RAG/LLM).

uav-sim-env telemetry-tap NDJSON 과 동일 스키마의 합성 텔레메트리를 흘려
정상 비행 → GPS 스푸핑 주입 → 탐지 → 6-에이전트 SOC 처리를 터미널 대시보드로 본다.
실 시뮬 연결 시 synth_stream 을 telemetry-tap UDP/파일 스트림으로 교체하면 된다.

실행: python scripts/sim_demo.py
"""
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
POC = ROOT / "projects" / "uav_soc_rag_poc"


def _load_env() -> None:
    cred = json.load(open(POC / "ragflow_credentials.json"))
    kb = json.load(open(POC / "raw_docs" / "ragflow_kb_info.json"))
    os.environ.setdefault("RAGFLOW_API_TOKEN", cred["api_token"])
    os.environ.setdefault("RAGFLOW_DATASET_ID", kb["dataset_id"])


_load_env()

from core.llm import get_llm_client  # noqa: E402
from sim_bridge.bridge import SimBridge  # noqa: E402
from sim_bridge.synth import synth_records  # noqa: E402
from tools.ragflow_tool import RagflowRetrievalTool  # noqa: E402


async def main() -> None:
    print("\n" + "█" * 66)
    print("  uav-sim-env → pollack-ai SOC  |  실시간 탐지·대응 가시화 데모")
    print("  (합성 telemetry-tap 스트림 + 실 RAGFlow + 실 Ollama)")
    print("█" * 66)

    bridge = SimBridge(retriever=RagflowRetrievalTool(), llm=get_llm_client())
    records = synth_records(uav_id="MPD-001", benign_n=5)

    print("\n[텔레메트리 스트림] MPD-001 정찰 비행 중...")
    for i, rec in enumerate(records, 1):
        tag = rec.msg_type
        detail = ""
        if rec.pos_horiz_variance is not None:
            detail = f"PosHorizVar={rec.pos_horiz_variance:.2f}"
        elif rec.eph_cm is not None:
            detail = f"Eph={rec.eph_cm}cm Sats={rec.satellites_visible}"
        flag = "  ⚠️ 이상" if (rec.pos_horiz_variance or 0) > 0.8 or (rec.eph_cm or 0) > 500 else ""
        print(f"  {i:02d}. {tag:<20} {detail}{flag}")
        event = await bridge.process(rec)
        if event is None:
            continue
        # 탐지 → SOC 처리 결과 대시보드
        r = event.report
        print("\n" + "─" * 66)
        print("  🚨 SOC 탐지·대응 (6-에이전트)")
        print("─" * 66)
        print(f"  경보      : {event.alert.title}")
        print(f"  탐지 신호 : {', '.join(event.alert.signals)}")
        print(f"  심각도    : {r.severity}  ({' '.join(event.severity_rationale)})")
        print(f"  RAG 근거  : {len(event.similar_cases)}건  {event.similar_cases[0].replace('kb/','') if event.similar_cases else ''}")
        print(f"  LLM 분석  : {event.summary[:150]}...")
        print(f"  판정/대응 : {r.verdict} → {r.action_taken}  (플레이북 {r.scenario_id})")
        if event.guardrail_flags:
            print(f"  가드레일  : {event.guardrail_flags}")
        print(f"  → 권고    : INS 페일오버 + 자동 RTB (드론 복귀)")
        print("─" * 66)

    print("\n[완료] 정상 비행 → GPS 스푸핑 → 탐지 → SOC 대응까지 폐루프 데모 끝.")
    print("       실 시뮬 연결: synth_records → telemetry-tap(UDP :14552/파일) 교체.")


if __name__ == "__main__":
    asyncio.run(main())
