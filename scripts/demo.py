#!/usr/bin/env python3
"""6-에이전트 SOC end-to-end 데모 (실 RAGFlow + 실 Ollama LLM + HITL).

전제: RAGFlow(docker) + 전용 Ollama 기동.
실행: python scripts/demo.py
RAGFLOW_API_TOKEN/DATASET_ID 는 projects/uav_soc_rag_poc 자격증명에서 자동 로드.
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

from langgraph.types import Command  # noqa: E402

from agents.graph import build_soc_graph  # noqa: E402
from core.llm import get_llm_client  # noqa: E402
from core.models import Alert, Severity, Verdict  # noqa: E402
from tools.ragflow_tool import RagflowRetrievalTool  # noqa: E402


def _alert(**kw):
    base = dict(
        id="DEMO-1",
        scenario_id="UAV-GPS-SPOOF-001",
        title="GPS/GNSS 스푸핑에 의한 항법 탈취",
        asset_tier="T1-Critical",
        mission_phase="ingress",
        severity_baseline=Severity.HIGH,
        signals=["GNSS-INS 잔차 급증", "C/N0 비정상 상승", "IMU/GPS 불일치"],
        expected_detection={"sigma_rule": "uav_gps_spoof_residual.yml"},
        defense_playbook={"id": "PB-NAV-RTB-01", "actions": ["INS 페일오버", "RTB"]},
        ground_truth=Verdict.TRUE_POSITIVE,
    )
    base.update(kw)
    return Alert(**base)


async def main() -> None:
    rag = RagflowRetrievalTool()
    llm = get_llm_client()

    print("=" * 64)
    print("① 일반 모드 — 실 RAG + 실 LLM (적대 등급주입 'i')")
    print("=" * 64)
    s = await build_soc_graph(retriever=rag, llm=llm).ainvoke(
        {"alert": _alert(llm_suggested_severity=Severity.INFO)}
    )
    print("심각도   :", s["report"].severity, " ", " ".join(s["severity_rationale"]))
    print("RAG 근거 :", len(s["investigation"].similar_cases), "건")
    print("LLM 요약 :", s["investigation"].summary[:160], "...")
    print("판정/대응:", s["report"].verdict, "→", s["report"].action_taken)
    print("가드레일 :", s["guardrail_flags"])

    print("\n" + "=" * 64)
    print("② HITL 모드 — 고위험 → 운용자 승인 대기 → 거부")
    print("=" * 64)
    gh = build_soc_graph(retriever=rag, llm=llm, hitl=True)
    cfg = {"configurable": {"thread_id": "demo-hitl"}}
    paused = await gh.ainvoke({"alert": _alert()}, config=cfg)
    print("⏸  승인 대기:", paused["__interrupt__"][0].value["message"])
    fin = await gh.ainvoke(Command(resume={"approved": False}), config=cfg)
    print("승인 결과:", fin["approval"].note)
    print("자동대응 :", fin["response"].auto_response)
    print("경로     :", " → ".join(fin["trace"]))


if __name__ == "__main__":
    asyncio.run(main())
