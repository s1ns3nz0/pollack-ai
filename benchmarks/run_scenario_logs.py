#!/usr/bin/env python3
"""시나리오별·구조별 실제 에이전트 로그 수집.

각 시나리오(S1~S11 + 오탐 6)를 각 구조(Baseline/Parallel/Router/Supervisor/WizBlue)로
실행하며 agents 가 남기는 실제 로그(soc.* 로거 INFO)를 캡처한다. 구조에 따라 로그가
어떻게 달라지는지(예: Router 는 investigation 로그 부재, Supervisor 는 LLM 요약 생략,
WizBlue 는 서브에이전트 병합) 부록용 원본을 만든다.

전제: RAGFlow·Ollama 라이브. 실행: python benchmarks/run_scenario_logs.py
출력: benchmarks/results/scenario_logs.json + docs/analysis/run-logs/per-scenario-agent-logs.md
"""
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.structures import (  # noqa: E402
    build_baseline,
    build_parallel,
    build_router,
    build_supervisor,
    build_wizblue,
)
from agents.validation_agent import signal_judge  # noqa: E402
from benchmarks.run_kpi import _fp_alerts, _load_env, _timings, _tp_alerts  # noqa: E402
from core.models import SOCState, Verdict  # noqa: E402
from tools.ragflow_tool import RagflowRetrievalTool  # noqa: E402

STRUCTS = [
    ("baseline", build_baseline), ("parallel", build_parallel),
    ("router", build_router), ("supervisor", build_supervisor),
    ("wizblue", build_wizblue),
]
SHORT = {  # 케이스ID → 짧은 시나리오명
    "UAV-GPS-SPOOF-001": "S1 GNSS스푸핑", "UAV-C2-HIJACK-002": "S2 C2하이재킹",
    "UAV-SATCOM-MITM-003": "S3 SATCOM MITM", "UAV-FW-SUPPLY-004": "S4 펌웨어공급망",
    "AI-RAG-POISON-005": "S5 RAG포이즈닝", "UAV-GCS-LATERAL-006": "S6 GCS횡적확산",
    "UGV-TELEOP-HIJACK-007": "S7 UGV탈취", "AI-ONBOARD-EVADE-008": "S8 온보드AI",
    "UAV-SWARM-SATURATION-009": "S9 군집포화", "UAV-SATCOM-TAKEDOWN-010": "S10 SATCOM무력화",
    "UAV-MOBILE-GCS-011": "S11 모바일GCS",
}


class ListHandler(logging.Handler):
    """soc.* 로그 레코드를 리스트로 캡처."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(f"{record.name.replace('soc.', '')}: {record.getMessage()}")


async def main() -> None:
    _load_env()
    retriever = RagflowRetrievalTool()
    llm = None
    try:
        from core.llm import get_llm_client

        llm = get_llm_client()
        await llm.acomplete("요약", "워밍")
    except Exception:  # noqa: BLE001
        llm = None

    soclog = logging.getLogger("soc")
    soclog.setLevel(logging.INFO)
    handler = ListHandler()
    soclog.addHandler(handler)
    soclog.propagate = False

    cases = [(a, Verdict.TRUE_POSITIVE) for a in _tp_alerts()]
    cases += [(a, Verdict.FALSE_POSITIVE) for a in _fp_alerts()]

    data: dict[str, object] = {}
    for alert, label in cases:
        sid = alert.scenario_id
        name = SHORT.get(sid, alert.id.replace("KPI-FP-", "오탐 "))
        entry: dict[str, object] = {"title": alert.title, "label": label.value,
                                    "structures": {}}
        for sname, builder in STRUCTS:
            handler.records = []
            graph = builder(retriever=retriever, llm=llm, judge=signal_judge)
            state = cast(SOCState, await graph.ainvoke({"alert": alert}))
            inv = state.get("investigation")
            cast(dict, entry["structures"])[sname] = {
                "logs": list(handler.records),
                "trace": " → ".join(state.get("trace", [])),
                "verdict": state["report"].verdict.value,
                "severity": state["severity"].value,
                "confidence": inv.confidence if inv else None,
                "summary": (inv.summary[:140] if inv else "(investigation 없음)"),
                "ms": round(sum(_timings(dict(state)).values()), 1),
            }
        data[name] = entry

    out = ROOT / "benchmarks" / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / "scenario_logs.json").write_text(json.dumps(data, ensure_ascii=False, indent=2))

    # 마크다운 부록 생성
    md = ["# 부록 E — 시나리오별·구조별 실제 에이전트 로그", "",
          "> 각 시나리오를 각 구조로 실행하며 `soc.*` 로거가 남긴 실제 로그.",
          "> 구조 차이가 로그에 드러난다(Router=investigation 부재, Supervisor=LLM 요약 생략,",
          "> WizBlue=서브에이전트 병합 등). 라이브 LLM/RAG, 지연(ms)은 jitter 있음.", ""]
    for name, entry in data.items():
        e = cast(dict, entry)
        md.append(f"## {name} — {e['title']}  ({'정탐' if e['label']=='true_positive' else '오탐'})")
        for sname, _b in STRUCTS:
            s = cast(dict, e["structures"])[sname]
            md.append(f"\n**[{sname}]** trace: `{s['trace']}` · 판정 {s['verdict']} · "
                      f"심각도 {s['severity']} · conf {s['confidence']} · {s['ms']}ms")
            md.append("```")
            for ln in s["logs"]:
                md.append(ln)
            md.append(f"(investigation 요약) {s['summary']}")
            md.append("```")
        md.append("")
    log_dir = ROOT / "docs" / "analysis" / "run-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "per-scenario-agent-logs.md").write_text("\n".join(md), encoding="utf-8")

    print(f"시나리오 {len(data)}개 × 구조 {len(STRUCTS)}개 로그 수집 완료")
    print(f"JSON: {out / 'scenario_logs.json'}")
    print(f"MD  : {log_dir / 'per-scenario-agent-logs.md'}")


if __name__ == "__main__":
    asyncio.run(main())
