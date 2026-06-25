#!/usr/bin/env python3
"""시나리오별 분해표 — 집계값 뒤의 케이스별 실제 동작을 펼친다.

run_structure_comparison.py 가 17케이스 평균만 내보내는 데 반해, 본 하니스는
각 시나리오(S1~S11 + 오탐 6) × 각 구조에 대해 판정·지연·RAG/LLM 호출수를
케이스별로 기록한다. 집계 결론(품질 동률·효율 차이)이 모든 시나리오에서 균일하게
성립하는지 검증한다.

전제: RAGFlow·Ollama 라이브. 실행: python benchmarks/run_per_scenario.py
출력: benchmarks/results/per_scenario.json + 콘솔 표.
"""
import asyncio
import json
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
from benchmarks.run_structure_comparison import CountingLLM, CountingRetriever  # noqa: E402
from core.llm import LLMClient  # noqa: E402
from core.models import SOCState, Verdict  # noqa: E402
from tools.ragflow_tool import RagflowRetrievalTool  # noqa: E402

STRUCTURES = [
    ("baseline", build_baseline),
    ("parallel", build_parallel),
    ("router", build_router),
    ("supervisor", build_supervisor),
    ("wizblue", build_wizblue),
]


async def main() -> None:
    _load_env()
    retriever = RagflowRetrievalTool()
    llm: LLMClient | None = None
    try:
        from core.llm import get_llm_client

        llm = get_llm_client()
        await llm.acomplete("요약", "워밍")
    except Exception:  # noqa: BLE001
        llm = None

    cases = [(a, Verdict.TRUE_POSITIVE) for a in _tp_alerts()]
    cases += [(a, Verdict.FALSE_POSITIVE) for a in _fp_alerts()]

    rows: list[dict[str, object]] = []
    for name, builder in STRUCTURES:
        cr = CountingRetriever(retriever)
        cl = CountingLLM(llm) if llm is not None else None
        for alert, label in cases:
            rag0 = cr.calls
            llm0 = cl.calls if cl is not None else 0
            graph = builder(retriever=cr, llm=cl, judge=signal_judge)
            state = cast(SOCState, await graph.ainvoke({"alert": alert}))
            pred = state["report"].verdict
            rows.append({
                "scenario": alert.scenario_id,
                "case_id": alert.id,
                "label": label.value,
                "structure": name,
                "verdict": pred.value,
                "correct": pred == label,
                "ms": round(sum(_timings(dict(state)).values()), 1),
                "rag": cr.calls - rag0,
                "llm": (cl.calls - llm0) if cl is not None else 0,
            })

    out = ROOT / "benchmarks" / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / "per_scenario.json").write_text(
        json.dumps({"llm": "live" if llm else "deterministic", "rows": rows},
                   ensure_ascii=False, indent=2)
    )

    # 콘솔: 시나리오별 그룹, 구조는 열(지연 ms)로 — 판정 정오는 ✓/✗
    order = [a.id for a, _ in cases]
    by_case: dict[str, dict[str, dict[str, object]]] = {}
    for r in rows:
        by_case.setdefault(str(r["case_id"]), {})[str(r["structure"])] = r
    snames = [n for n, _ in STRUCTURES]
    print("=" * 96)
    print("시나리오별 분해 — 셀=지연ms(판정 ✓/✗), 모든 구조 동일판정이면 품질 균일")
    print("-" * 96)
    print(f"{'케이스':<26}{'라벨':>4}  " + "".join(f"{n:>13}" for n in snames))
    for cid in order:
        grp = by_case.get(cid, {})
        any_r = next(iter(grp.values()))
        lab = "TP" if any_r["label"] == "true_positive" else "FP"
        cells = ""
        for n in snames:
            r = grp.get(n)
            if r is None:
                cells += f"{'-':>13}"; continue
            mark = "✓" if r["correct"] else "✗"
            cells += f"{str(r['ms'])+mark:>13}"
        print(f"{cid:<26}{lab:>4}  {cells}")
    # 구조별 RAG/LLM 합계
    print("-" * 96)
    for n in snames:
        rr = [r for r in rows if r["structure"] == n]
        tot_ms = round(sum(float(r["ms"]) for r in rr), 0)
        rag = sum(int(r["rag"]) for r in rr)
        llmc = sum(int(r["llm"]) for r in rr)
        acc = sum(1 for r in rr if r["correct"])
        print(f"{n:<14} 정확 {acc}/{len(rr)}  총RAG×{rag} 총LLM×{llmc}  합지연 {tot_ms}ms")
    print(f"\n저장: {out / 'per_scenario.json'}")


if __name__ == "__main__":
    asyncio.run(main())
