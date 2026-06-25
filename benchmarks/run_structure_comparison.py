#!/usr/bin/env python3
"""에이전트 구조 비교 — Baseline vs Parallel vs Router vs Supervisor.

run_kpi.py 의 라벨셋(정탐11+오탐6)을 각 구조에 통과시켜 품질(P/R/FPR/FNR)과
효율(총 지연·LLM호출수·RAG호출수)을 실측 비교한다. RAGFlow·Ollama 라이브 전제.
출력: benchmarks/results/structure_comparison.json + 콘솔 표.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import json
from pathlib import Path
import sys
from typing import cast

from langgraph.graph.state import CompiledStateGraph

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.investigation_agent import ContextRetriever  # noqa: E402
from agents.structures import (  # noqa: E402
    build_baseline,
    build_parallel,
    build_router,
    build_supervisor,
    build_wizblue,
)
from agents.validation_agent import signal_judge  # noqa: E402
from benchmarks.run_kpi import _fp_alerts, _load_env, _timings, _tp_alerts  # noqa: E402
from core.llm import LLMClient  # noqa: E402
from core.models import RetrievedChunk, SOCState, Verdict  # noqa: E402
from tools.ragflow_tool import RagflowRetrievalTool  # noqa: E402

StructureBuilder = Callable[..., CompiledStateGraph[SOCState]]


class CountingRetriever:
    """aretrieve 호출수를 세는 RAG 래퍼."""

    def __init__(self, inner: ContextRetriever) -> None:
        self._inner = inner
        self.calls = 0

    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        self.calls += 1
        return await self._inner.aretrieve(query, k=k)


class CountingLLM:
    """acomplete 호출수를 세는 LLM 래퍼."""

    def __init__(self, inner: LLMClient) -> None:
        self._inner = inner
        self.calls = 0

    async def acomplete(self, system: str, user: str) -> str:
        self.calls += 1
        return await self._inner.acomplete(system, user)


def _avg(xs: list[float]) -> float:
    return round(sum(xs) / len(xs), 2) if xs else 0.0


async def _run_structure(
    name: str,
    builder: StructureBuilder,
    retriever: ContextRetriever,
    llm: LLMClient | None,
) -> dict[str, object]:
    cr = CountingRetriever(retriever)
    cl = CountingLLM(llm) if llm is not None else None
    cases = [(a, Verdict.TRUE_POSITIVE) for a in _tp_alerts()]
    cases += [(a, Verdict.FALSE_POSITIVE) for a in _fp_alerts()]
    tp = fp = fn = tn = 0
    total_ms: list[float] = []
    for alert, label in cases:
        graph = builder(retriever=cr, llm=cl, judge=signal_judge)
        state = cast(SOCState, await graph.ainvoke({"alert": alert}))
        total_ms.append(sum(_timings(dict(state)).values()))
        pred = state["report"].verdict
        if label == Verdict.TRUE_POSITIVE:
            tp += int(pred == Verdict.TRUE_POSITIVE)
            fn += int(pred != Verdict.TRUE_POSITIVE)
        else:
            fp += int(pred == Verdict.TRUE_POSITIVE)
            tn += int(pred != Verdict.TRUE_POSITIVE)
    return {
        "structure": name,
        "precision": round(tp / (tp + fp), 3) if (tp + fp) else None,
        "recall": round(tp / (tp + fn), 3) if (tp + fn) else None,
        "fpr": round(fp / (fp + tn), 3) if (fp + tn) else None,
        "fnr": round(fn / (fn + tp), 3) if (fn + tp) else None,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "total_ms_avg": _avg(total_ms),
        "rag_calls": cr.calls,
        "llm_calls": cl.calls if cl is not None else 0,
    }


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

    structures: list[tuple[str, StructureBuilder]] = [
        ("0_baseline", build_baseline),
        ("1_parallel", build_parallel),
        ("2_router", build_router),
        ("3_supervisor", build_supervisor),
        ("4_wizblue", build_wizblue),
    ]
    rows = []
    for name, builder in structures:
        row = await _run_structure(name, builder, retriever, llm)
        rows.append(row)
        print(
            f"[{name}] P/R={row['precision']}/{row['recall']} "
            f"FPR/FNR={row['fpr']}/{row['fnr']} "
            f"총{row['total_ms_avg']}ms RAG×{row['rag_calls']} "
            f"LLM×{row['llm_calls']}"
        )

    out = ROOT / "benchmarks" / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / "structure_comparison.json").write_text(
        json.dumps(
            {"llm": "live" if llm is not None else "deterministic", "rows": rows},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print("\n" + "=" * 78)
    print(
        f"{'구조':<14}{'P':>5}{'R':>5}{'FPR':>6}{'FNR':>6}{'총ms':>10}{'RAG':>6}{'LLM':>6}"
    )
    print("-" * 78)
    for row in rows:
        print(
            f"{row['structure']:<14}{row['precision']!s:>5}{row['recall']!s:>5}"
            f"{row['fpr']!s:>6}{row['fnr']!s:>6}{row['total_ms_avg']:>10}"
            f"{row['rag_calls']:>6}{row['llm_calls']:>6}"
        )
    print(f"\n저장: {out / 'structure_comparison.json'}")


if __name__ == "__main__":
    asyncio.run(main())
