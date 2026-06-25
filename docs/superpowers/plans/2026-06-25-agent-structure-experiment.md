# 에이전트 구조 비교 실험 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans 로 태스크별 실행.

**Goal:** SOC 파이프라인을 3개 변형 구조(Parallel·Router·Supervisor)로 재구성하고, 호출수까지 재는 비교 하니스로 Baseline 대비 효율·품질을 실측한다.

**Architecture:** 단일 `build_soc_graph`에 선택적 훅 2개(`investigation` 에이전트 주입, `router` 분기 함수)를 추가해 DRY로 변형을 표현한다. 변형 에이전트/라우터/빌더는 `agents/structures.py`에, 비교 하니스는 `benchmarks/run_structure_comparison.py`에 둔다. 핵심 통찰: ① report/rule_update는 investigation 없이 동작 → Router가 ruleless 경보를 investigation 통째로 스킵. ② signal_judge 판정은 RAG의 similar_cases·confidence만 사용하고 LLM 요약은 미사용 → Supervisor가 결정-무관 LLM 요약을 조건부 스킵.

**Tech Stack:** Python 3.11, LangGraph, asyncio, 기존 agents/core 파이프라인.

**전제:** `cd /gpfs/home/jm00055/pollack-ai && source .venv/bin/activate`. 기존 미커밋 변경은 건드리지 말 것.

---

## Task 1: build_soc_graph 에 investigation/router 훅 추가 (Baseline 무변)

**Files:** Modify `agents/graph.py`

- [ ] **Step 1: 시그니처/배선 확장.** `build_soc_graph` 에 두 파라미터 추가하고, 기본값이면 기존과 100% 동일하게 동작.

`build_soc_graph` 시그니처에 추가(기존 인자 뒤):
```python
    investigation: InvestigationAgent | None = None,
    router: Callable[[SOCState], str] | None = None,
```
(상단 임포트에 `InvestigationAgent` 는 이미 있음. `Callable` 도 있음.)

`investigation = InvestigationAgent(settings, retriever, llm, ti)` 줄을 다음으로 교체:
```python
    investigation = investigation or InvestigationAgent(settings, retriever, llm, ti)
```

`graph.add_edge("triage", "investigation")` 줄을 다음으로 교체:
```python
    if router is not None:
        # Router: triage 직후 분기 — 명백 케이스는 investigation(RAG+LLM) 스킵하고 오탐 종결.
        graph.add_conditional_edges(
            "triage", router,
            {"investigate": "investigation", "skip": "rule_update"},
        )
    else:
        graph.add_edge("triage", "investigation")
```

- [ ] **Step 2: 회귀 확인 — 기본 호출 무변.**

Run: `pytest tests/__tests__/test_soc_agents.py -q`
Expected: 기존 테스트 전부 PASS (기본값 None 이면 배선 동일).

- [ ] **Step 3: 커밋**
```bash
git add agents/graph.py
git commit -m "feat: build_soc_graph 에 investigation/router 훅 추가(구조 실험용, 기본 무변)"
```

---

## Task 2: agents/structures.py — 변형 에이전트/라우터/빌더

**Files:** Create `agents/structures.py`

- [ ] **Step 1: 작성.**

```python
"""에이전트 파이프라인 구조 변형 — Baseline/Parallel/Router/Supervisor 빌더.

단일 build_soc_graph 의 훅(investigation 주입 / router 분기)으로 변형을 표현한다.
비교 실험(benchmarks/run_structure_comparison.py) 전용 — 프로덕션 경로는 Baseline.
"""

from __future__ import annotations

import asyncio

from agents.graph import build_soc_graph
from agents.investigation_agent import (
    ContextRetriever,
    InvestigationAgent,
    ThreatIntelTool,
)
from core.llm import LLMClient
from core.models import (
    InvestigationResult,
    RetrievedChunk,
    SOCState,
    ThreatIntelFinding,
    TiVerdict,
    Verdict,
)
from core.settings import Settings
from core.severity import SeverityEngine
from langgraph.graph.state import CompiledStateGraph


# ── 변형 #1: Parallel-Investigation ─────────────────────────────────────────
class ParallelInvestigationAgent(InvestigationAgent):
    """독립 하위작업(TI)을 RAG→LLM요약 사슬과 동시 실행 후 병합.

    RAG→요약은 의존 사슬이라 직렬 유지되고, TI 조회만 동시 오버랩된다(가설: 단축 제한적).
    """

    async def run(self, state: SOCState) -> SOCState:
        alert = state["alert"]
        # RAG+요약(직렬 사슬)과 TI(독립)를 동시 실행
        rag_task = asyncio.create_task(self._rag_and_summarize(alert))
        ti_task = asyncio.create_task(self._lookup_ti(alert.iocs))
        (trusted, summary, dropped, rag_degraded), ti_findings = await asyncio.gather(
            rag_task, ti_task
        )
        confidence = self._confidence_with_ti(trusted, rag_degraded, ti_findings)
        return self._assemble(alert, trusted, summary, confidence, ti_findings,
                              rag_degraded, dropped)


# ── 변형 #3: Supervisor 적응형 ───────────────────────────────────────────────
class SupervisorInvestigationAgent(InvestigationAgent):
    """경보별로 비용을 적응 조절: 결정-무관 LLM 요약을 '모호한 경우'에만 호출.

    signal_judge 판정은 RAG 의 similar_cases·confidence 만 사용하고 LLM 요약은
    미사용이므로, 근거가 충분(similar_cases 있음 or confidence≥0.5)하면 LLM 요약을
    스킵해도 품질(FPR/FNR) 무손실. 근거가 약한 모호 케이스에만 LLM 요약 생성.
    TI 는 IOC 있을 때만(기존 동작) 호출.
    """

    async def run(self, state: SOCState) -> SOCState:
        alert = state["alert"]
        trusted, dropped, rag_degraded = await self._retrieve_trusted(alert)
        ti_findings = await self._lookup_ti(alert.iocs)
        confidence = self._confidence_with_ti(trusted, rag_degraded, ti_findings)
        decisive = bool(trusted) or confidence >= 0.5
        if decisive:
            summary = f"{alert.title} 상관분석: 신뢰 사례 {len(trusted)}건 (LLM 요약 생략 — 근거 충분)"
        else:
            summary = await self._summarize(alert.title, alert.signals, trusted)
        return self._assemble(alert, trusted, summary, confidence, ti_findings,
                              rag_degraded, dropped)


# ── 변형 #2: Router 분기 함수 ────────────────────────────────────────────────
def router_skip_ruleless(state: SOCState) -> str:
    """매칭 탐지룰이 없는 경보는 investigation(RAG+LLM) 스킵하고 오탐 종결.

    signal_judge 의 has_rule 게이트를 triage 직후로 앞당긴다 — 룰 없으면 어차피
    오탐이므로 RAG+LLM 비용을 들이지 않는다(품질 동일, 효율↑).
    """
    alert = state["alert"]
    has_rule = bool(
        alert.expected_detection.get("sigma_rule")
        or alert.expected_detection.get("sentinel_rule")
    )
    return "investigate" if has_rule else "skip"


# ── 공통 헬퍼(InvestigationAgent 에 추가하는 내부 메서드는 Task 3에서) ─────────


def build_baseline(**kw: object) -> CompiledStateGraph[SOCState]:
    """구조 0 — 현재 순차 DAG."""
    return build_soc_graph(**kw)  # type: ignore[arg-type]


def build_parallel(
    *, settings: Settings | None = None, retriever: ContextRetriever | None = None,
    llm: LLMClient | None = None, ti: ThreatIntelTool | None = None, **kw: object,
) -> CompiledStateGraph[SOCState]:
    """구조 1 — TI 를 RAG+LLM 과 동시 실행."""
    s = settings or __import__("core.settings", fromlist=["get_settings"]).get_settings()
    inv = ParallelInvestigationAgent(s, retriever, llm, ti)
    return build_soc_graph(settings=s, retriever=retriever, llm=llm, ti=ti,
                           investigation=inv, **kw)  # type: ignore[arg-type]


def build_router(**kw: object) -> CompiledStateGraph[SOCState]:
    """구조 2 — ruleless 경보 조기탈출(investigation 스킵)."""
    return build_soc_graph(router=router_skip_ruleless, **kw)  # type: ignore[arg-type]


def build_supervisor(
    *, settings: Settings | None = None, retriever: ContextRetriever | None = None,
    llm: LLMClient | None = None, ti: ThreatIntelTool | None = None, **kw: object,
) -> CompiledStateGraph[SOCState]:
    """구조 3 — 적응형: 결정-무관 LLM 요약을 모호 케이스에만."""
    s = settings or __import__("core.settings", fromlist=["get_settings"]).get_settings()
    inv = SupervisorInvestigationAgent(s, retriever, llm, ti)
    return build_soc_graph(settings=s, retriever=retriever, llm=llm, ti=ti,
                           investigation=inv, **kw)  # type: ignore[arg-type]
```

> 주의: 위 변형 에이전트는 `InvestigationAgent` 의 내부 헬퍼 `_rag_and_summarize`,
> `_retrieve_trusted`, `_confidence_with_ti`, `_assemble` 를 호출한다 — Task 3에서
> `InvestigationAgent` 에 이 4개 헬퍼를 추출/추가한다(기존 run 동작 보존).

- [ ] **Step 2: 임포트 스모크**

Run: `python -c "import ast; ast.parse(open('agents/structures.py').read()); print('ok')"`
Expected: `ok`

(실행 검증은 Task 3 완료 후)

---

## Task 3: InvestigationAgent 내부 헬퍼 추출 (변형이 재사용, Baseline 동작 보존)

**Files:** Modify `agents/investigation_agent.py`

- [ ] **Step 1: `run` 의 본문을 4개 헬퍼로 리팩터(동작 동일).**

`InvestigationAgent` 클래스에 메서드 추가하고 `run` 을 헬퍼 호출로 재구성:

```python
    async def _retrieve_trusted(
        self, alert: Alert
    ) -> tuple[list[RetrievedChunk], int, bool]:
        """RAG 검색 + 출처검증(kb/). 반환: (신뢰청크, 격리수, 강등여부)."""
        query = f"{alert.scenario_id} {alert.title} {' '.join(alert.signals)}"
        chunks: list[RetrievedChunk] = []
        rag_degraded = False
        if self._retriever is not None:
            try:
                chunks = await self._retriever.aretrieve(query, k=5)
            except SOCPlatformError as exc:
                rag_degraded = True
                self._logger.warning("investigation RAG 검색 실패, 빈 컨텍스트로 계속: %s", exc)
        trusted = [c for c in chunks if c.source.startswith("kb/")]
        return trusted, len(chunks) - len(trusted), rag_degraded

    async def _rag_and_summarize(
        self, alert: Alert
    ) -> tuple[list[RetrievedChunk], str, int, bool]:
        """RAG 검색 후 (의존) LLM 요약까지 — 직렬 사슬. 반환에 dropped/degraded 포함."""
        trusted, dropped, rag_degraded = await self._retrieve_trusted(alert)
        summary = await self._summarize(alert.title, alert.signals, trusted)
        return trusted, summary, dropped, rag_degraded

    def _confidence_with_ti(
        self, trusted: list[RetrievedChunk], rag_degraded: bool,
        ti_findings: list[ThreatIntelFinding],
    ) -> float:
        """신뢰도 산정 + 악성 IOC 가산."""
        confidence = _confidence(trusted, rag_degraded)
        if any(f.verdict == TiVerdict.MALICIOUS for f in ti_findings):
            confidence = round(min(1.0, confidence + 0.2), 3)
        return confidence

    def _assemble(
        self, alert: Alert, trusted: list[RetrievedChunk], summary: str,
        confidence: float, ti_findings: list[ThreatIntelFinding],
        rag_degraded: bool, dropped: int,
    ) -> SOCState:
        """investigation 산출물 + 가드레일 플래그 조립."""
        result: SOCState = {
            "investigation": InvestigationResult(
                matched_signals=alert.signals, mitre=alert.mitre,
                similar_cases=trusted, summary=summary,
                confidence=confidence, ti_findings=ti_findings,
            ),
            "trace": ["investigation"],
        }
        flags: list[str] = []
        if rag_degraded:
            flags.append("RAG 검색 불가 — 빈 컨텍스트로 강등(대응 계속)")
        if dropped:
            flags.append(f"미신뢰 컨텍스트 {dropped}건 격리")
        if flags:
            result["guardrail_flags"] = flags
        return result
```

그리고 기존 `run` 을 헬퍼 사용으로 교체(동작 동일):
```python
    async def run(self, state: SOCState) -> SOCState:
        alert = state["alert"]
        trusted, summary, dropped, rag_degraded = await self._rag_and_summarize(alert)
        ti_findings = await self._lookup_ti(alert.iocs)
        confidence = self._confidence_with_ti(trusted, rag_degraded, ti_findings)
        self._logger.info(
            "investigation: alert=%s trusted=%d degraded=%s ti=%d conf=%.2f",
            alert.id, len(trusted), rag_degraded, len(ti_findings), confidence,
        )
        return self._assemble(alert, trusted, summary, confidence, ti_findings,
                              rag_degraded, dropped)
```
(상단 임포트에 `Alert` 추가: `from core.models import Alert, ...`.)

- [ ] **Step 2: 회귀 — investigation 동작 동일 확인.**

Run: `pytest tests/__tests__/test_soc_agents.py tests/__tests__/test_sim_bridge.py -q`
Expected: 전부 PASS (리팩터 전후 동작 동일).

- [ ] **Step 3: 변형 빌더 임포트/구성 스모크.**
```bash
python -c "
from agents.structures import build_baseline, build_parallel, build_router, build_supervisor
for b in (build_baseline, build_parallel, build_router, build_supervisor):
    g=b(retriever=None, llm=None); print('OK', b.__name__)
"
```
Expected: 4개 모두 `OK`.

- [ ] **Step 4: 커밋**
```bash
git add agents/investigation_agent.py agents/structures.py
git commit -m "feat: 구조 변형(Parallel/Router/Supervisor) + Investigation 헬퍼 추출"
```

---

## Task 4: 비교 하니스 — 호출수 계측 포함

**Files:** Create `benchmarks/run_structure_comparison.py`

- [ ] **Step 1: 작성.** `run_kpi.py` 의 평가셋(_tp_alerts/_fp_alerts/signal_judge)을 재사용하고, 리트리버/LLM 을 카운팅 래퍼로 감싼다.

```python
#!/usr/bin/env python3
"""에이전트 구조 비교 — Baseline vs Parallel vs Router vs Supervisor.

run_kpi.py 의 라벨셋(정탐11+오탐6)을 각 구조에 통과시켜 품질(P/R/FPR/FNR)과
효율(총 지연·LLM호출수·RAG호출수)을 실측 비교한다. RAGFlow·Ollama 라이브 전제.
출력: benchmarks/results/structure_comparison.json + 콘솔 표.
"""
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.structures import (  # noqa: E402
    build_baseline, build_parallel, build_router, build_supervisor,
)
from agents.validation_agent import signal_judge  # noqa: E402
from benchmarks.run_kpi import _fp_alerts, _load_env, _timings, _tp_alerts  # noqa: E402
from core.models import RetrievedChunk, Verdict  # noqa: E402
from tools.ragflow_tool import RagflowRetrievalTool  # noqa: E402


class CountingRetriever:
    """aretrieve 호출수를 세는 RAG 래퍼."""

    def __init__(self, inner: object) -> None:
        self._inner = inner
        self.calls = 0

    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        self.calls += 1
        return await self._inner.aretrieve(query, k=k)  # type: ignore[attr-defined]


class CountingLLM:
    """acomplete 호출수를 세는 LLM 래퍼."""

    def __init__(self, inner: object) -> None:
        self._inner = inner
        self.calls = 0

    async def acomplete(self, system: str, user: str) -> str:
        self.calls += 1
        return await self._inner.acomplete(system, user)  # type: ignore[attr-defined]


def _avg(xs: list[float]) -> float:
    return round(sum(xs) / len(xs), 2) if xs else 0.0


async def _run_structure(name: str, builder, retriever, llm) -> dict:
    cr = CountingRetriever(retriever)
    cl = CountingLLM(llm) if llm is not None else None
    cases = [(a, Verdict.TRUE_POSITIVE) for a in _tp_alerts()]
    cases += [(a, Verdict.FALSE_POSITIVE) for a in _fp_alerts()]
    tp = fp = fn = tn = 0
    total_ms: list[float] = []
    for alert, label in cases:
        g = builder(retriever=cr, llm=cl, judge=signal_judge)
        state = await g.ainvoke({"alert": alert})
        total_ms.append(sum(_timings(state).values()))
        pred = state["report"].verdict
        if label == Verdict.TRUE_POSITIVE:
            tp += pred == Verdict.TRUE_POSITIVE
            fn += pred != Verdict.TRUE_POSITIVE
        else:
            fp += pred == Verdict.TRUE_POSITIVE
            tn += pred != Verdict.TRUE_POSITIVE
    n = len(cases)
    return {
        "structure": name,
        "precision": round(tp / (tp + fp), 3) if (tp + fp) else None,
        "recall": round(tp / (tp + fn), 3) if (tp + fn) else None,
        "fpr": round(fp / (fp + tn), 3) if (fp + tn) else None,
        "fnr": round(fn / (fn + tp), 3) if (fn + tp) else None,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "total_ms_avg": _avg(total_ms),
        "rag_calls": cr.calls,
        "llm_calls": cl.calls if cl else 0,
    }


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

    structures = [
        ("0_baseline", build_baseline),
        ("1_parallel", build_parallel),
        ("2_router", build_router),
        ("3_supervisor", build_supervisor),
    ]
    rows = []
    for name, builder in structures:
        row = await _run_structure(name, builder, retriever, llm)
        rows.append(row)
        print(f"[{name}] P/R={row['precision']}/{row['recall']} "
              f"FPR/FNR={row['fpr']}/{row['fnr']} "
              f"총{row['total_ms_avg']}ms RAG×{row['rag_calls']} LLM×{row['llm_calls']}")

    out = ROOT / "benchmarks" / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / "structure_comparison.json").write_text(
        json.dumps({"llm": "live" if llm else "deterministic", "rows": rows},
                   ensure_ascii=False, indent=2)
    )
    print("\n" + "=" * 78)
    print(f"{'구조':<14}{'P':>5}{'R':>5}{'FPR':>6}{'FNR':>6}{'총ms':>10}{'RAG':>6}{'LLM':>6}")
    print("-" * 78)
    for r in rows:
        print(f"{r['structure']:<14}{r['precision']!s:>5}{r['recall']!s:>5}"
              f"{r['fpr']!s:>6}{r['fnr']!s:>6}{r['total_ms_avg']:>10}"
              f"{r['rag_calls']:>6}{r['llm_calls']:>6}")
    print(f"\n저장: {out / 'structure_comparison.json'}")


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 2: 구문 스모크**
Run: `python -c "import ast; ast.parse(open('benchmarks/run_structure_comparison.py').read()); print('ok')"`
Expected: `ok`

- [ ] **Step 3: 커밋**
```bash
git add benchmarks/run_structure_comparison.py
git commit -m "feat: 구조 비교 하니스(P/R/FPR/FNR + 총지연 + RAG/LLM 호출수)"
```

---

## Task 5: 전체 검증

- [ ] **Step 1: 린트/타입/테스트**
```bash
black agents/structures.py agents/graph.py agents/investigation_agent.py benchmarks/run_structure_comparison.py
ruff check agents/structures.py agents/graph.py agents/investigation_agent.py benchmarks/run_structure_comparison.py
mypy agents benchmarks/run_structure_comparison.py
pytest tests/__tests__/test_soc_agents.py tests/__tests__/test_sim_bridge.py -q
```
Expected: black 통과, ruff 0(신규 파일), mypy 0(가능 범위), pytest 전부 PASS.

> mypy 가 기존 파일의 선행 이슈를 내면 신규/변경 파일만 깨끗하면 됨.

- [ ] **Step 2: 커밋(있으면)**
```bash
git add -A agents benchmarks
git commit -m "chore: 구조 실험 포맷/린트 정리" || echo "no changes"
```

## 완료 기준
- [ ] `build_soc_graph` 기본 호출 무변(기존 테스트 PASS)
- [ ] 4개 빌더 모두 구성·실행 가능
- [ ] `run_structure_comparison.py` 가 4구조 × 17케이스 실측치(P/R/FPR/FNR + 총ms + RAG/LLM 호출수) JSON 출력
- [ ] 라이브 실측은 Opus 가 구현 후 직접 실행해 markdown 리포트에 기록
