#!/usr/bin/env python3
"""FP-재발률 / Rule Effectiveness 벤치마크 (자가발전 억제 KPI).

맥락 의존 FP(신호+룰+근거가 있어 결정론 judge 가 TP 와 구별 못 하는 양성 이벤트)를
2라운드로 돌려 자가발전 억제 효과를 정량화한다.

  라운드1(메모리 없음): 맥락 FP → 오경보(TP 판정)
  → 확정 FP 를 exp/ 에 적립(env_verified — 라벨셋이 ground truth)
  라운드2(메모리 있음): 같은 맥락 FP → 억제(FP 판정)

지표:
  - FP-재발률      = 라운드2 오경보 / 라운드1 오경보   (낮을수록 좋음)
  - Rule Effectiveness = 1 − FP-재발률                  (높을수록 좋음)
  - 재현율 무손실  = 진짜 공격(다른 신호)이 양 라운드 모두 TP 유지

KPI 시트의 Rule Update · Rule Effectiveness(재오탐 감소율) 칸을 채운다.
결정론 — 외부(RAGFlow/LLM) 불요. 실행: python benchmarks/run_fp_recurrence.py
출력: 콘솔 표 + benchmarks/results/fp_recurrence.json
"""

import asyncio
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.graph import build_soc_graph  # noqa: E402
from agents.validation_agent import signal_judge  # noqa: E402
from core.experience import (  # noqa: E402
    InMemoryExperienceStore,
    MemoryReadGate,
    MemoryWriteGate,
)
from core.models import (  # noqa: E402
    Alert,
    EnvVerdict,
    ExperienceRecord,
    JudgeFeatures,
    Provenance,
    RetrievedChunk,
    Severity,
    SOCState,
    Verdict,
)

# 맥락 의존 FP — 신호+룰+근거가 있어 "정탐처럼 보이는" 양성 이벤트(라벨=오탐).
_FP_CASES: list[dict[str, object]] = [
    {
        "id": "AUTH-RETASK",
        "title": "인가 운용자 기체 재지정",
        "signals": ["기체 재지정 1건(인가 계정·근무시간·화이트리스트)"],
    },
    {
        "id": "SATCOM-MAINT",
        "title": "예정된 SATCOM 점검 재접속",
        "signals": ["SATCOM 단말 재접속(예정 점검창 내)"],
    },
    {
        "id": "FW-SIGNED-UPDATE",
        "title": "정상 펌웨어 업데이트(서명·SBOM 일치)",
        "signals": ["펌웨어 해시 변경(서명 유효, SBOM 등록됨)"],
    },
    {
        "id": "C2-RSSI-WEATHER",
        "title": "기상에 의한 C2 RSSI 일시 저하",
        "signals": ["C2 RSSI 일시 -8dB(30초 내 자동 회복)"],
    },
]

# 진짜 공격 — 다른 신호. 억제가 재현율을 깎지 않는지 대조(양 라운드 TP 유지 기대).
_ATTACK_CASE: dict[str, object] = {
    "id": "GPS-SPOOF",
    "title": "GPS/GNSS 스푸핑(실공격)",
    "signals": ["GNSS-INS 잔차 급증", "위성수 급감"],
}


class _StubRetriever:
    """kb/ 신뢰 청크 1건 반환 → similar_cases 채워 corroborated(맥락 FP 가 오경보).

    실 RAGFlow 대신 결정론 스텁(벤치마크 재현성). 맥락 FP 는 실제로 과거 유사
    정상사례가 있어 검색되는 것이 자연스럽다.
    """

    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        return [RetrievedChunk(text="유사 정상사례", source="kb/case.md", score=0.9)]


def _alert(case: dict[str, object], ground_truth: Verdict) -> Alert:
    """케이스 dict → Alert(룰 보유 = has_rule, 라벨 = ground_truth)."""
    return Alert(
        id=f"FPR-{case['id']}",
        scenario_id=f"BENCH-{case['id']}",
        title=str(case["title"]),
        asset_tier="T2-Important",
        mission_phase="on-station",
        severity_baseline=Severity.MEDIUM,
        signals=list(case["signals"]),  # type: ignore[arg-type]
        expected_detection={"sigma_rule": f"{str(case['id']).lower()}.yml"},
        ground_truth=ground_truth,
    )


def _fp_record(alert: Alert, confidence: float) -> ExperienceRecord:
    """라운드1 확정 오탐 → 적립용 경험 레코드(신뢰=라벨셋 ground truth)."""
    return ExperienceRecord(
        scenario_id=alert.scenario_id,
        signals=list(alert.signals),
        asset_id=alert.asset_id,
        asset_tier=alert.asset_tier,
        verdict=Verdict.FALSE_POSITIVE,
        severity=Severity.LOW,
        judge_features=JudgeFeatures(
            has_signal=bool(alert.signals),
            has_rule=True,
            corroborated=True,
            confidence=confidence,
        ),
        env_verdict=EnvVerdict.CONFIRMED_FP,
        provenance=Provenance.ENV_VERIFIED,
    )


async def _run_once(
    alert: Alert, reader: MemoryReadGate | None
) -> tuple[Verdict, SOCState]:
    """경보 1건을 파이프라인에 통과시켜 (최종 verdict, 상태)를 반환."""
    graph = build_soc_graph(
        retriever=_StubRetriever(), experience=reader, judge=signal_judge
    )
    state = await graph.ainvoke({"alert": alert})
    return state["report"].verdict, state


async def main() -> None:
    store = InMemoryExperienceStore()
    write_gate = MemoryWriteGate(store)
    reader = MemoryReadGate(store)

    fp_alerts = [_alert(c, Verdict.FALSE_POSITIVE) for c in _FP_CASES]
    attack = _alert(_ATTACK_CASE, Verdict.TRUE_POSITIVE)

    # ── 라운드 1 (메모리 없음): 맥락 FP 오경보 수 측정 + 확정 FP 적립 ──
    round1_false_alarms = 0
    written = 0
    for alert in fp_alerts:
        verdict, state = await _run_once(alert, reader=None)
        if verdict == Verdict.TRUE_POSITIVE:  # 맥락 FP 인데 정탐 = 오경보
            round1_false_alarms += 1
            inv = state["investigation"]
            decision = await write_gate.submit(_fp_record(alert, inv.confidence))
            written += int(decision.written)
    attack_r1, _ = await _run_once(attack, reader=None)

    # ── 라운드 2 (메모리 있음): 같은 맥락 FP 가 억제되는지 + 공격 재현율 유지 ──
    round2_false_alarms = 0
    for alert in fp_alerts:
        verdict, _ = await _run_once(alert, reader=reader)
        if verdict == Verdict.TRUE_POSITIVE:
            round2_false_alarms += 1
    attack_r2, _ = await _run_once(attack, reader=reader)

    recurrence = (
        round(round2_false_alarms / round1_false_alarms, 3)
        if round1_false_alarms
        else None
    )
    effectiveness = round(1.0 - recurrence, 3) if recurrence is not None else None
    recall_preserved = (
        attack_r1 == Verdict.TRUE_POSITIVE and attack_r2 == Verdict.TRUE_POSITIVE
    )

    results = {
        "fp_cases": len(fp_alerts),
        "round1_false_alarms": round1_false_alarms,
        "memory_written": written,
        "round2_false_alarms": round2_false_alarms,
        "fp_recurrence_rate": recurrence,
        "rule_effectiveness": effectiveness,
        "attack_verdict_round1": attack_r1.value,
        "attack_verdict_round2": attack_r2.value,
        "recall_preserved": recall_preserved,
    }
    out = ROOT / "benchmarks" / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / "fp_recurrence.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2)
    )

    print("=" * 60)
    print("FP-재발률 / Rule Effectiveness (자가발전 억제)")
    print("=" * 60)
    print(f"  맥락 FP 케이스           : {results['fp_cases']}")
    print(f"  라운드1 오경보(메모리 X) : {round1_false_alarms}")
    print(f"  exp/ 적립(확정 오탐)     : {written}")
    print(f"  라운드2 오경보(메모리 O) : {round2_false_alarms}")
    print(f"  FP-재발률                : {recurrence}")
    print(f"  Rule Effectiveness       : {effectiveness}")
    print(
        f"  재현율 무손실(공격 TP→TP): {recall_preserved} "
        f"({attack_r1.value}→{attack_r2.value})"
    )
    print(f"\n저장: {out / 'fp_recurrence.json'}")


if __name__ == "__main__":
    asyncio.run(main())
