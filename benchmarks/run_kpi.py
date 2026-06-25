#!/usr/bin/env python3
"""6-에이전트 SOC KPI 산출 하니스 (에이전트 25점 / 방어 25점 증거).

라벨된 평가셋(정탐=S1~S11 실공격 + 오탐=양성 노이즈)을 파이프라인에 통과시켜
에이전트별 KPI 를 측정한다. 판정은 `signal_judge`(근거 기반, 라벨 비참조)를 쓰므로
FPR/FNR 이 의미를 갖는다.

측정:
  - Triage      : MTTT (Mean Time To Triage, ms)
  - Investigation: Confidence Score(평균), Context(신뢰 사례 평균 건수)
  - Validation  : Precision / Recall / FPR / FNR (혼동행렬, 라벨 대비)
  - Response    : MTTC (Mean Time To Contain, ms), Playbook Success Rate
  - Report      : Report Latency(ms), Evidence Completeness

전제: RAGFlow 라이브(RAGFLOW_*), 로컬 Ollama(.env). 실행: python benchmarks/run_kpi.py
출력: 콘솔 표 + benchmarks/results/kpi_results.json
"""
import asyncio
import json
import os
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.graph import build_soc_graph  # noqa: E402
from agents.validation_agent import signal_judge  # noqa: E402
from core.models import Alert, Severity, Verdict  # noqa: E402
from tools.ragflow_tool import RagflowRetrievalTool  # noqa: E402

SCEN_DIR = ROOT / "projects" / "dah2026" / "scenarios"
POC = ROOT / "projects" / "uav_soc_rag_poc"


def _load_env() -> None:
    cred = json.load(open(POC / "ragflow_credentials.json"))
    kb = json.load(open(POC / "raw_docs" / "ragflow_kb_info.json"))
    os.environ.setdefault("RAGFLOW_API_TOKEN", cred["api_token"])
    os.environ.setdefault("RAGFLOW_DATASET_ID", kb["dataset_id"])


def _tp_alerts() -> list[Alert]:
    """정탐(공격) 케이스 — S1~S11 시나리오에서 파생."""
    alerts: list[Alert] = []
    for path in sorted(SCEN_DIR.glob("S*.yaml"), key=lambda p: int(p.name[1:].split("-")[0])):
        scn = yaml.safe_load(path.read_text(encoding="utf-8"))
        alerts.append(
            Alert(
                id=f"KPI-TP-{scn['scenario_id']}",
                scenario_id=scn["scenario_id"],
                title=scn["title"],
                asset_tier=scn.get("target_asset", {}).get("tier", ""),
                mission_phase=scn.get("mission_context", {}).get("phase", ""),
                severity_baseline=Severity(scn["severity_baseline"]),
                signals=scn.get("telemetry", {}).get("signals", []),
                expected_detection=scn.get("expected_detection", {}),
                defense_playbook=scn.get("defense_playbook", {}),
                ground_truth=Verdict.TRUE_POSITIVE,
            )
        )
    return alerts


# 오탐(양성 노이즈) — 경보처럼 보이나 매칭 탐지룰/근거가 없어 기각돼야 하는 정상 이벤트.
_FP_CASES: list[dict[str, object]] = [
    {"id": "GPS-DEGRADE-URBAN", "title": "GPS 정확도 경미 저하(도심 협곡)",
     "sev": "l", "signals": ["위성수 14→9 경미 감소(EKF 잔차 정상범위)"]},
    {"id": "FW-SIGNED-UPDATE", "title": "정상 펌웨어 업데이트(서명·SBOM 일치)",
     "sev": "i", "signals": ["펌웨어 해시 변경(서명 유효, SBOM 등록됨)"]},
    {"id": "C2-RSSI-WEATHER", "title": "기상에 의한 C2 RSSI 일시 저하",
     "sev": "l", "signals": ["C2 RSSI 일시 -8dB(30초 내 자동 회복)"]},
    {"id": "AUTH-RETASK", "title": "인가 운용자 기체 재지정",
     "sev": "i", "signals": ["기체 재지정 1건(인가 계정·근무시간·화이트리스트)"]},
    {"id": "SATCOM-MAINT", "title": "예정된 SATCOM 점검 재접속",
     "sev": "i", "signals": ["SATCOM 단말 재접속(예정 점검창 내)"]},
    {"id": "EKF-TAKEOFF-CONVERGE", "title": "이륙 직후 EKF 수렴 트랜지언트",
     "sev": "l", "signals": ["이륙 직후 EKF 잔차 일시 상승 후 수렴(위성·플래그 정상)"]},
]


def _fp_alerts() -> list[Alert]:
    """오탐 케이스 — 매칭 탐지룰 없음(expected_detection 비움) → 근거 기반 판정 기각."""
    return [
        Alert(
            id=f"KPI-FP-{c['id']}",
            scenario_id=str(c["id"]),
            title=str(c["title"]),
            severity_baseline=Severity(str(c["sev"])),
            signals=list(c["signals"]),  # type: ignore[arg-type]
            expected_detection={},  # 매칭 룰 없음 = 양성 노이즈
            ground_truth=Verdict.FALSE_POSITIVE,
        )
        for c in _FP_CASES
    ]


def _timings(state: dict) -> dict[str, float]:
    out: dict[str, float] = {}
    for t in state.get("node_timings", []):
        out[str(t["node"])] = float(t["elapsed_ms"])
    return out


def _avg(xs: list[float]) -> float | None:
    return round(sum(xs) / len(xs), 2) if xs else None


async def main() -> None:
    _load_env()
    retriever = RagflowRetrievalTool()
    llm = None
    try:
        from core.llm import get_llm_client

        llm = get_llm_client()
        await llm.acomplete("요약", "워밍")  # 콜드로드 분리(타이밍 왜곡 방지)
    except Exception:  # noqa: BLE001 - LLM 미가용 시 결정론 폴백
        llm = None

    cases = [(a, Verdict.TRUE_POSITIVE) for a in _tp_alerts()]
    cases += [(a, Verdict.FALSE_POSITIVE) for a in _fp_alerts()]

    triage_ms, mttc_ms, report_ms, total_ms = [], [], [], []
    conf_scores, ctx_counts = [], []
    tp = fp = fn = tn = 0
    playbook_ok = playbook_total = 0
    evidence_ok = 0

    for alert, label in cases:
        graph = build_soc_graph(retriever=retriever, llm=llm, judge=signal_judge)
        state = await graph.ainvoke({"alert": alert})
        ts = _timings(state)
        triage_ms.append(ts.get("triage", 0.0))
        report_ms.append(ts.get("report", 0.0))
        total_ms.append(sum(ts.values()))
        inv = state["investigation"]
        conf_scores.append(inv.confidence)
        ctx_counts.append(float(len(inv.similar_cases)))
        pred = state["report"].verdict
        if label == Verdict.TRUE_POSITIVE:
            if pred == Verdict.TRUE_POSITIVE:
                tp += 1
            else:
                fn += 1
        else:
            if pred == Verdict.TRUE_POSITIVE:
                fp += 1
            else:
                tn += 1
        if pred == Verdict.TRUE_POSITIVE:
            mttc_ms.append(ts.get("response", 0.0))
            playbook_total += 1
            playbook_ok += int(bool(state.get("response") and state["response"].playbook_id))
        if state.get("oscal_evidence") is not None:
            evidence_ok += 1

    n = len(cases)
    precision = round(tp / (tp + fp), 3) if (tp + fp) else None
    recall = round(tp / (tp + fn), 3) if (tp + fn) else None
    fpr = round(fp / (fp + tn), 3) if (fp + tn) else None
    fnr = round(fn / (fn + tp), 3) if (fn + tp) else None

    results = {
        "eval_set": {"total": n, "tp_cases": tp + fn, "fp_cases": fp + tn},
        "triage_MTTT_ms": _avg(triage_ms),
        "investigation_confidence_avg": _avg(conf_scores),
        "investigation_context_avg_cases": _avg(ctx_counts),
        "validation": {
            "precision": precision, "recall": recall, "fpr": fpr, "fnr": fnr,
            "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        },
        "response_MTTC_ms": _avg(mttc_ms),
        "response_playbook_success_rate": (
            round(playbook_ok / playbook_total, 3) if playbook_total else None
        ),
        "report_latency_ms": _avg(report_ms),
        "report_evidence_completeness": round(evidence_ok / n, 3) if n else None,
        "pipeline_total_ms_avg": _avg(total_ms),
        "llm": "live" if llm is not None else "deterministic-fallback",
    }
    out = ROOT / "benchmarks" / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / "kpi_results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2)
    )

    v = results["validation"]
    print("=" * 60)
    print("6-에이전트 SOC KPI (라벨셋: 정탐 11 + 오탐 6)")
    print("=" * 60)
    print(f"  Triage   · MTTT                 : {results['triage_MTTT_ms']} ms")
    print(f"  Investig.· Confidence(평균)     : {results['investigation_confidence_avg']}")
    print(f"           · Context(신뢰사례 평균): {results['investigation_context_avg_cases']}건")
    print(f"  Validation·Precision/Recall     : {v['precision']} / {v['recall']}")
    print(f"           · FPR / FNR            : {v['fpr']} / {v['fnr']}  (혼동 {v['confusion']})")
    print(f"  Response · MTTC                 : {results['response_MTTC_ms']} ms")
    print(f"           · Playbook 성공률       : {results['response_playbook_success_rate']}")
    print(f"  Report   · Latency              : {results['report_latency_ms']} ms")
    print(f"           · Evidence 완전성       : {results['report_evidence_completeness']}")
    print(f"  파이프라인 총 소요(평균)        : {results['pipeline_total_ms_avg']} ms  [LLM:{results['llm']}]")
    print(f"\n저장: {out / 'kpi_results.json'}")


if __name__ == "__main__":
    asyncio.run(main())
