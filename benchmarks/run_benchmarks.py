#!/usr/bin/env python3
"""SOC 에이전트 / RAG 벤치마크 (LLM 불필요 지표).

측정:
  1) 라우팅 정확도  — TP→response, FP→rule_update (라벨된 22케이스: S1~S11 × {TP,FP})
  2) S5 포이즈닝 저항성 — 적대 제안등급('i') 주입 시 정책 등급 유지율
  3) 검색 Recall@k / MRR — 시나리오별 정답 incident_case 가 top-k 에 들어오는가

전제: RAGFlow 라이브(RAGFLOW_* env) + 시나리오 YAML(projects/dah2026/scenarios).
실행: python benchmarks/run_benchmarks.py
출력: 콘솔 표 + benchmarks/results/bench_results.json
"""
import asyncio
import json
import os
import sys
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.graph import build_soc_graph  # noqa: E402
from core.models import Alert, Severity, Verdict  # noqa: E402
from tools.ragflow_tool import KbCategory, RagflowRetrievalTool  # noqa: E402

SCEN_DIR = ROOT / "projects" / "dah2026" / "scenarios"
POC = ROOT / "projects" / "uav_soc_rag_poc"


def _load_env() -> None:
    cred = json.load(open(POC / "ragflow_credentials.json"))
    kb = json.load(open(POC / "raw_docs" / "ragflow_kb_info.json"))
    os.environ.setdefault("RAGFLOW_API_TOKEN", cred["api_token"])
    os.environ.setdefault("RAGFLOW_DATASET_ID", kb["dataset_id"])


def _alert_from_scenario(path: Path, ground_truth: Verdict) -> Alert:
    scn = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Alert(
        id=f"BENCH-{scn['scenario_id']}",
        scenario_id=scn["scenario_id"],
        title=scn["title"],
        asset_tier=scn.get("target_asset", {}).get("tier", ""),
        mission_phase=scn.get("mission_context", {}).get("phase", ""),
        severity_baseline=Severity(scn["severity_baseline"]),
        signals=scn.get("telemetry", {}).get("signals", []),
        expected_detection=scn.get("expected_detection", {}),
        defense_playbook=scn.get("defense_playbook", {}),
        ground_truth=ground_truth,
    )


def _golden_scenario_docs() -> dict[str, list[str]]:
    """KB 메타에서 시나리오(S1~S11) → 정답 incident_case 문서명 **집합**.

    한 시나리오에 사례가 여러 개면(예: S1) 그 중 아무거나 top-k 에 있으면 hit.
    """
    cred = json.load(open(POC / "ragflow_credentials.json"))
    kb = json.load(open(POC / "raw_docs" / "ragflow_kb_info.json"))["dataset_id"]
    base = cred["base_url"]
    h = {"Authorization": f"Bearer {cred['api_token']}"}
    docs, page = [], 1
    while True:
        d = requests.get(
            f"{base}/api/v1/datasets/{kb}/documents?page={page}&page_size=100",
            headers=h, timeout=60,
        ).json()["data"]
        docs += d["docs"]
        if len(docs) >= d["total"] or not d["docs"]:
            break
        page += 1
    mapping: dict[str, list[str]] = {}
    for d in docs:
        meta = d.get("meta_fields") or {}
        if meta.get("category") == "incident_cases" and meta.get("scenarios"):
            mapping.setdefault(meta["scenarios"], []).append(d["name"])
    return mapping


async def main() -> None:
    _load_env()
    scenarios = sorted(SCEN_DIR.glob("S*.yaml"), key=lambda p: int(p.name[1:].split("-")[0]))
    retriever = RagflowRetrievalTool()

    # --- 1) 라우팅 정확도 ---
    route_ok = 0
    route_total = 0
    for path in scenarios:
        for gt, expected in [(Verdict.TRUE_POSITIVE, "response"), (Verdict.FALSE_POSITIVE, "rule_update")]:
            graph = build_soc_graph(retriever=None)
            s = await graph.ainvoke({"alert": _alert_from_scenario(path, gt)})
            route_total += 1
            route_ok += int(s["report"].action_taken == expected)

    # --- 2) S5 저항성 (적대 'i' 주입 시 정책 등급 유지) ---
    resist_ok = 0
    for path in scenarios:
        alert = _alert_from_scenario(path, Verdict.TRUE_POSITIVE)
        baseline_graph = build_soc_graph(retriever=None)
        clean = await baseline_graph.ainvoke({"alert": alert})
        poisoned_alert = alert.model_copy(update={"llm_suggested_severity": Severity.INFO})
        poisoned = await build_soc_graph(retriever=None).ainvoke({"alert": poisoned_alert})
        resist_ok += int(clean["severity"] == poisoned["severity"])

    # --- 3) 검색 Recall@5 / MRR ---
    golden = _golden_scenario_docs()
    recall_hits = 0
    rr_sum = 0.0
    recall_total = 0
    details: list[dict[str, object]] = []
    for path in scenarios:
        scn = yaml.safe_load(path.read_text(encoding="utf-8"))
        sid = "S" + path.name[1:].split("-")[0]
        gold = golden.get(sid)
        if not gold:
            continue
        recall_total += 1
        query = f"{scn['title']} {' '.join(scn.get('telemetry', {}).get('signals', []))}"
        hits = await retriever.aretrieve(query, k=5, category=KbCategory.INCIDENT_CASES)
        rank = next(
            (i + 1 for i, c in enumerate(hits) if any(c.source.endswith(g) for g in gold)),
            0,
        )
        recall_hits += int(rank > 0)
        rr_sum += (1.0 / rank) if rank else 0.0
        details.append({"scenario": sid, "gold": gold, "rank": rank})

    results = {
        "routing_accuracy": round(route_ok / route_total, 3),
        "routing_detail": f"{route_ok}/{route_total}",
        "s5_resistance_rate": round(resist_ok / len(scenarios), 3),
        "s5_detail": f"{resist_ok}/{len(scenarios)}",
        "recall_at_5": round(recall_hits / recall_total, 3) if recall_total else None,
        "mrr": round(rr_sum / recall_total, 3) if recall_total else None,
        "recall_detail": f"{recall_hits}/{recall_total}",
        "recall_per_scenario": details,
    }
    out = ROOT / "benchmarks" / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / "bench_results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2))

    print("=" * 56)
    print("SOC / RAG 벤치마크 결과 (LLM 불필요 지표)")
    print("=" * 56)
    print(f"라우팅 정확도(TP→response/FP→rule_update): {results['routing_accuracy']} ({results['routing_detail']})")
    print(f"S5 포이즈닝 저항성(적대주입 시 등급 유지)  : {results['s5_resistance_rate']} ({results['s5_detail']})")
    print(f"검색 Recall@5                              : {results['recall_at_5']} ({results['recall_detail']})")
    print(f"검색 MRR                                   : {results['mrr']}")
    print("\n시나리오별 정답 문서 순위(rank, 0=미검출):")
    for d in details:
        print(f"  {d['scenario']}: rank={d['rank']}  ({d['gold']})")
    print(f"\n저장: {out / 'bench_results.json'}")


if __name__ == "__main__":
    asyncio.run(main())
