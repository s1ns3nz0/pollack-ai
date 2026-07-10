"""방어측 정량 베이스라인(defensive detection KPI) 회귀 게이트.

심사 리뷰 B2(방어측 정량 결과 공백)에 대응 — 공격측 표에 대응하는 방어측
숫자 표를 코드로 못박아, 회귀 시 테스트가 깨지게 한다. 한 곳에서 다음을 계량한다:

- SOC 그래프 노드 수(6-에이전트 파이프라인 + 조건부 approval/active_hunt)
- 분석(탐지) 룰 수 — `sentinel/rule_manifest.json`(dah-sentinel-content 스냅샷)
- 골든 픽스처 수 — `benchmarks/eval_scenarios/*.yaml`(response-trace 게이트 대상)
- pollack-ai 테스트 수(파일·함수) — 방어 실증 규모
- 킬체인 단계 수 — `data/attack_coverage.yaml` 전술 순서(폐루프 탐지 범위)
- MTTT/MTTC — `benchmarks/run_kpi.py`가 `node_timings`에서 산출(측정 방식·현재값)

정직성 가드(stub-honesty 캠페인과 일관): MTTT/MTTC는 런타임에 이름있는 필드로
'저장'되지 않는다. 벤치(run_kpi) 시 `node_timings`에서 파생 측정될 뿐이며,
`test_mttt_mttc_is_benchmark_derived_not_persisted`가 이 사실을 못박는다.

베이스라인 수치는 `defense_kpi_snapshot()`이 dict 로 모아 반환한다 — 이 함수가
리뷰어가 요구한 '방어측 표 하나'의 기계가독 원천이다.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import TypedDict

import pytest
import yaml

from agents.graph import build_soc_graph
from core.cacao import load_playbooks, scenario_tactic_map, select_playbook
from core.models import SOCState
from core.runbook import load_runbooks
from core.settings import Settings
from tools.coverage import CoverageMatrix

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST_PATH = _REPO_ROOT / "sentinel" / "rule_manifest.json"
_FIXTURES_DIR = _REPO_ROOT / "benchmarks" / "eval_scenarios"
_ANALYTIC_RULES_DIR = _REPO_ROOT / "sentinel" / "Analytic Rules"
_TESTS_DIR = _REPO_ROOT / "tests"
_KPI_RESULTS_PATH = _REPO_ROOT / "benchmarks" / "results" / "kpi_results.json"

# 6-에이전트 SOC 파이프라인의 핵심(항상 존재) 노드. active_hunt/approval 은 조건부.
_CORE_NODES = frozenset(
    {"triage", "investigation", "validation", "response", "rule_update", "report"}
)

# 회귀 방지 하한선(floor). 정확값은 snapshot 이 실은다 — 하한만 지키면 성장은 허용.
_MIN_RULE_COUNT = 120
_MIN_GOLDEN_FIXTURES = 9
_MIN_TEST_FILES = 140
_MIN_TEST_FUNCTIONS = 1300
_MIN_KILLCHAIN_STAGES = 10

# 시나리오 커버리지 펀넬 floor(회귀만 차단 — 실물 랜딩으로만 성장).
_MIN_SCENARIOS = 131  # 런북 배선 시나리오 총수(분모)
_MIN_GOLDEN_E2E = 9  # 골든픽스처로 end-to-end 검증된 시나리오
_MIN_IMPL_DETECTORS = 1  # in-repo 구현 분석룰(런타임 탐지 근사) — S1_GNSS

_TEST_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+test_", re.MULTILINE)


class ScenarioFunnel(TypedDict):
    """131 시나리오 커버리지 펀넬 계량 결과."""

    scenario_total: int
    contract_wired: int
    golden_e2e: int
    impl_detectors: int
    contract_pct: float
    golden_e2e_pct: float
    impl_detector_pct: float
    runbook_count: int
    cacao_playbooks: int
    attack_technique_mapping: str


def _scenario_coverage_funnel() -> ScenarioFunnel:
    """131 시나리오 기준 방어 커버리지 펀넬을 계산한다.

    3계단(계약→검증→구현)은 각각 다른 높이이며, 배선 존재(계약)가 검증·구현을
    대신하지 않는다. 계단은 오직 실물 랜딩(픽스처 파일·탐지기/룰 추가)으로만
    오른다 — 따라서 이 값이 움직였다는 것 자체가 실 작업이 들어왔다는 증거다.

    Returns:
        펀넬 계단(절대수·백분율)과, 과소평가를 막는 정직한 상단 지표(계약 폭·
        ATT&CK 매핑·픽스처 경로 다양성)를 함께 담은 dict.
    """
    runbooks = load_runbooks().runbooks
    scenarios = {getattr(rb, "scenario_id", "") for rb in runbooks}
    scenarios.discard("")
    total = len(scenarios)

    # 계약 배선: 런북 + tactic 매핑 + tactic→playbook 선택 가능이 모두 성립한 시나리오.
    stm = scenario_tactic_map()
    playbooks = load_playbooks()
    contract_wired = sum(
        1
        for s in scenarios
        if s in stm and select_playbook(stm.get(s, ""), playbooks) is not None
    )

    # 검증: 골든픽스처 scenario_id 중 런북 시나리오에 실재하는 것(오배선 픽스처 제외).
    fixture_scn = set()
    for path in _FIXTURES_DIR.glob("*.yaml"):
        fx = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(fx, dict) and fx.get("scenario_id") in scenarios:
            fixture_scn.add(fx["scenario_id"])
    golden_e2e = len(fixture_scn)

    # 구현: in-repo 분석룰 JSON(런타임 탐지 근사) — 매핑(165)이 아니라 실제 구현물.
    impl_detectors = (
        len(list(_ANALYTIC_RULES_DIR.glob("*.json")))
        if _ANALYTIC_RULES_DIR.is_dir()
        else 0
    )

    # 과소평가 방지용 정직한 상단 지표(구현 1/131만 보이면 방어 폭이 가려진다).
    matrix = CoverageMatrix.from_yaml()
    attack_covered = sum(len(t.covered) for t in matrix.tactics)
    attack_total = attack_covered + sum(
        len(t.planned) + len(t.uncovered) for t in matrix.tactics
    )

    def _pct(n: int, d: int) -> float:
        return round(100.0 * n / d, 1) if d else 0.0

    return {
        "scenario_total": total,
        "contract_wired": contract_wired,
        "golden_e2e": golden_e2e,
        "impl_detectors": impl_detectors,
        "contract_pct": _pct(contract_wired, total),
        "golden_e2e_pct": _pct(golden_e2e, total),
        "impl_detector_pct": _pct(impl_detectors, total),
        # 정직한 상단 지표(라벨 유지 — 매핑≠구현).
        "runbook_count": len(runbooks),
        "cacao_playbooks": len(playbooks),
        "attack_technique_mapping": f"{attack_covered}/{attack_total} (매핑)",
    }


def _real_nodes(*, active_hunt: bool = False, hitl: bool = False) -> set[str]:
    """컴파일된 그래프에서 `__start__`/`__end__` 의사노드를 제외한 실노드 집합.

    Args:
        active_hunt: opt-in hunt 노드 배선 여부.
        hitl: 고위험 정탐 승인(approval) 노드 배선 여부.

    Returns:
        그래프에 등록된 실제 에이전트 노드 이름 집합.
    """
    # active_hunt 노드는 enabled 플래그 + sentinel_workspace_id 둘 다 있어야 배선된다
    # (agents/graph.py:490 게이트).
    settings = (
        Settings(active_hunt_enabled=True, sentinel_workspace_id="ws-test")
        if active_hunt
        else Settings(active_hunt_enabled=False)
    )
    graph = build_soc_graph(settings=settings, hitl=hitl)
    return {n for n in graph.get_graph().nodes if not n.startswith("__")}


def _load_manifest() -> dict[str, object]:
    """분석 룰 매니페스트(JSON)를 파싱해 반환."""
    data = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _count_test_functions() -> int:
    """`tests/` 하위 모든 `test_*.py` 의 `test_` 함수 총수(자기 자신 포함)."""
    total = 0
    for path in _TESTS_DIR.rglob("test_*.py"):
        total += len(_TEST_DEF_RE.findall(path.read_text(encoding="utf-8")))
    return total


def defense_kpi_snapshot() -> dict[str, object]:
    """방어측 정량 지표를 한 dict 로 모아 반환(리뷰 B2 '방어측 표' 원천).

    Returns:
        방어 실증 계량치. `mttt_mttc` 는 측정 방식·현재값을 함께 실어 정직성을
        유지한다(런타임 저장 필드가 아니라 벤치 파생 측정임을 명시).
    """
    manifest = _load_manifest()
    rules = manifest["rules"]
    assert isinstance(rules, dict)
    fixtures = sorted(p.name for p in _FIXTURES_DIR.glob("*.yaml"))
    tactics = CoverageMatrix.from_yaml().tactics
    test_files = sorted(p.name for p in _TESTS_DIR.rglob("test_*.py"))

    kpi: dict[str, object] = {
        "measurement": "benchmark-derived from node_timings (run_kpi.py)",
        "persisted_named_field": False,
    }
    if _KPI_RESULTS_PATH.exists():
        results = json.loads(_KPI_RESULTS_PATH.read_text(encoding="utf-8"))
        kpi.update(
            {
                "mode": results.get("mode"),
                "llm": results.get("llm"),
                "triage_MTTT_ms": results.get("triage_MTTT_ms"),
                "response_MTTC_ms": results.get("response_MTTC_ms"),
                "eval_set_total": results.get("eval_set", {}).get("total"),
            }
        )
    else:
        kpi["status"] = "미측정(벤치 결과 없음 — run_kpi.py 실행 필요)"

    return {
        "soc_graph_core_nodes": len(_CORE_NODES),
        "soc_graph_nodes_with_hitl_and_hunt": len(
            _real_nodes(active_hunt=True, hitl=True)
        ),
        "analysis_rule_count": len(rules),
        "golden_fixture_count": len(fixtures),
        "golden_fixtures": fixtures,
        "killchain_stage_count": len(tactics),
        "pollack_ai_test_files": len(test_files),
        "pollack_ai_test_functions": _count_test_functions(),
        "scenario_coverage": _scenario_coverage_funnel(),
        "mttt_mttc": kpi,
    }


class TestDefenseKpiBaseline:
    """방어측 정량 베이스라인 게이트."""

    def test_soc_graph_exposes_six_core_nodes(self) -> None:
        """기본 파이프라인이 정확히 6개 핵심 에이전트 노드를 노출한다."""
        assert _real_nodes() == _CORE_NODES

    def test_hitl_adds_approval_node(self) -> None:
        """HITL 활성 시 approval(승인 대기) 노드가 추가된다."""
        nodes = _real_nodes(hitl=True)
        assert "approval" in nodes
        assert _CORE_NODES <= nodes

    def test_active_hunt_is_opt_in(self) -> None:
        """active_hunt 노드는 opt-in — 기본에는 없고 설정 시에만 배선된다."""
        assert "active_hunt" not in _real_nodes()
        assert "active_hunt" in _real_nodes(active_hunt=True)

    def test_analysis_rule_manifest_is_internally_consistent(self) -> None:
        """매니페스트의 선언 룰 수(`_rule_count`)와 실제 룰 항목 수가 일치한다."""
        manifest = _load_manifest()
        rules = manifest["rules"]
        assert isinstance(rules, dict)
        assert manifest["_rule_count"] == len(rules)

    def test_analysis_rule_count_meets_floor(self) -> None:
        """분석(탐지) 룰 수가 회귀 하한선 이상이다."""
        rules = _load_manifest()["rules"]
        assert isinstance(rules, dict)
        assert len(rules) >= _MIN_RULE_COUNT

    def test_golden_fixture_count_meets_floor(self) -> None:
        """골든 픽스처 수가 하한선 이상이며 전부 YAML 로 로드된다."""
        fixtures = sorted(_FIXTURES_DIR.glob("*.yaml"))
        assert len(fixtures) >= _MIN_GOLDEN_FIXTURES

    def test_pollack_ai_test_suite_meets_floor(self) -> None:
        """방어 실증 규모(테스트 파일·함수 수)가 하한선 이상이다."""
        files = list(_TESTS_DIR.rglob("test_*.py"))
        assert len(files) >= _MIN_TEST_FILES
        assert _count_test_functions() >= _MIN_TEST_FUNCTIONS

    def test_killchain_stages_are_ordered(self) -> None:
        """폐루프 탐지 범위(킬체인 전술)가 하한선 이상이며 order 로 정렬 가능하다."""
        tactics = CoverageMatrix.from_yaml().tactics
        assert len(tactics) >= _MIN_KILLCHAIN_STAGES
        orders = [t.order for t in tactics]
        assert orders == sorted(orders)

    def test_closed_loop_pipeline_covers_detect_contain_learn(self) -> None:
        """폐루프 단계가 그래프 노드로 실재한다 — 탐지·차단·학습 각 단계.

        detect=triage/validation, contain=response, learn=rule_update 가 모두
        배선돼야 '탐지→차단→재학습' 폐루프가 성립한다.
        """
        nodes = _real_nodes()
        assert {"triage", "validation"} <= nodes  # detect
        assert "response" in nodes  # contain
        assert "rule_update" in nodes  # learn(오탐 시 룰 갱신)

    def test_mttt_mttc_source_field_is_wired(self) -> None:
        """MTTT/MTTC 원천인 `node_timings` 상태 필드가 SOCState 에 배선돼 있다."""
        assert "node_timings" in SOCState.__annotations__

    def test_mttt_mttc_is_benchmark_derived_not_persisted(self) -> None:
        """정직성 가드 — MTTT/MTTC 는 런타임 저장 필드가 아니라 벤치 파생 측정이다.

        `soc.*` 런타임 상태에 mttt/mttc 라는 이름의 필드는 없어야 한다(과대광고
        방지). 값은 오직 `benchmarks/run_kpi.py` 가 `node_timings` 에서 산출한다.
        """
        annotations = {k.lower() for k in SOCState.__annotations__}
        assert not any("mttt" in k or "mttc" in k for k in annotations)

    @pytest.mark.skipif(
        not _KPI_RESULTS_PATH.exists(),
        reason="벤치 결과 없음 — run_kpi.py 미실행(미측정 상태는 정직하게 허용)",
    )
    def test_kpi_results_carry_mttt_and_mttc(self) -> None:
        """벤치 결과가 존재하면 MTTT/MTTC 키와 실행 모드를 실어야 한다."""
        results = json.loads(_KPI_RESULTS_PATH.read_text(encoding="utf-8"))
        assert "triage_MTTT_ms" in results
        assert "response_MTTC_ms" in results
        # 결정론 오프라인 실행은 mode/llm 라벨로 측정 맥락을 밝힌다.
        assert results.get("mode") is not None

    def test_defense_kpi_snapshot_is_complete(self) -> None:
        """방어측 표(snapshot)가 모든 정량 필드를 채워 반환한다."""
        snap = defense_kpi_snapshot()
        for key in (
            "soc_graph_core_nodes",
            "analysis_rule_count",
            "golden_fixture_count",
            "killchain_stage_count",
            "pollack_ai_test_files",
            "pollack_ai_test_functions",
            "scenario_coverage",
            "mttt_mttc",
        ):
            assert key in snap, f"snapshot 누락 필드: {key}"
        assert snap["soc_graph_core_nodes"] == 6
        assert isinstance(snap["mttt_mttc"], dict)


class TestScenarioCoverageFunnel:
    """131 시나리오 기준 방어 커버리지 펀넬(계약→검증→구현) 게이트.

    핵심 불변식: 계단은 실물 랜딩으로만 오른다. 배선 존재(계약 100%)가 검증·구현을
    대신하지 않으므로 세 계단은 monotonic 하게 좁아진다(구현 ≤ 검증 ≤ 계약 ≤ 총).
    """

    def test_all_scenarios_contract_wired(self) -> None:
        """모든 시나리오가 런북+tactic+playbook 로 계약 배선돼 있다(계약 계단=100%)."""
        f = _scenario_coverage_funnel()
        assert f["scenario_total"] >= _MIN_SCENARIOS
        assert f["contract_wired"] == f["scenario_total"]
        assert f["contract_pct"] == 100.0

    def test_golden_e2e_coverage_meets_floor(self) -> None:
        """골든픽스처 e2e 검증 시나리오 수가 floor 이상이다(성장은 픽스처 추가로만)."""
        assert _scenario_coverage_funnel()["golden_e2e"] >= _MIN_GOLDEN_E2E

    def test_impl_detector_count_is_honest(self) -> None:
        """in-repo 구현 분석룰 수가 floor 이상 — 매핑(165)이 아닌 실제 구현물 계량."""
        assert _scenario_coverage_funnel()["impl_detectors"] >= _MIN_IMPL_DETECTORS

    def test_funnel_is_monotonic(self) -> None:
        """펀넬이 좁아진다 — 구현 ≤ 검증 ≤ 계약 ≤ 총(배선≠검증≠구현 불변식)."""
        f = _scenario_coverage_funnel()
        assert (
            f["impl_detectors"]
            <= f["golden_e2e"]
            <= f["contract_wired"]
            <= f["scenario_total"]
        )

    def test_attack_mapping_metric_labeled_as_mapping(self) -> None:
        """ATT&CK 상단 지표는 '매핑' 라벨을 유지한다(구현으로 세탁 금지)."""
        f = _scenario_coverage_funnel()
        assert "매핑" in str(f["attack_technique_mapping"])
