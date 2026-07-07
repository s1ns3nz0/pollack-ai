"""CoaPlanner 테스트 — 현재 단계 + 예측 다음 단계 COA 집계."""

from core.coa import CoaMatrix, CoaPlanner
from tools.coverage import CoverageMatrix


def _planner() -> CoaPlanner:
    return CoaPlanner(CoverageMatrix.from_yaml(), CoaMatrix.from_yaml())


class TestCoaPlanner:
    """현재 도달 단계(current) + 예측 다음(predicted) COA."""

    def test_current_tactic_options_marked_current(self) -> None:
        """현재 tactic COA 는 stage=current."""
        opts = _planner().plan(
            current_tactics=["CommandAndControl"], predicted_techniques=[]
        )

        assert opts
        assert all(o.stage == "current" for o in opts)
        assert all(o.tactic == "CommandAndControl" for o in opts)

    def test_highest_order_tactic_chosen_for_current(self) -> None:
        """현재 tactic 여럿이면 최고 order(후반) 단계 선택."""
        opts = _planner().plan(
            current_tactics=["InitialAccess", "Impact"], predicted_techniques=[]
        )

        assert opts and all(o.tactic == "Impact" for o in opts)

    def test_predicted_technique_mapped_to_tactic(self) -> None:
        """예측 technique → 소속 tactic COA(stage=predicted)."""
        # T1590 = Reconnaissance (coverage.yaml)
        opts = _planner().plan(
            current_tactics=["Execution"], predicted_techniques=["T1590"]
        )

        pred = [o for o in opts if o.stage == "predicted"]
        assert pred and all(o.tactic == "Reconnaissance" for o in pred)

    def test_duplicate_tactic_not_repeated(self) -> None:
        """현재 tactic 과 예측 tactic 이 같으면 중복 제외."""
        # 현재 Execution, 예측 technique 도 Execution 소속이면 중복 안 함
        cov = CoverageMatrix.from_yaml()
        exec_tech = next(
            t
            for tac in cov.tactics
            if tac.name == "Execution"
            for t in (tac.covered + tac.planned)
        )
        opts = _planner().plan(
            current_tactics=["Execution"], predicted_techniques=[exec_tech]
        )

        assert not any(o.stage == "predicted" for o in opts)

    def test_unmapped_predicted_skipped(self) -> None:
        """매핑 안 되는 예측 technique 은 skip."""
        opts = _planner().plan(
            current_tactics=["Execution"], predicted_techniques=["T9999"]
        )

        assert not any(o.stage == "predicted" for o in opts)

    def test_empty_input_empty_result(self) -> None:
        """입력 없으면 빈 결과."""
        assert _planner().plan(current_tactics=[], predicted_techniques=[]) == []

    def test_gap_and_available_both_present(self) -> None:
        """COA 에 available 과 gap 셀 둘 다 노출(7D 프레임)."""
        opts = _planner().plan(
            current_tactics=["CommandAndControl"], predicted_techniques=[]
        )

        statuses = {o.status for o in opts}
        assert statuses == {"available", "gap"}
