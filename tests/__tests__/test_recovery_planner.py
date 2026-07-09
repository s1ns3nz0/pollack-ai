"""RecoveryPlanner 테스트 — 정탐 tactic → 축출/복구/검증 절차 조립."""

from core.models import RecoveryStep
from core.recovery import RecoveryMatrix, RecoveryPlanner
from tools.coverage import CoverageMatrix


class TestRecoveryMatrix:
    """recovery-matrix.yaml 로더."""

    def test_loads_from_yaml(self) -> None:
        rm = RecoveryMatrix.from_yaml()
        assert rm.plan_for("CommandAndControl") is not None

    def test_evict_restore_verify_present(self) -> None:
        """C2 plan — 축출/복구 단계 + 검증 문구."""
        rm = RecoveryMatrix.from_yaml()

        plan = rm.plan_for("CommandAndControl")

        assert plan is not None
        assert plan.evict_steps and isinstance(plan.evict_steps[0], RecoveryStep)
        assert plan.restore_steps
        assert "reoccurred" in plan.verify or "축출 실패" in plan.verify
        assert plan.evict_steps[0].d3fend_id

    def test_unknown_tactic_none(self) -> None:
        rm = RecoveryMatrix.from_yaml()
        assert rm.plan_for("UnknownTactic") is None


class TestRecoveryPlanner:
    """정탐 alert tactic → RecoveryPlan(최고 order 단계 기준)."""

    def _planner(self) -> RecoveryPlanner:
        return RecoveryPlanner(CoverageMatrix.from_yaml(), RecoveryMatrix.from_yaml())

    def test_highest_order_tactic_plan(self) -> None:
        """여러 tactic 중 최고 order(후반) 단계의 recovery plan."""
        plan = self._planner().plan(["InitialAccess", "Impact"])

        assert plan is not None
        assert plan.tactic == "Impact"

    def test_unknown_tactic_without_recovery_none(self) -> None:
        """recovery 정의 없는 tactic 만 있으면 None."""
        plan = self._planner().plan(["UnknownTactic"])

        assert plan is None

    def test_empty_none(self) -> None:
        assert self._planner().plan([]) is None
