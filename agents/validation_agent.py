"""[3] Validation Agent — 오탐/정탐 판단 + 라우팅.

판정기(Judge)는 주입 가능. 기본 Judge 는 신호-탐지로직 정합성 + ground_truth 로
결정론적으로 동작(MVP). 실연동 시 LLM-as-Judge 루브릭으로 교체.
"""

from __future__ import annotations

from collections.abc import Callable

from agents.base import BaseSOCAgent
from core.models import SOCState, Verdict
from core.settings import Settings

Judge = Callable[[SOCState], Verdict]


def default_judge(state: SOCState) -> Verdict:
    """신호+룰 매핑 시 정탐 후보, 최종은 ground_truth 로 확정(MVP)."""
    alert = state["alert"]
    has_signal = bool(alert.signals)
    has_rule = bool(alert.expected_detection.get("sigma_rule"))
    candidate = (
        Verdict.TRUE_POSITIVE if (has_signal and has_rule) else Verdict.FALSE_POSITIVE
    )
    return alert.ground_truth or candidate


def route_after_validation(state: SOCState) -> str:
    """Validation 이후 분기 키를 반환한다(정탐→response, 오탐→rule_update)."""
    return (
        "false_positive"
        if state["verdict"] == Verdict.FALSE_POSITIVE
        else "true_positive"
    )


class ValidationAgent(BaseSOCAgent):
    """오탐/정탐 판정 Agent."""

    def __init__(self, settings: Settings, judge: Judge = default_judge) -> None:
        super().__init__(settings)
        self._judge = judge

    async def run(self, state: SOCState) -> SOCState:
        """판정 실행.

        Args:
            state: investigation 까지 완료된 상태.

        Returns:
            verdict 가 담긴 부분 상태.
        """
        verdict = self._judge(state)
        self._logger.info("validation: alert=%s verdict=%s", state["alert"].id, verdict)
        return {"verdict": verdict, "trace": ["validation"]}
