"""[4a] Rule Update Agent (오탐) — 탐지룰 수정 제안(PR stub).

실연동 시 Sigma 룰 diff + GitHub PR 생성. 여기서는 제안 페이로드만 구성한다.
"""

from __future__ import annotations

from agents.base import BaseSOCAgent
from core.coerce import opt_str
from core.models import RuleUpdateResult, SOCState


class RuleUpdateAgent(BaseSOCAgent):
    """오탐 → 탐지룰 수정 제안 Agent."""

    async def run(self, state: SOCState) -> SOCState:
        """탐지룰 수정 제안 구성.

        Args:
            state: verdict=false_positive 인 상태.

        Returns:
            rule_update 제안이 담긴 부분 상태.
        """
        alert = state["alert"]
        rule = opt_str(alert.expected_detection.get("sigma_rule")) or "unknown.yml"
        self._logger.info("rule_update: alert=%s rule=%s", alert.id, rule)
        return {
            "rule_update": RuleUpdateResult(
                target_rule=rule,
                proposal=f"오탐 패턴 반영: '{alert.title}' 신호 임계/예외 조정",
                pr_status="proposed",
                reason=f"verdict=false_positive (alert {alert.id})",
            ),
            "trace": ["rule_update"],
        }
