"""[HITL] Approval Agent — 고위험 자동대응 전 운용자 승인 대기.

방산 운용 특성상 고위험(h) 자동대응은 사람 승인이 필요하다. LangGraph `interrupt`로
파이프라인을 멈추고 운용자 결정을 기다린 뒤 재개한다. 등급이 h 미만이면 멈추지 않고
자동 승인한다(불필요한 개입 방지).

이 노드는 `build_soc_graph(hitl=True)`(checkpointer 동반) 에서만 그래프에 삽입된다.
"""

from __future__ import annotations

from langgraph.types import interrupt

from agents.base import BaseSOCAgent
from core.models import ApprovalResult, Severity, SOCState


def _coerce_approved(raw: object) -> bool:
    """interrupt 재개값(임의 타입)을 승인 bool 로 좁힌다."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, dict):
        return bool(raw.get("approved"))
    return bool(raw)


class ApprovalAgent(BaseSOCAgent):
    """고위험 대응 전 HITL 승인 게이트."""

    async def run(self, state: SOCState) -> SOCState:
        """등급 h 면 운용자 승인 대기(interrupt), 그 외 자동 승인.

        Args:
            state: 정탐 판정 + severity 가 정해진 상태.

        Returns:
            approval 결과가 담긴 부분 상태.
        """
        alert = state["alert"]
        severity = state["severity"]
        if severity != Severity.HIGH:
            return {
                "approval": ApprovalResult(
                    required=False, approved=True, note="자동대응(등급 h 미해당)"
                ),
                "trace": ["approval"],
            }

        self._logger.info(
            "approval: HITL 승인 대기 alert=%s severity=%s", alert.id, severity
        )
        decision = interrupt(
            {
                "action": "approve_auto_response",
                "alert_id": alert.id,
                "severity": str(severity),
                "playbook": alert.defense_playbook.get("id"),
                "message": "고위험(h) 자동대응 실행 전 운용자 승인이 필요합니다.",
            }
        )
        approved = _coerce_approved(decision)
        return {
            "approval": ApprovalResult(
                required=True,
                approved=approved,
                note="운용자 승인" if approved else "운용자 거부 — 자동대응 보류",
            ),
            "trace": ["approval"],
        }
