"""[HITL] Approval Agent — 고위험 자동대응 전 운용자 승인 대기.

방산 운용 특성상 고위험 자동대응은 사람 승인이 필요하다. LangGraph `interrupt`로
파이프라인을 멈추고 운용자 결정을 기다린 뒤 재개한다. 게이트 조건 미해당이면 멈추지
않고 자동 승인한다(불필요한 개입 방지).

게이트 발동 조건(둘 중 하나 — 상향만, 절대 하향 없음):
  (1) severity == h (기존).
  (2) METT-TC 임무위험 score ≥ hitl_force_threshold — severity 가 h 미만이어도
      임무위험 高(핵심지형·의존자산·민간 부수피해·적 진행)면 인간 게이트 강제.
      mission_risk 는 wire 필드 파생이라 위조 시 과-게이트(안전 방향)일 뿐.

이 노드는 `build_soc_graph(hitl=True)`(checkpointer 동반) 에서만 그래프에 삽입된다.
Spec: docs/superpowers/specs/2026-07-09-mett-tc-weighted-triage-design.md
"""

from __future__ import annotations

from langgraph.types import interrupt

from agents.base import BaseSOCAgent
from core.models import ApprovalResult, Severity, SOCState
from core.settings import Settings


def _coerce_approved(raw: object) -> bool:
    """interrupt 재개값(임의 타입)을 승인 bool 로 좁힌다."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, dict):
        return bool(raw.get("approved"))
    return bool(raw)


class ApprovalAgent(BaseSOCAgent):
    """고위험 대응 전 HITL 승인 게이트."""

    def __init__(self, settings: Settings, hitl_force_threshold: int = 6) -> None:
        super().__init__(settings)
        self._hitl_force_threshold = hitl_force_threshold

    async def run(self, state: SOCState) -> SOCState:
        """severity h 또는 임무위험 高면 운용자 승인 대기(interrupt), 그 외 자동 승인.

        Args:
            state: 정탐 판정 + severity(+ mission_risk) 가 정해진 상태.

        Returns:
            approval 결과가 담긴 부분 상태.
        """
        alert = state["alert"]
        severity = state["severity"]
        mission_risk = state.get("mission_risk")
        force_high = severity == Severity.HIGH
        force_mission = (
            mission_risk is not None
            and mission_risk.score >= self._hitl_force_threshold
        )
        if not (force_high or force_mission):
            return {
                "approval": ApprovalResult(
                    required=False,
                    approved=True,
                    note="자동대응(HITL 게이트 미해당)",
                ),
                "trace": ["approval"],
            }

        reason = "고위험(h) 자동대응" if force_high else "임무위험 高"
        mr_score = mission_risk.score if mission_risk is not None else None
        self._logger.info(
            "approval: HITL 승인 대기 alert=%s severity=%s mission_risk=%s(%s)",
            alert.id,
            severity,
            mr_score,
            reason,
        )
        decision = interrupt(
            {
                "action": "approve_auto_response",
                "alert_id": alert.id,
                "severity": str(severity),
                "mission_risk_score": mr_score,
                "playbook": alert.defense_playbook.get("id"),
                "message": f"{reason} 실행 전 운용자 승인이 필요합니다.",
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
