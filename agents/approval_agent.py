"""[HITL] Approval Agent — 고위험 자동대응 전 운용자 승인 대기.

방산 운용 특성상 고위험 자동대응은 사람 승인이 필요하다. LangGraph `interrupt`로
파이프라인을 멈추고 운용자 결정을 기다린 뒤 재개한다. 게이트 조건 미해당이면 멈추지
않고 자동 승인한다(불필요한 개입 방지).

게이트 발동 조건(셋 중 하나 — 상향만, 절대 하향 없음):
  (1) severity == h (기존).
  (2) METT-TC 임무위험 score ≥ hitl_force_threshold — severity 가 h 미만이어도
      임무위험 高(핵심지형·의존자산·민간 부수피해·적 진행)면 인간 게이트 강제.
      mission_risk 는 wire 필드 파생이라 위조 시 과-게이트(안전 방향)일 뿐.
  (3) CACAO 플레이북(전술) mission-gate 가 보수분기 요구 — mission_risk None(불명)·
      malformed 플레이북 포함 fail-safe. resolve 를 approval 에서 강제해 ResponseAgent
      뒤가 아닌 실제 interrupt 로 게이트한다(Codex High 후속).

이 노드는 `build_soc_graph(hitl=True)`(checkpointer 동반) 에서만 그래프에 삽입된다.
Spec: docs/superpowers/specs/2026-07-09-cacao-approval-hitl-design.md
"""

from __future__ import annotations

from langgraph.types import interrupt

from agents.base import BaseSOCAgent
from core.cacao import CacaoPlaybook, playbook_requires_hitl, select_playbook
from core.models import ApprovalResult, Severity, SOCState
from core.runbook import RunbookCatalog
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

    def __init__(
        self,
        settings: Settings,
        hitl_force_threshold: int = 6,
        playbooks: list[CacaoPlaybook] | None = None,
        scenario_tactic: dict[str, str] | None = None,
        runbooks: RunbookCatalog | None = None,
    ) -> None:
        super().__init__(settings)
        self._hitl_force_threshold = hitl_force_threshold
        self._playbooks = playbooks
        self._scenario_tactic = scenario_tactic or {}
        self._runbooks = runbooks

    def _cacao_forces_hitl(self, state: SOCState) -> bool:
        """alert 전술의 CACAO 플레이북이 보수(HITL) 분기를 요구하는지."""
        if not self._playbooks:
            return False
        tactic = self._scenario_tactic.get(state["alert"].scenario_id, "")
        pb = select_playbook(tactic, self._playbooks)
        if pb is None:
            return False
        return playbook_requires_hitl(pb, state.get("mission_risk"))

    def _runbook_forces_hitl(self, state: SOCState) -> bool:
        """Runbook approval.required 가 HITL 을 요구하는지."""
        if self._runbooks is None:
            return False
        runbook = self._runbooks.by_scenario(state["alert"].scenario_id)
        return bool(runbook is not None and runbook.approval.required)

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
        force_cacao = self._cacao_forces_hitl(state)
        force_runbook = self._runbook_forces_hitl(state)
        if not (force_high or force_mission or force_cacao or force_runbook):
            return {
                "approval": ApprovalResult(
                    required=False,
                    approved=True,
                    note="자동대응(HITL 게이트 미해당)",
                ),
                "trace": ["approval"],
            }

        if force_high:
            reason = "고위험(h) 자동대응"
        elif force_mission:
            reason = "임무위험 高"
        elif force_runbook:
            reason = "Runbook 승인필수"
        else:
            reason = "CACAO 보수분기(임무게이트)"
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
