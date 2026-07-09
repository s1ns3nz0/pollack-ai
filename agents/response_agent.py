"""[4b] Response Agent (정탐) — 시나리오 플레이북 실행 + 등급별 HITL/자동대응.

자동대응 가능 여부는 정책의 등급 메타(auto_response/hitl)를 따른다.
"""

from __future__ import annotations

from agents.base import BaseSOCAgent
from core.coerce import opt_str, str_list
from core.models import ResponseResult, SOCState
from core.settings import Settings
from core.severity import SeverityEngine


class ResponseAgent(BaseSOCAgent):
    """정탐 대응(플레이북 실행) Agent."""

    def __init__(self, settings: Settings, engine: SeverityEngine) -> None:
        super().__init__(settings)
        self._engine = engine

    async def run(self, state: SOCState) -> SOCState:
        """플레이북 + 등급별 자동대응/HITL 구성.

        Args:
            state: severity/verdict 가 정해진 상태.

        Returns:
            response 결과가 담긴 부분 상태.
        """
        alert = state["alert"]
        pb = alert.defense_playbook
        meta = self._engine.level_meta(state["severity"])
        # HITL 활성 시 승인 거부면 자동대응 보류
        approval = state.get("approval")
        auto_response = opt_str(meta.get("auto_response"))
        if approval is not None and approval.required and not approval.approved:
            auto_response = "보류(운용자 거부 — 자동대응 미실행)"
        # METT-TC 임무위험 맥락 부착(강제 게이트는 approval 노드가 이미 처리 — 상향만).
        # hitl=False 그래프(approval 부재)에선 표기로 인간검토 권고를 정직 반영.
        mission_risk = state.get("mission_risk")
        mr_score: int | None = None
        mr_note: str | None = None
        if mission_risk is not None:
            mr_score = mission_risk.score
            if mission_risk.score >= self._engine.mett_tc.hitl_force_threshold:
                mr_note = f"임무위험 高(score={mission_risk.score}) — 인간검토 권고" + (
                    "(운용자 게이트 통과)" if approval is not None else ""
                )
        self._logger.info("response: alert=%s playbook=%s", alert.id, pb.get("id"))
        return {
            "response": ResponseResult(
                playbook_id=opt_str(pb.get("id")),
                actions=str_list(pb.get("actions", [])),
                failover=opt_str(pb.get("failover")),
                auto_response=auto_response,
                hitl=opt_str(meta.get("hitl")),
                mission_risk_score=mr_score,
                mission_risk_note=mr_note,
            ),
            "trace": ["response"],
        }
