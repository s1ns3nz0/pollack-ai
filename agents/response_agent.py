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
        self._logger.info("response: alert=%s playbook=%s", alert.id, pb.get("id"))
        return {
            "response": ResponseResult(
                playbook_id=opt_str(pb.get("id")),
                actions=str_list(pb.get("actions", [])),
                failover=opt_str(pb.get("failover")),
                auto_response=opt_str(meta.get("auto_response")),
                hitl=opt_str(meta.get("hitl")),
            ),
            "trace": ["response"],
        }
