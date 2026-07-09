"""[4b] Response Agent (정탐) — 대응 플레이북 표면 + 등급별 HITL/자동대응.

CACAO 카탈로그(전술 키잉) 주입 시 alert 전술로 플레이북을 선택하고 mission-gate
if-condition 을 MissionRisk 로 결정론 평가해 임무-분기 행동을 **권고전용**으로 표면한다.
미커버 전술/미주입은 기존 `alert.defense_playbook` 경로로 폴백(회귀 안전). 자동대응
가능 여부는 정책 등급 메타(auto_response/hitl) + approval 게이트를 그대로 따른다 —
CACAO 분기는 라벨/표면일 뿐 actuator 실행 없음.
"""

from __future__ import annotations

from agents.base import BaseSOCAgent
from core.cacao import CacaoPlaybook, resolve_playbook, select_playbook
from core.coerce import opt_str, str_list
from core.exceptions import PlaybookError
from core.models import ResponseResult, SOCState
from core.settings import Settings
from core.severity import SeverityEngine


class ResponseAgent(BaseSOCAgent):
    """정탐 대응(플레이북 표면) Agent."""

    def __init__(
        self,
        settings: Settings,
        engine: SeverityEngine,
        playbooks: list[CacaoPlaybook] | None = None,
        scenario_tactic: dict[str, str] | None = None,
    ) -> None:
        super().__init__(settings)
        self._engine = engine
        self._playbooks = playbooks
        self._scenario_tactic = scenario_tactic or {}

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
        # CACAO 카탈로그 배선: 전술로 플레이북 선택 + mission-gate 결정론 평가 →
        # 임무-분기 행동 표면(권고전용). 미커버/미주입 → defense_playbook 폴백.
        cacao_id: str | None = None
        cacao_steps: list[dict[str, object]] | None = None
        mission_branch: str | None = None
        if self._playbooks:
            tactic = self._scenario_tactic.get(alert.scenario_id, "")
            cpb = select_playbook(tactic, self._playbooks)
            if cpb is not None:
                try:
                    # mission_risk None → resolve 가 보수(HITL) 분기 fail-safe.
                    plan = resolve_playbook(cpb, mission_risk)
                except PlaybookError as exc:  # malformed 워크 → defense_playbook 폴백
                    self._logger.warning("CACAO resolve 실패, 폴백: %s", exc)
                else:
                    cacao_id = plan.playbook_id
                    cacao_steps = plan.steps
                    mission_branch = plan.mission_branch
                    # 보수분기(임무게이트)는 **권고 표면** — 실제 HITL 강제는 approval
                    # 노드(severity==h OR mission_risk.score≥임계, #66)가 이미 처리하며
                    # conservative 조건(score≥임계)과 정렬. mission_risk None 케이스의
                    # approval 강제는 후속(그래프 라우팅). 여기선 인간검토 권고 표기.
                    if plan.hitl_required and mr_note is None:
                        mr_note = "CACAO 보수분기(임무게이트 高) — 인간검토 권고"

        self._logger.info(
            "response: alert=%s playbook=%s cacao=%s branch=%s",
            alert.id,
            pb.get("id"),
            cacao_id,
            mission_branch,
        )
        return {
            "response": ResponseResult(
                playbook_id=opt_str(pb.get("id")),
                actions=str_list(pb.get("actions", [])),
                failover=opt_str(pb.get("failover")),
                auto_response=auto_response,
                hitl=opt_str(meta.get("hitl")),
                mission_risk_score=mr_score,
                mission_risk_note=mr_note,
                cacao_playbook_id=cacao_id,
                cacao_steps=cacao_steps,
                mission_branch=mission_branch,
            ),
            "trace": ["response"],
        }
