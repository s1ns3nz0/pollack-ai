"""[4b] Response Agent (정탐) — 대응 플레이북 표면 + 등급별 HITL/자동대응.

CACAO 카탈로그(전술 키잉) 주입 시 alert 전술로 플레이북을 선택하고 mission-gate
if-condition 을 MissionRisk 로 결정론 평가해 임무-분기 행동을 **권고전용**으로 표면한다.
미커버 전술/미주입은 기존 `alert.defense_playbook` 경로로 폴백(회귀 안전). 자동대응
가능 여부는 정책 등급 메타(auto_response/hitl) + approval 게이트를 그대로 따른다 —
CACAO 분기는 라벨/표면일 뿐 actuator 실행 없음.
"""

from __future__ import annotations

from agents.base import BaseSOCAgent
from core.actors import ActorReadGate
from core.cacao import CacaoPlaybook, resolve_playbook, select_playbook
from core.coerce import opt_str, str_list
from core.degradation import DegradationAssessor
from core.exceptions import PlaybookError
from core.models import (
    ActorProfile,
    Alert,
    MissionContinuity,
    MissionRisk,
    ResponseMissionContext,
    ResponseResult,
    SOCState,
)
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
        actor_read: ActorReadGate | None = None,
        degradation: DegradationAssessor | None = None,
    ) -> None:
        super().__init__(settings)
        self._engine = engine
        self._playbooks = playbooks
        self._scenario_tactic = scenario_tactic or {}
        self._actor_read = actor_read
        self._degradation = degradation

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
        mission_continuity = self._assess_mission_continuity(state)
        resilience_note = self._resilience_note(mission_continuity)
        if resilience_note is not None:
            mr_note = f"{mr_note} | {resilience_note}" if mr_note else resilience_note
        mr_note = await self._append_pb_effect_note(alert.actor_id, cacao_id, mr_note)
        mission_context = self._build_mission_context(
            alert=alert,
            mission_risk=mission_risk,
            mission_continuity=mission_continuity,
            mission_branch=mission_branch,
        )

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
                mission_continuity=mission_continuity,
                resilience_note=resilience_note,
                mission_context=mission_context,
                cacao_playbook_id=cacao_id,
                cacao_steps=cacao_steps,
                mission_branch=mission_branch,
            ),
            "trace": ["response"],
        }

    def _build_mission_context(
        self,
        *,
        alert: Alert,
        mission_risk: MissionRisk | None,
        mission_continuity: MissionContinuity | None,
        mission_branch: str | None,
    ) -> ResponseMissionContext | None:
        """임무위험과 지속성 판정을 response 용 구조화 카드로 합성한다."""
        if mission_risk is None and mission_continuity is None:
            return None

        asset_id = self._context_asset_id(alert, mission_risk, mission_continuity)
        mission_phase = mission_risk.mission_phase if mission_risk is not None else ""
        posture = self._operator_posture(
            mission_risk=mission_risk,
            mission_continuity=mission_continuity,
            mission_branch=mission_branch,
        )
        fallback = mission_continuity.fallback if mission_continuity is not None else ""
        continuity_level = (
            mission_continuity.level if mission_continuity is not None else ""
        )
        summary = self._mission_context_summary(
            asset_id=asset_id,
            mission_phase=mission_phase,
            posture=posture,
            mission_risk=mission_risk,
            continuity_level=continuity_level,
            fallback=fallback,
        )

        return ResponseMissionContext(
            asset_id=asset_id,
            mission_phase=mission_phase,
            risk_score=mission_risk.score if mission_risk is not None else None,
            risk_factors=dict(mission_risk.factors) if mission_risk is not None else {},
            is_key_terrain=(
                mission_risk.is_key_terrain if mission_risk is not None else False
            ),
            dependents=(
                list(mission_risk.dependents) if mission_risk is not None else []
            ),
            rationale=list(mission_risk.rationale) if mission_risk is not None else [],
            continuity_level=continuity_level,
            fallback=fallback,
            operator_posture=posture,
            summary=summary,
        )

    @staticmethod
    def _context_asset_id(
        alert: Alert,
        mission_risk: MissionRisk | None,
        mission_continuity: MissionContinuity | None,
    ) -> str:
        """가장 신뢰도 높은 순서로 response 맥락 자산 id 를 선택한다."""
        if mission_risk is not None and mission_risk.asset_id:
            return mission_risk.asset_id
        if mission_continuity is not None and mission_continuity.asset_id:
            return mission_continuity.asset_id
        return alert.asset_id

    def _operator_posture(
        self,
        *,
        mission_risk: MissionRisk | None,
        mission_continuity: MissionContinuity | None,
        mission_branch: str | None,
    ) -> str:
        """임무 맥락을 운용자가 바로 쓸 수 있는 posture 라벨로 변환한다."""
        if mission_continuity is not None and mission_continuity.level == "ABORT":
            return "ABORT_SAFE_LAND"
        if mission_risk is not None:
            if mission_risk.score >= self._engine.mett_tc.hitl_force_threshold:
                return "HITL_REQUIRED"
        if mission_branch == "conservative":
            return "HITL_REQUIRED"
        if mission_continuity is not None and mission_continuity.level in {
            "MINIMAL",
            "SUSTAINED",
        }:
            return "CONTINUE_DEGRADED"
        return "MONITOR_CONTINUE"

    @staticmethod
    def _mission_context_summary(
        *,
        asset_id: str,
        mission_phase: str,
        posture: str,
        mission_risk: MissionRisk | None,
        continuity_level: str,
        fallback: str,
    ) -> str:
        """ResponseMissionContext 의 한 줄 운용 요약을 만든다."""
        parts = [
            f"asset={asset_id or '미상'}",
            f"phase={mission_phase or '미상'}",
            f"posture={posture}",
        ]
        if mission_risk is not None:
            parts.append(f"risk={mission_risk.score}")
            if mission_risk.is_key_terrain:
                parts.append("key_terrain")
            if mission_risk.dependents:
                parts.append(f"dependents={','.join(mission_risk.dependents)}")
        if continuity_level:
            parts.append(f"continuity={continuity_level}")
        if fallback:
            parts.append(f"fallback={fallback}")
        return " | ".join(parts)

    def _assess_mission_continuity(self, state: SOCState) -> MissionContinuity | None:
        """손상 자산의 mission assurance 판정을 response 에 즉시 부착한다."""
        if self._degradation is None:
            return None
        return self._degradation.assess(state["alert"], state["verdict"])

    @staticmethod
    def _resilience_note(mc: MissionContinuity | None) -> str | None:
        """MissionContinuity 를 response 표면용 한 줄 resilience note 로 변환한다."""
        if mc is None:
            return None
        return (
            f"Resilience {mc.level}: 손실={mc.capability_lost}; " f"대체={mc.fallback}"
        )

    async def _append_pb_effect_note(
        self, actor_id: str | None, playbook_id: str | None, note: str | None
    ) -> str | None:
        """선택된 CACAO PB 의 actor별 과거 효과 점수를 임무 노트에 부착한다."""
        if self._actor_read is None or not actor_id or not playbook_id:
            return note
        normalized_actor_id = actor_id.strip()
        if not normalized_actor_id:
            return note
        profile: ActorProfile | None = await self._actor_read.recall(
            normalized_actor_id
        )
        if profile is None:
            return note
        score = profile.pb_scores.get(playbook_id)
        if score is None:
            return note
        effect_note = (
            f"PB 효과 {score.playbook_id}={score.avg_effect:.2f}({score.count})"
        )
        return f"{note} | {effect_note}" if note else effect_note
