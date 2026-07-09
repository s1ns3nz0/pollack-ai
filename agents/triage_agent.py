"""[1] Triage Agent — 우선순위 분류 + 심각도 산정 + 가드레일.

심각도는 정책 엔진이 정한다. 입력에 실린 제안 등급(`llm_suggested_severity`)이
정책 결과보다 낮으면 무시·기록한다 → S5(RAG 포이즈닝) 방어(PB-AISOC-GUARD-05).

spec #2: explicit actor_id + alert_count≥min_alerts 인 활성 공격자면 priority 를
1단계 강등(최저 1까지). fingerprint actor 는 priority 영향 0.

METT-TC: mission_risk assessor 주입 시 임무위험(MissionRisk)을 산출해 (1) priority 를
상승-전용으로 가중(severity 미중복 delta 요소만, +cap 밴드), (2) mission_risk 를
SOCState 로 실어 approval(HITL 게이트)·report 가 소비한다. severity 레벨은 미접촉
(정책 엔진 권한 유지 — h 레벨의 auto_response 오발동 방지).
Spec: docs/superpowers/specs/2026-07-09-mett-tc-weighted-triage-design.md
"""

from __future__ import annotations

from agents.base import BaseSOCAgent
from core.actors import ActorReadGate
from core.models import Severity, SOCState
from core.settings import Settings
from core.severity import SeverityEngine
from core.terrain import MissionRiskAssessor

_PRIORITY = {Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


class TriageAgent(BaseSOCAgent):
    """경보 트리아지 + 심각도 산정 Agent."""

    def __init__(
        self,
        settings: Settings,
        engine: SeverityEngine,
        actor_read: ActorReadGate | None = None,
        min_alerts: int = 2,
        mission_risk: MissionRiskAssessor | None = None,
    ) -> None:
        super().__init__(settings)
        self._engine = engine
        self._actor_read = actor_read
        self._min_alerts = min_alerts
        self._mission_risk = mission_risk

    async def run(self, state: SOCState) -> SOCState:
        """심각도 산정 + 가드레일 + (선택) actor 강등 + METT-TC priority 상승."""
        alert = state["alert"]
        level, rationale = self._engine.compute(alert)
        flags: list[str] = []
        priority = _PRIORITY[level]

        suggested = alert.llm_suggested_severity
        if suggested is not None and _PRIORITY[suggested] > _PRIORITY[level]:
            flags.append(
                f"제안등급({suggested}) < 정책등급({level}) → 무시(정책 하한 유지)"
            )
            self._logger.warning("guardrail: 제안등급 무시 alert=%s", alert.id)

        # spec #2: explicit + count≥min_alerts actor 면 priority 강등.
        if self._actor_read is not None and alert.actor_id:
            profile = await self._actor_read.recall(alert.actor_id.strip())
            if (
                profile is not None
                and profile.is_explicit
                and profile.alert_count >= self._min_alerts
            ):
                priority = max(1, priority - 1)
                rationale.append(
                    f"actor[{profile.actor_id}] 활성 (count={profile.alert_count}) "
                    f"→ priority -1"
                )

        result: SOCState = {
            "severity": level,
            "severity_rationale": rationale,
            "priority": priority,
            "trace": ["triage"],
        }

        # METT-TC: 임무위험 산출 → priority 상승-전용 가중 + 상태 부착.
        if self._mission_risk is not None:
            mr = self._mission_risk.assess(alert)
            cfg = self._engine.mett_tc
            delta = sum(mr.factors.get(f, 0) for f in cfg.priority_delta_factors)
            if delta >= cfg.priority_delta_min:
                new_priority = max(1, priority - cfg.priority_delta_cap)
                if new_priority != priority:
                    rationale.append(
                        f"METT-TC delta={delta}(≥{cfg.priority_delta_min}) "
                        f"→ priority {priority}→{new_priority}(상승, cap "
                        f"{cfg.priority_delta_cap})"
                    )
                    # 과상승 관측(위조 wire 필드로 인한 alert fatigue 감시).
                    self._logger.info(
                        "mett-tc priority escalation alert=%s delta=%d %d->%d",
                        alert.id,
                        delta,
                        priority,
                        new_priority,
                    )
                    priority = new_priority
                    result["priority"] = priority
            result["mission_risk"] = mr

        if flags:
            result["guardrail_flags"] = flags
        return result
