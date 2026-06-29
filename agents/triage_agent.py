"""[1] Triage Agent — 우선순위 분류 + 심각도 산정 + 가드레일.

심각도는 정책 엔진이 정한다. 입력에 실린 제안 등급(`llm_suggested_severity`)이
정책 결과보다 낮으면 무시·기록한다 → S5(RAG 포이즈닝) 방어(PB-AISOC-GUARD-05).

spec #2: explicit actor_id + alert_count≥min_alerts 인 활성 공격자면 priority 를
1단계 강등(최저 1까지). fingerprint actor 는 priority 영향 0.
"""

from __future__ import annotations

from agents.base import BaseSOCAgent
from core.actors import ActorReadGate
from core.models import Severity, SOCState
from core.settings import Settings
from core.severity import SeverityEngine

_PRIORITY = {Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


class TriageAgent(BaseSOCAgent):
    """경보 트리아지 + 심각도 산정 Agent."""

    def __init__(
        self,
        settings: Settings,
        engine: SeverityEngine,
        actor_read: ActorReadGate | None = None,
        min_alerts: int = 2,
    ) -> None:
        super().__init__(settings)
        self._engine = engine
        self._actor_read = actor_read
        self._min_alerts = min_alerts

    async def run(self, state: SOCState) -> SOCState:
        """심각도 산정 + 가드레일 + (선택) 활성 explicit actor priority 강등."""
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
        if flags:
            result["guardrail_flags"] = flags
        return result
