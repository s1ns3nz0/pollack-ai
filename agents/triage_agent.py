"""[1] Triage Agent — 우선순위 분류 + 심각도 산정 + 가드레일.

심각도는 정책 엔진이 정한다. 입력에 실린 제안 등급(`llm_suggested_severity`)이
정책 결과보다 낮으면 무시·기록한다 → S5(RAG 포이즈닝) 방어(PB-AISOC-GUARD-05).
"""

from __future__ import annotations

from agents.base import BaseSOCAgent
from core.models import Severity, SOCState
from core.settings import Settings
from core.severity import SeverityEngine

_PRIORITY = {Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


class TriageAgent(BaseSOCAgent):
    """경보 트리아지 + 심각도 산정 Agent."""

    def __init__(self, settings: Settings, engine: SeverityEngine) -> None:
        super().__init__(settings)
        self._engine = engine

    async def run(self, state: SOCState) -> SOCState:
        """심각도 산정 + 가드레일 적용.

        Args:
            state: `alert` 를 포함한 현재 상태.

        Returns:
            severity/priority/근거 + 가드레일 플래그가 담긴 부분 상태.
        """
        alert = state["alert"]
        level, rationale = self._engine.compute(alert)
        flags: list[str] = []

        suggested = alert.llm_suggested_severity
        if suggested is not None and _PRIORITY[suggested] > _PRIORITY[level]:
            flags.append(
                f"제안등급({suggested}) < 정책등급({level}) → 무시(정책 하한 유지)"
            )
            self._logger.warning("guardrail: 제안등급 무시 alert=%s", alert.id)

        result: SOCState = {
            "severity": level,
            "severity_rationale": rationale,
            "priority": _PRIORITY[level],
            "trace": ["triage"],
        }
        if flags:
            result["guardrail_flags"] = flags
        return result
