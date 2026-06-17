"""[5] Report Agent — 최종 리포트 조립 + OSCAL 증거(등급별 차등)."""

from __future__ import annotations

from agents.base import BaseSOCAgent
from core import oscal
from core.coerce import opt_str
from core.models import SOCReport, SOCState, Verdict
from core.settings import Settings
from core.severity import SeverityEngine


class ReportAgent(BaseSOCAgent):
    """리포트 + OSCAL 증거 생성 Agent."""

    def __init__(self, settings: Settings, engine: SeverityEngine) -> None:
        super().__init__(settings)
        self._engine = engine

    async def run(self, state: SOCState) -> SOCState:
        """리포트 + OSCAL 증거 구성.

        Args:
            state: response 또는 rule_update 까지 완료된 상태.

        Returns:
            report + oscal_evidence 가 담긴 부분 상태.
        """
        alert = state["alert"]
        severity = state["severity"]
        verdict = state["verdict"]
        meta = self._engine.level_meta(severity)
        evidence_level = opt_str(meta.get("oscal_evidence")) or "summary"

        report = SOCReport(
            alert_id=alert.id,
            scenario_id=alert.scenario_id,
            title=alert.title,
            severity=severity,
            verdict=verdict,
            action_taken=(
                "response" if verdict == Verdict.TRUE_POSITIVE else "rule_update"
            ),
            mitre=alert.mitre,
            guardrail_flags=state.get("guardrail_flags", []),
            hitl=opt_str(meta.get("hitl")),
        )
        evidence = oscal.build_evidence(state, evidence_level)
        self._logger.info(
            "report: alert=%s severity=%s verdict=%s", alert.id, severity, verdict
        )
        return {"report": report, "oscal_evidence": evidence, "trace": ["report"]}
