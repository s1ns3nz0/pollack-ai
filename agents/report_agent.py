"""[5] Report Agent — 최종 리포트 조립 + OSCAL 증거(등급별 차등).

spec C1: investigation.predictions 가 있으면 `hunt_candidates` 에 노출.
spec A1: CausalReasoner 주입 시 `causal_summary` + OSCAL `causal_chain` 임베드.
"""

from __future__ import annotations

from agents.base import BaseSOCAgent
from core import oscal
from core.causal import CausalReasoner
from core.coerce import opt_str
from core.models import SOCReport, SOCState, Verdict
from core.settings import Settings
from core.severity import SeverityEngine


class ReportAgent(BaseSOCAgent):
    """리포트 + OSCAL 증거 생성 Agent."""

    def __init__(
        self,
        settings: Settings,
        engine: SeverityEngine,
        reasoner: CausalReasoner | None = None,
    ) -> None:
        super().__init__(settings)
        self._engine = engine
        self._reasoner = reasoner

    async def run(self, state: SOCState) -> SOCState:
        """리포트 + OSCAL 증거 구성."""
        alert = state["alert"]
        severity = state["severity"]
        verdict = state["verdict"]
        meta = self._engine.level_meta(severity)
        evidence_level = opt_str(meta.get("oscal_evidence")) or "summary"

        inv = state.get("investigation")
        hunt_candidates: list[str] = []
        if inv is not None and inv.predictions:
            hunt_candidates = [p.next_technique for p in inv.predictions]

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
            hunt_candidates=hunt_candidates,
        )
        # spec A1: 인과 체인 매핑
        if self._reasoner is not None:
            chain = await self._reasoner.build_chain(alert, inv)
            if chain.steps:
                report.causal_summary = chain

        evidence = oscal.build_evidence(state, evidence_level)
        if report.causal_summary is not None:
            evidence.causal_chain = report.causal_summary

        self._logger.info(
            "report: alert=%s severity=%s verdict=%s hunts=%d causal=%s",
            alert.id,
            severity,
            verdict,
            len(hunt_candidates),
            bool(report.causal_summary),
        )
        return {"report": report, "oscal_evidence": evidence, "trace": ["report"]}
