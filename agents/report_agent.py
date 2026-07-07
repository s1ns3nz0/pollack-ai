"""[5] Report Agent — 최종 리포트 조립 + OSCAL 증거(등급별 차등).

spec C1: investigation.predictions 가 있으면 `hunt_candidates` 에 노출.
spec A1: CausalReasoner 주입 시 `causal_summary` + OSCAL `causal_chain` 임베드.
spec B-1: actor_read 주입 시 actor.pb_scores top-3 을 guardrail_flags 에 노출.
예측 폐루프: stager 주입 시 예측 TTP 선제 스테이징 판정을 `staged_defenses` 노출.
"""

from __future__ import annotations

from agents.base import BaseSOCAgent
from app.metrics import metrics
from core import oscal
from core.actors import ActorReadGate
from core.causal import CausalReasoner
from core.coa import CoaPlanner
from core.coerce import opt_str
from core.lineage import LineageCollector
from core.models import (
    Alert,
    CoaOption,
    InvestigationResult,
    SOCReport,
    SOCState,
    StagedDefense,
    Verdict,
)
from core.settings import Settings
from core.severity import SeverityEngine
from core.staging import DefenseStager


class ReportAgent(BaseSOCAgent):
    """리포트 + OSCAL 증거 생성 Agent."""

    def __init__(
        self,
        settings: Settings,
        engine: SeverityEngine,
        reasoner: CausalReasoner | None = None,
        actor_read: ActorReadGate | None = None,
        lineage: LineageCollector | None = None,
        stager: DefenseStager | None = None,
        coa_planner: CoaPlanner | None = None,
    ) -> None:
        super().__init__(settings)
        self._engine = engine
        self._coa_planner = coa_planner
        self._reasoner = reasoner
        self._actor_read = actor_read
        self._lineage = lineage
        self._stager = stager

    async def run(self, state: SOCState) -> SOCState:
        """리포트 + OSCAL 증거 구성."""
        alert = state["alert"]
        severity = state["severity"]
        verdict = state["verdict"]
        meta = self._engine.level_meta(severity)
        evidence_level = opt_str(meta.get("oscal_evidence")) or "summary"

        inv = state.get("investigation")
        hunt_candidates: list[str] = []
        staged_defenses: list[StagedDefense] = []
        if inv is not None and inv.predictions:
            hunt_candidates = [p.next_technique for p in inv.predictions]
            if self._stager is not None:
                staged_defenses = self._stager.stage(inv.predictions)

        coa_options = await self._build_coa(alert, inv)

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
            staged_defenses=staged_defenses,
            coa_options=coa_options,
        )
        # kill chain: 후반단계 도달 시 guardrail 노출 + 메트릭 계측.
        if alert.kill_chain_advanced:
            report.guardrail_flags = list(report.guardrail_flags) + [
                "kill chain 후반단계(C2 이후) 도달 — 진행 중 캠페인, 심각도 격상됨"
            ]
            metrics().record_killchain_advanced()

        # spec A1: 인과 체인 매핑
        if self._reasoner is not None:
            chain = await self._reasoner.build_chain(alert, inv)
            if chain.steps:
                report.causal_summary = chain

        # spec B-1: actor.pb_scores top-3 노출
        if self._actor_read is not None and alert.actor_id:
            profile = await self._actor_read.recall(alert.actor_id.strip())
            if profile is not None and profile.pb_scores:
                top = sorted(profile.pb_scores.values(), key=lambda s: -s.avg_effect)[
                    :3
                ]
                top_str = ", ".join(
                    f"{s.playbook_id}={s.avg_effect:.2f}({s.count})" for s in top
                )
                report.guardrail_flags = list(report.guardrail_flags) + [
                    f"actor[{profile.actor_id}] PB 효과 top-3: {top_str}"
                ]

        evidence = oscal.build_evidence(state, evidence_level)
        if report.causal_summary is not None:
            evidence.causal_chain = report.causal_summary
        if self._lineage is not None:
            evidence.lineage = self._lineage.snapshot(state)

        self._logger.info(
            "report: alert=%s severity=%s verdict=%s hunts=%d causal=%s",
            alert.id,
            severity,
            verdict,
            len(hunt_candidates),
            bool(report.causal_summary),
        )
        return {"report": report, "oscal_evidence": evidence, "trace": ["report"]}

    async def _build_coa(
        self, alert: Alert, inv: InvestigationResult | None
    ) -> list[CoaOption]:
        """현재 도달 단계 + 예측 다음 단계의 COA 옵션을 집계한다.

        현재 단계 = alert.mitre tactics + actor 누적 tactic 이력(최고 order).
        예측 다음 = investigation.predictions technique(planner 가 tactic 으로 환산).

        Args:
            alert: 대상 알람(mitre tactics·actor_id 포함).
            inv: Investigation 산출물(predictions).

        Returns:
            CoaOption 목록. planner 미주입 시 빈 리스트.
        """
        if self._coa_planner is None:
            return []
        raw = alert.mitre.get("tactics", [])
        tactics = [str(t) for t in raw] if isinstance(raw, list) else []
        # actor 누적 tactic 이력 합류(진행도 반영).
        if self._actor_read is not None and alert.actor_id:
            profile = await self._actor_read.recall(alert.actor_id.strip())
            if profile is not None:
                tactics.extend(s.tactic for s in profile.ttp_stats)
        predicted = (
            [p.next_technique for p in inv.predictions] if inv is not None else []
        )
        return self._coa_planner.plan(tactics, predicted)
