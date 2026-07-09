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
from core.aibom import (
    AibomInventory,
    AIBOMVerifier,
    ApprovedAibom,
    expected_component_types,
    settings_datasets,
)
from core.campaign import CampaignDetector
from core.causal import CausalReasoner
from core.coa import CoaPlanner
from core.coerce import opt_str
from core.commander import IncidentCommander
from core.degradation import DegradationAssessor
from core.diamond import DiamondAnalyzer
from core.exceptions import SOCPlatformError
from core.honeypot import HoneypotPlanner
from core.hunt import HuntPlanner
from core.incident import CaseManager
from core.intent import IntentFilter
from core.killweb import KillWebBuilder
from core.lineage import LineageCollector
from core.models import (
    ActorProfile,
    AibomFinding,
    Alert,
    CampaignMatch,
    CoaOption,
    DecoyPlacement,
    DiamondEvent,
    HuntHypothesis,
    InvestigationResult,
    MissionContinuity,
    RecoveryPlan,
    SbomFinding,
    SOCReport,
    SOCState,
    StagedDefense,
    StrideThreat,
    Verdict,
)
from core.ooda import DecisionAdvantageAssessor, ooda_alignment
from core.recovery import RecoveryPlanner
from core.sbom import SBOMVerifier, VulnLookup
from core.settings import Settings
from core.severity import SeverityEngine
from core.staging import DefenseStager
from core.stride import StrideClassifier
from core.terrain import MissionRiskAssessor
from core.zero_trust import load_zt_mapping
from tools.coverage import GroundSegmentCoverage, GroundSegmentReport
from utils.logging import get_logger


def _load_aibom_findings(settings: Settings) -> list[AibomFinding]:
    """AIBOM 정적 검증 1회 실행 → 위반 findings. 정책 실패 시 빈 목록(graceful).

    위반 수는 metric 으로 1회 계상한다(per-alert 재계상 금지 — 정적 posture).

    Args:
        settings: 플랫폼 설정(기대 컴포넌트 유형 도출용).

    Returns:
        AIBOM 거버넌스 위험 목록(정상/정책실패 시 빈 목록).
    """
    try:
        approved = ApprovedAibom.from_yaml()
        # dataset 은 settings(실행값)가 authoritative 관측 — 매니페스트의 dataset 선언은
        # 제외해 이중소스 중복/모순 봉인(Codex Low). 그 외 유형은 매니페스트 선언.
        manifest = [
            c for c in AibomInventory.from_manifest() if c.component_type != "dataset"
        ]
        components = manifest + settings_datasets(settings)
    except SOCPlatformError as exc:
        # 정책 로드 실패 — "AIBOM 부재"를 "AIBOM 정상"과 구분(관측가능 degraded, Codex).
        get_logger("report").warning("AIBOM 정책 로드 실패, degraded: %s", exc)
        metrics().record_aibom_violation()
        return [
            AibomFinding(
                component="aibom_policy",
                issue="policy_unavailable",
                detail="AIBOM 정책 로드 실패 — 거버넌스 검증 불가(degraded)",
            )
        ]
    findings = AIBOMVerifier(approved).verify(
        components, expected_component_types(settings)
    )
    if findings:
        metrics().record_aibom_violation(len(findings))
    return findings


def _load_ground_segment() -> GroundSegmentReport | None:
    """지상 세그먼트 방어 사각 1회 계량 → SOCReport posture. 정책 실패 시 None.

    KPI 는 여기서 계상하지 않는다 — 정적 posture 라 스크레이프 시점 gauge 로 노출
    (app.metrics._ground_metrics). per-alert 카운터 재계상 방지(Codex High).

    Returns:
        지상 blind KPI·계측 백로그. 정책 로드 실패 시 None(관측: gauge degraded).
    """
    try:
        return GroundSegmentCoverage.from_yaml().ground_report()
    except SOCPlatformError as exc:
        get_logger("report").warning("지상 커버리지 로드 실패, 생략: %s", exc)
        return None


def _scenario_prefix(scenario_id: str) -> str:
    """scenario_id 를 캠페인 시퀀스 접두("S6-GCS-..." → "S6")로 정규화한다."""
    return scenario_id.split("-", 1)[0]


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
        recovery_planner: RecoveryPlanner | None = None,
        degradation: DegradationAssessor | None = None,
        stride: StrideClassifier | None = None,
        sbom: SBOMVerifier | None = None,
        vuln: VulnLookup | None = None,
        campaign_detector: CampaignDetector | None = None,
        mission_risk: MissionRiskAssessor | None = None,
        diamond: DiamondAnalyzer | None = None,
        case_mgr: CaseManager | None = None,
        hunt: HuntPlanner | None = None,
        planner: HoneypotPlanner | None = None,
    ) -> None:
        super().__init__(settings)
        self._engine = engine
        self._mission_risk = mission_risk
        self._diamond = diamond
        self._case_mgr = case_mgr
        self._hunt = hunt
        self._coa_planner = coa_planner
        self._recovery_planner = recovery_planner
        self._degradation = degradation
        self._stride = stride
        self._sbom = sbom
        self._vuln = vuln
        self._campaign_detector = campaign_detector
        self._reasoner = reasoner
        self._actor_read = actor_read
        self._lineage = lineage
        self._stager = stager
        self._planner = planner
        # AIBOM 은 정적 posture — 로드 시 1회 계산·캐시(per-alert 재계산·재계상 금지).
        self._aibom_findings = _load_aibom_findings(settings)
        # ZTMM self-attested 매핑도 정적 — 로드 시 1회 캐시.
        self._zt_mapping = load_zt_mapping()
        _unverified = [f for f in self._zt_mapping.findings if "unverified" in f]
        if _unverified:
            metrics().record_ztmm_unverified(len(_unverified))
        # 지상 세그먼트 사각도 정적 posture — 로드 시 1회 계량·캐시.
        self._ground_segment = _load_ground_segment()
        # 지휘관 의도도 정적 교리 — 로드 시 1회 캐시(fail-safe degrade 내장).
        self._intent_filter = IntentFilter.from_yaml()
        # Kill Web 커버리지 breadth 도 정적 posture — 로드 시 1회 계산·캐시.
        self._kill_web = KillWebBuilder.load().resilience()

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
        decoy_placements: list[DecoyPlacement] = []
        if inv is not None and inv.predictions:
            hunt_candidates = [p.next_technique for p in inv.predictions]
            if self._stager is not None:
                staged_defenses = self._stager.stage(inv.predictions)
            if self._planner is not None:
                decoy_placements = self._planner.plan(
                    inv.predictions, asset_hint=alert.asset_id
                )

        # actor 프로필은 report 소비처(coa·diamond·campaign·recovery·pb_scores)가 공유 —
        # 지연민감 노드라 1회만 회상해 재사용(Codex 중복 recall 반영).
        profile = await self._recall_profile(alert)
        coa_options = await self._build_coa(alert, inv, profile)
        recovery_plan = await self._build_recovery(alert, verdict, profile)
        mission_continuity: MissionContinuity | None = None
        if self._degradation is not None:
            mission_continuity = self._degradation.assess(alert, verdict)
            if mission_continuity is not None and mission_continuity.level == "ABORT":
                metrics().record_mission_abort()
        stride_threats: list[StrideThreat] = []
        if self._stride is not None:
            stride_threats = self._stride.classify(alert)
        sbom_findings: list[SbomFinding] = []
        if (
            self._sbom is not None
            and verdict == Verdict.TRUE_POSITIVE
            and alert.sbom_components
        ):
            sbom_findings = await self._sbom.averify(
                alert.sbom_components, vuln=self._vuln
            )
        campaign_matches = await self._build_campaign(alert, profile)
        mission_risk = (
            self._mission_risk.assess(alert) if self._mission_risk is not None else None
        )
        diamond = self._build_diamond(alert, profile)
        hunt_hypotheses = self._build_hunt(alert, inv, campaign_matches, profile)
        incident_case = (
            self._case_mgr.observe_alert(alert, severity)
            if self._case_mgr is not None
            else None
        )
        # Incident Commander: provisional case 기반 자문 지시(무상태·읽기전용).
        incident_directive = (
            IncidentCommander().direct(incident_case)
            if incident_case is not None
            else None
        )
        # 임무형 지휘: 의도 기반 우선순위·결심필요 판정(자문·표현, 정책 캐시).
        intent_assessment = self._intent_filter.assess(alert, incident_case)
        if intent_assessment.decision_class == "commander_decision":
            metrics().record_commander_decision()

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
            hunt_hypotheses=hunt_hypotheses,
            staged_defenses=staged_defenses,
            decoy_placements=decoy_placements,
            coa_options=coa_options,
            mission_risk=mission_risk,
            diamond=diamond,
            incident_case=incident_case,
            incident_directive=incident_directive,
            aibom_findings=self._aibom_findings,
            zt_mapping=self._zt_mapping,
            ground_segment=self._ground_segment,
            intent_assessment=intent_assessment,
            kill_web_resilience=self._kill_web,
            recovery_plan=recovery_plan,
            mission_continuity=mission_continuity,
            stride_threats=stride_threats,
            sbom_findings=sbom_findings,
            campaign_matches=campaign_matches,
        )
        # kill chain: 후반단계 도달 시 guardrail 노출 + 메트릭 계측.
        if alert.kill_chain_advanced:
            report.guardrail_flags = list(report.guardrail_flags) + [
                "kill chain 후반단계(C2 이후) 도달 — 진행 중 캠페인, 심각도 격상됨"
            ]
            metrics().record_killchain_advanced()
        # deception/MBCRA 격상 신호 계측(killchain 과 동형 관측성).
        if alert.decoy_hit:
            metrics().record_decoy_hit()
        if alert.key_terrain:
            metrics().record_key_terrain()
        # AIBOM 정적 posture — 위반 시 report 당 1개 guardrail(캐시 참조, 재계상 없음).
        if self._aibom_findings:
            report.guardrail_flags = list(report.guardrail_flags) + [
                f"AIBOM 거버넌스 위반 {len(self._aibom_findings)}건(AI 공급망·출처)"
            ]
        # 지상 세그먼트 사각 posture — blind 존재 시 report 당 1개 guardrail(캐시 참조).
        if self._ground_segment is not None and self._ground_segment.blind:
            gs = self._ground_segment
            report.guardrail_flags = list(report.guardrail_flags) + [
                f"지상 세그먼트 방어 사각 {gs.blind}면(UAV*_CL 밖) — "
                f"계측 백로그 {len(gs.backlog)}건"
            ]

        # spec A1: 인과 체인 매핑
        if self._reasoner is not None:
            chain = await self._reasoner.build_chain(alert, inv)
            if chain.steps:
                report.causal_summary = chain

        # spec B-1: actor.pb_scores top-3 노출(위에서 회상한 profile 재사용)
        if profile is not None and profile.pb_scores:
            top = sorted(profile.pb_scores.values(), key=lambda s: -s.avg_effect)[:3]
            top_str = ", ".join(
                f"{s.playbook_id}={s.avg_effect:.2f}({s.count})" for s in top
            )
            report.guardrail_flags = list(report.guardrail_flags) + [
                f"actor[{profile.actor_id}] PB 효과 top-3: {top_str}"
            ]

        # OODA 결심 여유: 브리핑 지연 vs 관측 적 진행 cadence(자문·정직 프록시).
        # profile 은 ActorReadGate 검증본 — cadence 는 신뢰 kill_chain 에서만(Codex).
        soc_latency_ms = 0.0
        for _t in state.get("node_timings", []):
            _e = _t.get("elapsed_ms")
            if isinstance(_e, (int, float)):
                soc_latency_ms += float(_e)
        present = {
            "signals": bool(alert.signals),
            "telemetry": True,
            "mitre": bool(alert.mitre),
            "diamond": report.diamond is not None,
            "actor_profile": profile is not None,
            "campaign_matches": bool(report.campaign_matches),
            "causal_summary": report.causal_summary is not None,
            "coa_options": bool(report.coa_options),
            "intent_assessment": report.intent_assessment is not None,
            "incident_directive": report.incident_directive is not None,
            "recovery_plan": report.recovery_plan is not None,
            "recommended_action": bool(report.action_taken),
        }
        report.decision_advantage = DecisionAdvantageAssessor().assess(
            soc_latency_ms,
            profile.kill_chain if profile is not None else [],
            ooda=ooda_alignment(present),
        )
        metrics().record_decision_margin(report.decision_advantage.verdict)

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

    async def _recall_profile(self, alert: Alert) -> ActorProfile | None:
        """report 노드 소비처 공용 — actor 프로필을 한 번만 회상한다."""
        if self._actor_read is None or not alert.actor_id:
            return None
        return await self._actor_read.recall(alert.actor_id.strip())

    async def _build_coa(
        self,
        alert: Alert,
        inv: InvestigationResult | None,
        profile: ActorProfile | None,
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
        # actor 누적 tactic 이력 합류(진행도 반영) + Engage 교전 상태(Deceive enrich).
        engagement = None
        if profile is not None:
            tactics.extend(s.tactic for s in profile.ttp_stats)
            engagement = profile.engagement
        predicted = (
            [p.next_technique for p in inv.predictions] if inv is not None else []
        )
        return self._coa_planner.plan(tactics, predicted, engagement)

    def _build_diamond(
        self, alert: Alert, profile: ActorProfile | None
    ) -> DiamondEvent | None:
        """현 alert(+신뢰 actor 프로필)을 침입분석 다이아몬드 4정점으로 사상한다.

        Args:
            alert: 대상 알람.
            profile: 재사용 actor 프로필(run 에서 1회 회상).

        Returns:
            DiamondEvent(analyzer 미주입 시 None). 프로필 있으면 정점 보강.
        """
        if self._diamond is None:
            return None
        return self._diamond.build(alert, profile)

    def _build_hunt(
        self,
        alert: Alert,
        inv: InvestigationResult | None,
        campaign_matches: list[CampaignMatch],
        profile: ActorProfile | None,
    ) -> list[HuntHypothesis]:
        """예측/campaign/coverage-gap 융합 Tier3 hunt 가설(planner 미주입 시 빈).

        현 tactic 은 profile 누적 우선(신뢰), 없으면 alert.mitre tactics(자문 스코프).
        """
        if self._hunt is None:
            return []
        preds = inv.predictions if inv is not None else []
        camp = [
            (m.next_expected, m.matched) for m in campaign_matches if m.next_expected
        ]
        if profile is not None and profile.ttp_stats:
            tactics: list[str] = [s.tactic for s in profile.ttp_stats]
        else:
            raw = alert.mitre.get("tactics", [])
            tactics = [str(t) for t in raw] if isinstance(raw, list) else []
        return self._hunt.plan(preds, camp, tactics)

    async def _build_campaign(
        self, alert: Alert, profile: ActorProfile | None
    ) -> list[CampaignMatch]:
        """actor 시나리오 이력 + 현 alert → 진행 중 캠페인 체인을 식별한다.

        actor kill_chain 의 scenario_id 시퀀스에 현 alert scenario_id 를 이어
        캠페인 시퀀스(S{n} 접두)와 대조한다. scenario_id 는 "S6-GCS-..." 형식이라
        캠페인 시퀀스의 "S6" 접두로 정규화한다.

        Args:
            alert: 대상 알람(actor_id·scenario_id 포함).

        Returns:
            CampaignMatch 목록. detector/actor 미주입·미매칭 시 빈 리스트.
        """
        if self._campaign_detector is None:
            return []
        history: list[str] = []
        if profile is not None:
            history = [_scenario_prefix(s.scenario_id) for s in profile.kill_chain]
        history.append(_scenario_prefix(alert.scenario_id))
        return self._campaign_detector.detect(history)

    async def _build_recovery(
        self, alert: Alert, verdict: Verdict, profile: ActorProfile | None
    ) -> RecoveryPlan | None:
        """정탐 확정 시 도달 tactic 의 축출/복구/검증 플랜을 조립한다.

        오탐은 recovery 불필요(None). 현재 tactic = alert.mitre tactics +
        actor 누적 이력(진행도 반영, planner 가 최고 order 채택).

        Args:
            alert: 대상 알람.
            verdict: 최종 판정(정탐일 때만 플랜 생성).

        Returns:
            RecoveryPlan, 정탐 아님/미주입/미매핑 시 None.
        """
        if self._recovery_planner is None or verdict != Verdict.TRUE_POSITIVE:
            return None
        raw = alert.mitre.get("tactics", [])
        tactics = [str(t) for t in raw] if isinstance(raw, list) else []
        if profile is not None:
            tactics.extend(s.tactic for s in profile.ttp_stats)
        return self._recovery_planner.plan(tactics)
