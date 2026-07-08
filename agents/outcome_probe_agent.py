"""OutcomeProbeAgent — observation 3 gate fan-out(spec A-1).

ObservationSource 에서 관측을 가져와 ProbeEngine 결정 → exp / actors / pb_scores
gate 각각 호출. BaseWorkerAgent 패턴 (alert state 무관, 주기 트리거).

Spec: docs/superpowers/specs/2026-06-30-outcome-probe-design.md
"""

from __future__ import annotations

from datetime import UTC, datetime

from agents.base import BaseWorkerAgent
from app.metrics import metrics
from core.actors import ActorWriteGate
from core.bda import BdaAssessor
from core.exceptions import SOCPlatformError
from core.experience import MemoryWriteGate
from core.incident import CaseManager, incident_store
from core.models import (
    Alert,
    ExperienceRecord,
    Provenance,
    Severity,
    WorkerReport,
)
from core.outcome import Observation, ObservationSource, ProbeEngine
from core.playbook_outcome import (
    ActorPlaybookOutcomeGate,
    PlaybookOutcome,
)
from core.settings import Settings


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _reconstruct_alert(obs: Observation) -> Alert:
    """obs 핵심 필드로 ActorWriteGate 가 받는 최소 Alert 재구성."""
    return Alert(
        id=obs.alert_id,
        scenario_id=obs.scenario_id,
        title=obs.scenario_id,
        asset_id=obs.asset_id,
        asset_tier=obs.asset_tier,
        severity_baseline=obs.alert_severity or Severity.INFO,
        signals=obs.alert_signals,
        iocs=obs.alert_iocs,
        mitre=obs.alert_mitre,
        actor_id=obs.actor_id,
    )


class OutcomeProbeAgent(BaseWorkerAgent):
    """ObservationSource → ProbeEngine → 3 gate fan-out."""

    def __init__(
        self,
        settings: Settings,
        source: ObservationSource,
        engine: ProbeEngine,
        exp_gate: MemoryWriteGate | None = None,
        actor_gate: ActorWriteGate | None = None,
        pb_gate: ActorPlaybookOutcomeGate | None = None,
        bda: BdaAssessor | None = None,
        case_mgr: CaseManager | None = None,
    ) -> None:
        super().__init__(settings)
        self._source = source
        self._engine = engine
        self._exp_gate = exp_gate
        self._actor_gate = actor_gate
        self._pb_gate = pb_gate
        self._bda = bda or BdaAssessor()
        self._case_mgr = case_mgr or CaseManager(incident_store())

    async def run(self) -> WorkerReport:
        try:
            obs_list = await self._source.apoll()
        except SOCPlatformError as exc:
            return WorkerReport(cycle_at=_now_iso(), errors=[f"source: {exc}"])
        exp_n, actor_n, pb_n, restore_n = 0, 0, 0, 0
        errors: list[str] = []
        for obs in obs_list:
            decision = self._engine.decide(obs)
            exp_n += await self._submit_exp(obs, decision, errors)
            actor_n += await self._submit_actor(obs, decision, errors)
            pb_n += await self._submit_pb(obs, decision, errors)
            restore_n += self._assess_bda(obs, decision, errors)
            self._submit_case(obs, decision, errors)
        if restore_n:
            metrics().record_bda_restore(restore_n)
        self._logger.info(
            "outcome_probe: obs=%d exp=%d actor=%d pb=%d restore=%d errors=%d",
            len(obs_list),
            exp_n,
            actor_n,
            pb_n,
            restore_n,
            len(errors),
        )
        return WorkerReport(
            cycle_at=_now_iso(),
            auto_applied=exp_n + actor_n + pb_n,
            errors=errors,
        )

    def _submit_case(
        self, obs: Observation, decision: object, errors: list[str]
    ) -> None:
        """Incident Case 후반 생명주기 전진(신뢰관측). 오류는 사이클 격리(Codex M6)."""
        if self._case_mgr is None or not obs.actor_id:
            return
        try:
            self._case_mgr.observe_outcome(
                _reconstruct_alert(obs),
                decision.env_verdict,  # type: ignore[attr-defined]
                recovery_applied=obs.recovery_applied,
                reoccurred=obs.reoccurred,
                no_effect_sustained=obs.no_effect_sustained,
                sbom_tampered=obs.sbom_tampered,
            )
        except SOCPlatformError as exc:
            errors.append(f"case[{obs.alert_id}]: {exc}")

    def _assess_bda(self, obs: Observation, decision: object, errors: list[str]) -> int:
        """교전피해평가(BDA) 산정 — 유의미 피해/복구권고 시 로깅. 복구권고면 1 반환.

        BDA 오류는 사이클을 깨지 않게 격리한다(Codex: 워커 루프 보호). 다른 gate
        제출과 동일 방침 — 실패는 errors 에 담고 0 반환.

        Args:
            obs: 후속 관측(복구 적용/재발/윈도우).
            decision: ProbeEngine 결정(effect 보유).
            errors: 사이클 오류 누적 목록.

        Returns:
            복구/재교전 권고 시 1, 아니면 0(집계용).
        """
        if self._bda is None:
            return 0
        try:
            effect = getattr(decision, "effect", 1.0)
            report = self._bda.assess(effect, obs)
        except (SOCPlatformError, ValueError, TypeError) as exc:
            errors.append(f"bda[{obs.alert_id}]: {exc}")
            return 0
        if report.damage_level != "none":
            self._logger.info(
                "bda: alert=%s 피해=%s restore=%s conf=%s",
                obs.alert_id,
                report.damage_level,
                report.restore_recommended,
                report.confidence,
            )
        return 1 if report.restore_recommended else 0

    async def _submit_exp(
        self, obs: Observation, decision: object, errors: list[str]
    ) -> int:
        if (
            self._exp_gate is None
            or obs.alert_verdict is None
            or obs.alert_severity is None
            or obs.judge_features is None
        ):
            return 0
        try:
            rec = ExperienceRecord(
                scenario_id=obs.scenario_id,
                signals=obs.alert_signals,
                asset_id=obs.asset_id,
                asset_tier=obs.asset_tier,
                verdict=obs.alert_verdict,
                severity=obs.alert_severity,
                judge_features=obs.judge_features,
                playbook_id=obs.playbook_id,
                env_verdict=decision.env_verdict,  # type: ignore[attr-defined]
                provenance=Provenance.ENV_VERIFIED,
                ts=obs.ts,
            )
            d = await self._exp_gate.submit(rec)
            return 1 if d.written else 0
        except SOCPlatformError as exc:
            errors.append(f"exp[{obs.alert_id}]: {exc}")
            return 0

    async def _submit_actor(
        self, obs: Observation, decision: object, errors: list[str]
    ) -> int:
        if self._actor_gate is None or not obs.actor_id:
            return 0
        fake_alert = _reconstruct_alert(obs)
        try:
            d = await self._actor_gate.submit(
                fake_alert,
                decision.env_verdict,  # type: ignore[attr-defined]
                Provenance.ENV_VERIFIED,
                engagement=decision.engagement,  # type: ignore[attr-defined]
            )
            return 1 if d.written else 0
        except SOCPlatformError as exc:
            errors.append(f"actor[{obs.alert_id}]: {exc}")
            return 0

    async def _submit_pb(
        self, obs: Observation, decision: object, errors: list[str]
    ) -> int:
        if self._pb_gate is None or not obs.actor_id or not obs.playbook_id:
            return 0
        try:
            d = await self._pb_gate.submit(
                PlaybookOutcome(
                    actor_id=obs.actor_id,
                    playbook_id=obs.playbook_id,
                    effect=decision.effect,  # type: ignore[attr-defined]
                    ts=obs.ts,
                    reason=decision.rationale,  # type: ignore[attr-defined]
                )
            )
            return 1 if d.written else 0
        except SOCPlatformError as exc:
            errors.append(f"pb[{obs.alert_id}]: {exc}")
            return 0
