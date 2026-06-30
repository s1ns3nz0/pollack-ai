"""spec A-1 OutcomeProbe — engine + agent + 3 gate fan-out + learning 통합."""

from __future__ import annotations

import pytest

from agents.outcome_probe_agent import OutcomeProbeAgent
from app.learning import run_cycle
from core.actors import ActorWriteGate, InMemoryActorStore
from core.experience import InMemoryExperienceStore, MemoryWriteGate
from core.models import (
    EnvVerdict,
    JudgeFeatures,
    Severity,
    Verdict,
)
from core.outcome import (
    InMemoryObservationSource,
    Observation,
    ProbeEngine,
)
from core.playbook_outcome import ActorPlaybookOutcomeGate
from core.settings import Settings


def _judge_features() -> JudgeFeatures:
    return JudgeFeatures(
        has_signal=True, has_rule=True, corroborated=True, confidence=0.9
    )


def _obs(**kwargs: object) -> Observation:
    base: dict[str, object] = {
        "alert_id": "a1",
        "scenario_id": "S2",
        "actor_id": "team-red",
        "playbook_id": "pb1",
        "window_min": 10,
        "ts": "2026-06-30T00:00:00Z",
        "alert_signals": ["sig.a"],
        "alert_severity": Severity.MEDIUM,
        "alert_verdict": Verdict.TRUE_POSITIVE,
        "alert_mitre": {"tactics": ["TA0008"], "techniques": ["T1021"]},
        "asset_id": "GCS",
        "judge_features": _judge_features(),
    }
    base.update(kwargs)
    return Observation.model_validate(base)


class TestProbeEngineMatrix:
    def test_mission_reoccur_full_failure(self) -> None:
        eng = ProbeEngine()
        d = eng.decide(_obs(mission_effect_observed=True, reoccurred=True))
        assert d.env_verdict == EnvVerdict.CONFIRMED_TP
        assert d.effect == 0.0

    def test_mission_single_partial(self) -> None:
        eng = ProbeEngine()
        d = eng.decide(_obs(mission_effect_observed=True, reoccurred=False))
        assert d.env_verdict == EnvVerdict.CONFIRMED_TP
        assert d.effect == 0.3

    def test_no_effect_long_window_fp(self) -> None:
        eng = ProbeEngine(min_window_for_fp=5)
        d = eng.decide(_obs(no_effect_sustained=True, window_min=10))
        assert d.env_verdict == EnvVerdict.CONFIRMED_FP
        assert d.effect == 1.0

    def test_no_effect_short_window_inconclusive(self) -> None:
        eng = ProbeEngine(min_window_for_fp=5)
        d = eng.decide(_obs(no_effect_sustained=True, window_min=2))
        assert d.env_verdict == EnvVerdict.INCONCLUSIVE

    def test_unknown_inconclusive(self) -> None:
        eng = ProbeEngine()
        d = eng.decide(_obs())
        assert d.env_verdict == EnvVerdict.INCONCLUSIVE
        assert d.effect == 0.5


class TestAgentFanOut:
    @pytest.mark.asyncio
    async def test_three_gates_called_for_full_obs(self) -> None:
        exp_store = InMemoryExperienceStore()
        actor_store = InMemoryActorStore()
        source = InMemoryObservationSource()
        # mission_effect 단발 TP → 모든 gate 적립
        source.push(_obs(mission_effect_observed=True))
        agent = OutcomeProbeAgent(
            Settings(),
            source,
            ProbeEngine(),
            exp_gate=MemoryWriteGate(exp_store),
            actor_gate=ActorWriteGate(actor_store),
            pb_gate=ActorPlaybookOutcomeGate(actor_store),
        )
        report = await agent.run()
        # exp 1 + actor 1 + pb 1 = 3
        assert report.auto_applied == 3

    @pytest.mark.asyncio
    async def test_no_playbook_skips_pb(self) -> None:
        actor_store = InMemoryActorStore()
        source = InMemoryObservationSource()
        source.push(_obs(mission_effect_observed=True, playbook_id=None))
        agent = OutcomeProbeAgent(
            Settings(),
            source,
            ProbeEngine(),
            actor_gate=ActorWriteGate(actor_store),
            pb_gate=ActorPlaybookOutcomeGate(actor_store),
        )
        report = await agent.run()
        # actor 1, pb 0 (playbook 없음)
        assert report.auto_applied == 1

    @pytest.mark.asyncio
    async def test_no_actor_skips_actor_and_pb(self) -> None:
        exp_store = InMemoryExperienceStore()
        source = InMemoryObservationSource()
        source.push(_obs(mission_effect_observed=True, actor_id=None))
        agent = OutcomeProbeAgent(
            Settings(),
            source,
            ProbeEngine(),
            exp_gate=MemoryWriteGate(exp_store),
            actor_gate=ActorWriteGate(InMemoryActorStore()),
            pb_gate=ActorPlaybookOutcomeGate(InMemoryActorStore()),
        )
        report = await agent.run()
        # exp 1만
        assert report.auto_applied == 1

    @pytest.mark.asyncio
    async def test_metadata_missing_skips_exp(self) -> None:
        actor_store = InMemoryActorStore()
        source = InMemoryObservationSource()
        source.push(_obs(mission_effect_observed=True, judge_features=None))
        agent = OutcomeProbeAgent(
            Settings(),
            source,
            ProbeEngine(),
            exp_gate=MemoryWriteGate(InMemoryExperienceStore()),
            actor_gate=ActorWriteGate(actor_store),
        )
        report = await agent.run()
        # actor 1만 (exp skip — judge_features 없음)
        assert report.auto_applied == 1

    @pytest.mark.asyncio
    async def test_inconclusive_no_exp_no_actor(self) -> None:
        # INCONCLUSIVE → exp gate 거부, actor gate 도 TP 아니라 거부
        exp_store = InMemoryExperienceStore()
        actor_store = InMemoryActorStore()
        source = InMemoryObservationSource()
        source.push(_obs())  # 디폴트 = INCONCLUSIVE
        agent = OutcomeProbeAgent(
            Settings(),
            source,
            ProbeEngine(),
            exp_gate=MemoryWriteGate(exp_store),
            actor_gate=ActorWriteGate(actor_store),
            pb_gate=ActorPlaybookOutcomeGate(actor_store),
        )
        report = await agent.run()
        # exp REJECTED_INCONCLUSIVE, actor REJECTED_NOT_TP, pb REJECTED_NO_ACTOR
        assert report.auto_applied == 0


class _FailingSource:
    async def apoll(self) -> list[Observation]:
        from core.exceptions import SOCPlatformError

        raise SOCPlatformError("source down")


class TestAgentErrorHandling:
    @pytest.mark.asyncio
    async def test_source_failure_records_error(self) -> None:
        agent = OutcomeProbeAgent(Settings(), _FailingSource(), ProbeEngine())
        report = await agent.run()
        assert any("source" in e for e in report.errors)
        assert report.auto_applied == 0


class TestLearningIntegration:
    @pytest.mark.asyncio
    async def test_outcome_probe_invoked(self) -> None:
        actor_store = InMemoryActorStore()
        source = InMemoryObservationSource()
        source.push(_obs(mission_effect_observed=True))
        agent = OutcomeProbeAgent(
            Settings(),
            source,
            ProbeEngine(),
            actor_gate=ActorWriteGate(actor_store),
            pb_gate=ActorPlaybookOutcomeGate(actor_store),
        )
        await run_cycle(outcome_probe=agent)
        prof = await actor_store.aload("team-red")
        assert prof is not None

    @pytest.mark.asyncio
    async def test_no_outcome_probe_preserves_behavior(self) -> None:
        # outcome_probe 미주입 — run_cycle 무사 통과
        await run_cycle()
