"""SimBridgeObservationSource — 매핑 + 큐 + reoccurrence 추적."""

from __future__ import annotations

import pytest

from agents.outcome_probe_agent import OutcomeProbeAgent
from core.actors import ActorWriteGate, InMemoryActorStore
from core.models import (
    Alert,
    EnvVerdict,
    JudgeFeatures,
    Severity,
    Verdict,
)
from core.outcome import ProbeEngine
from core.playbook_outcome import ActorPlaybookOutcomeGate
from core.settings import Settings
from sim_bridge.observation_source import SimBridgeObservationSource
from sim_bridge.outcome import OutcomeAssessment


def _alert(**kwargs: object) -> Alert:
    base: dict[str, object] = {
        "id": "a1",
        "scenario_id": "S1",
        "title": "X",
        "severity_baseline": Severity.MEDIUM,
        "signals": ["sig.a"],
        "iocs": ["1.2.3.4"],
        "actor_id": "team-red",
        "asset_id": "GNSS",
    }
    base.update(kwargs)
    return Alert.model_validate(base)


def _assessment(env: EnvVerdict, observations: int = 60) -> OutcomeAssessment:
    return OutcomeAssessment(
        env_verdict=env,
        sustained_effect_records=5,
        observations=observations,
        rationale=["stub"],
    )


class TestMapping:
    @pytest.mark.asyncio
    async def test_tp_mission_effect(self) -> None:
        src = SimBridgeObservationSource(records_per_minute=600)
        src.enqueue(
            _alert(),
            _assessment(EnvVerdict.CONFIRMED_TP),
            playbook_id="pb1",
            ts="2026-07-02T00:00:00Z",
        )
        obs = await src.apoll()
        assert len(obs) == 1
        assert obs[0].mission_effect_observed
        assert not obs[0].no_effect_sustained

    @pytest.mark.asyncio
    async def test_fp_no_effect(self) -> None:
        src = SimBridgeObservationSource()
        src.enqueue(
            _alert(),
            _assessment(EnvVerdict.CONFIRMED_FP),
            playbook_id="pb1",
            ts="t",
        )
        obs = await src.apoll()
        assert obs[0].no_effect_sustained
        assert not obs[0].mission_effect_observed

    @pytest.mark.asyncio
    async def test_inconclusive_neither(self) -> None:
        src = SimBridgeObservationSource()
        src.enqueue(
            _alert(),
            _assessment(EnvVerdict.INCONCLUSIVE),
            playbook_id="pb1",
            ts="t",
        )
        obs = await src.apoll()
        assert not obs[0].mission_effect_observed
        assert not obs[0].no_effect_sustained


class TestWindowMin:
    @pytest.mark.asyncio
    async def test_observations_to_window(self) -> None:
        # 1200 records @ 600 rpm → 2 min
        src = SimBridgeObservationSource(records_per_minute=600)
        src.enqueue(
            _alert(),
            _assessment(EnvVerdict.CONFIRMED_FP, observations=1200),
            playbook_id=None,
            ts="t",
        )
        obs = await src.apoll()
        assert obs[0].window_min == 2

    @pytest.mark.asyncio
    async def test_min_window_at_least_one(self) -> None:
        src = SimBridgeObservationSource(records_per_minute=600)
        src.enqueue(
            _alert(),
            _assessment(EnvVerdict.CONFIRMED_TP, observations=10),
            playbook_id=None,
            ts="t",
        )
        obs = await src.apoll()
        assert obs[0].window_min == 1


class TestReoccurrence:
    @pytest.mark.asyncio
    async def test_second_same_pair_is_reoccurred(self) -> None:
        src = SimBridgeObservationSource()
        src.enqueue(
            _alert(id="a1"),
            _assessment(EnvVerdict.CONFIRMED_TP),
            playbook_id="pb1",
            ts="t",
        )
        src.enqueue(
            _alert(id="a2"),
            _assessment(EnvVerdict.CONFIRMED_TP),
            playbook_id="pb1",
            ts="t",
        )
        obs = await src.apoll()
        assert not obs[0].reoccurred
        assert obs[1].reoccurred

    @pytest.mark.asyncio
    async def test_different_actor_no_reoccurrence(self) -> None:
        src = SimBridgeObservationSource()
        src.enqueue(
            _alert(actor_id="A"),
            _assessment(EnvVerdict.CONFIRMED_TP),
            playbook_id="pb1",
            ts="t",
        )
        src.enqueue(
            _alert(actor_id="B", id="a2"),
            _assessment(EnvVerdict.CONFIRMED_TP),
            playbook_id="pb1",
            ts="t",
        )
        obs = await src.apoll()
        assert not obs[0].reoccurred
        assert not obs[1].reoccurred

    @pytest.mark.asyncio
    async def test_no_actor_never_reoccurred(self) -> None:
        src = SimBridgeObservationSource()
        for _ in range(3):
            src.enqueue(
                _alert(actor_id=None),
                _assessment(EnvVerdict.CONFIRMED_TP),
                playbook_id="pb",
                ts="t",
            )
        obs = await src.apoll()
        assert all(not o.reoccurred for o in obs)


class TestQueueLifecycle:
    @pytest.mark.asyncio
    async def test_apoll_drains(self) -> None:
        src = SimBridgeObservationSource()
        src.enqueue(
            _alert(),
            _assessment(EnvVerdict.CONFIRMED_TP),
            playbook_id="pb",
            ts="t",
        )
        assert src.pending() == 1
        await src.apoll()
        assert src.pending() == 0
        obs = await src.apoll()
        assert obs == []


class TestEndToEndFanOut:
    @pytest.mark.asyncio
    async def test_sim_source_feeds_outcome_probe_agent(self) -> None:
        """sim_bridge → OutcomeProbeAgent → actors/pb_scores 적립."""
        actor_store = InMemoryActorStore()
        src = SimBridgeObservationSource()
        src.enqueue(
            _alert(),
            _assessment(EnvVerdict.CONFIRMED_TP),
            playbook_id="pb-block",
            ts="2026-07-02T00:00:00Z",
            judge_features=JudgeFeatures(
                has_signal=True, has_rule=True, corroborated=True, confidence=0.9
            ),
            alert_verdict=Verdict.TRUE_POSITIVE,
        )
        agent = OutcomeProbeAgent(
            Settings(),
            src,
            ProbeEngine(),
            actor_gate=ActorWriteGate(actor_store),
            pb_gate=ActorPlaybookOutcomeGate(actor_store),
        )
        report = await agent.run()
        # actor 1 + pb 1
        assert report.auto_applied == 2
        prof = await actor_store.aload("team-red")
        assert prof is not None
        assert "pb-block" in prof.pb_scores
