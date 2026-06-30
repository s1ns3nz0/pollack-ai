"""spec B-1 PB 효과 점수 학습 — 모델 + gate + Report 노출."""

from __future__ import annotations

from pydantic import ValidationError
import pytest

from agents.report_agent import ReportAgent
from core.actors import (
    ActorReadGate,
    ActorWriteGate,
    ActorWriteStatus,
    InMemoryActorStore,
)
from core.models import (
    Alert,
    EnvVerdict,
    Provenance,
    Severity,
    SOCState,
    Verdict,
)
from core.playbook_outcome import (
    ActorPlaybookOutcomeGate,
    PlaybookOutcome,
)
from core.settings import Settings
from core.severity import SeverityEngine


def _alert(**kwargs: object) -> Alert:
    base: dict[str, object] = {
        "id": "a1",
        "scenario_id": "S2",
        "title": "X",
        "severity_baseline": Severity.MEDIUM,
        "signals": ["sig.a"],
        "expected_detection": {"sigma_rule": "r1"},
        "mitre": {"tactics": ["TA0008"], "techniques": ["T1021"]},
        "actor_id": "team-red",
    }
    base.update(kwargs)
    return Alert.model_validate(base)


class TestOutcomeModel:
    def test_effect_bounds_low(self) -> None:
        with pytest.raises(ValidationError):
            PlaybookOutcome(actor_id="x", playbook_id="p", effect=-0.1, ts="2026-06-30")

    def test_effect_bounds_high(self) -> None:
        with pytest.raises(ValidationError):
            PlaybookOutcome(actor_id="x", playbook_id="p", effect=1.1, ts="2026-06-30")


class TestGateRejection:
    @pytest.mark.asyncio
    async def test_rejects_empty(self) -> None:
        gate = ActorPlaybookOutcomeGate(InMemoryActorStore())
        out = await gate.submit(
            PlaybookOutcome(actor_id="", playbook_id="p", effect=0.5, ts="t")
        )
        assert out.status == ActorWriteStatus.REJECTED_EMPTY

    @pytest.mark.asyncio
    async def test_rejects_no_actor(self) -> None:
        gate = ActorPlaybookOutcomeGate(InMemoryActorStore())
        out = await gate.submit(
            PlaybookOutcome(actor_id="missing", playbook_id="p", effect=0.5, ts="t")
        )
        assert out.status == ActorWriteStatus.REJECTED_NO_ACTOR


class TestGateAccumulation:
    @pytest.mark.asyncio
    async def test_accumulates_avg(self) -> None:
        store = InMemoryActorStore()
        # actor 먼저 적립
        write = ActorWriteGate(store)
        await write.submit(_alert(), EnvVerdict.CONFIRMED_TP, Provenance.AUTO)
        # 3 outcome 누적
        gate = ActorPlaybookOutcomeGate(store)
        for eff in (1.0, 0.5, 0.0):
            r = await gate.submit(
                PlaybookOutcome(
                    actor_id="team-red",
                    playbook_id="pb1",
                    effect=eff,
                    ts="2026-06-30T00:00:00Z",
                )
            )
            assert r.status == ActorWriteStatus.WRITTEN
        prof = await store.aload("team-red")
        assert prof is not None
        score = prof.pb_scores["pb1"]
        assert score.count == 3
        assert score.avg_effect == 0.5

    @pytest.mark.asyncio
    async def test_independent_playbooks(self) -> None:
        store = InMemoryActorStore()
        await ActorWriteGate(store).submit(
            _alert(), EnvVerdict.CONFIRMED_TP, Provenance.AUTO
        )
        gate = ActorPlaybookOutcomeGate(store)
        await gate.submit(
            PlaybookOutcome(actor_id="team-red", playbook_id="pbA", effect=1.0, ts="t")
        )
        await gate.submit(
            PlaybookOutcome(actor_id="team-red", playbook_id="pbB", effect=0.0, ts="t")
        )
        prof = await store.aload("team-red")
        assert prof is not None
        assert prof.pb_scores["pbA"].avg_effect == 1.0
        assert prof.pb_scores["pbB"].avg_effect == 0.0


class TestGateSignatureRoundTrip:
    @pytest.mark.asyncio
    async def test_read_after_outcome_passes_verify(self) -> None:
        store = InMemoryActorStore()
        await ActorWriteGate(store).submit(
            _alert(), EnvVerdict.CONFIRMED_TP, Provenance.AUTO
        )
        await ActorPlaybookOutcomeGate(store).submit(
            PlaybookOutcome(actor_id="team-red", playbook_id="pb1", effect=0.8, ts="t")
        )
        # ReadGate 가 서명 재계산 후 None 안 줘야 함 (서명 일관성).
        prof = await ActorReadGate(store).recall("team-red")
        assert prof is not None
        assert prof.pb_scores["pb1"].avg_effect == 0.8


class TestReportExposure:
    @pytest.mark.asyncio
    async def test_pb_scores_in_guardrail_flags(self) -> None:
        store = InMemoryActorStore()
        await ActorWriteGate(store).submit(
            _alert(), EnvVerdict.CONFIRMED_TP, Provenance.AUTO
        )
        await ActorPlaybookOutcomeGate(store).submit(
            PlaybookOutcome(
                actor_id="team-red", playbook_id="pb_block", effect=0.9, ts="t"
            )
        )
        agent = ReportAgent(
            Settings(),
            SeverityEngine(),
            actor_read=ActorReadGate(store),
        )
        out: SOCState = await agent.run(
            {
                "alert": _alert(),
                "severity": Severity.MEDIUM,
                "verdict": Verdict.TRUE_POSITIVE,
            }
        )
        flags = out["report"].guardrail_flags
        assert any("PB 효과" in f for f in flags)
        assert any("pb_block" in f for f in flags)

    @pytest.mark.asyncio
    async def test_no_actor_read_skip(self) -> None:
        agent = ReportAgent(Settings(), SeverityEngine())
        out: SOCState = await agent.run(
            {
                "alert": _alert(),
                "severity": Severity.MEDIUM,
                "verdict": Verdict.TRUE_POSITIVE,
            }
        )
        assert not any("PB 효과" in f for f in out["report"].guardrail_flags)
