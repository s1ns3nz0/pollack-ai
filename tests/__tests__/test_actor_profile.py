"""spec #2 Attacker Profile Store — fingerprint, gate, Triage/Investigation 통합."""

from __future__ import annotations

import pytest

from agents.investigation_agent import InvestigationAgent
from agents.triage_agent import TriageAgent
from core.actor_fingerprint import (
    empty_fingerprint,
    fingerprint,
    is_empty_fingerprint,
    resolve_actor_id,
)
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
)
from core.settings import Settings
from core.severity import SeverityEngine


def _alert(**kwargs: object) -> Alert:
    base: dict[str, object] = {
        "id": "a1",
        "scenario_id": "S2-MOVEMENT",
        "title": "Lateral",
        "severity_baseline": Severity.MEDIUM,
        "signals": ["sig.a"],
        "mitre": {
            "tactics": ["TA0008"],
            "techniques": ["T1021"],
        },
        "iocs": ["203.0.113.1", "evil.example.com"],
        "expected_detection": {"sigma_rule": "r1"},
        "asset_id": "GCS",
    }
    base.update(kwargs)
    return Alert.model_validate(base)


class TestFingerprint:
    def test_same_alert_same_key(self) -> None:
        a = _alert()
        b = _alert()
        assert fingerprint(a) == fingerprint(b)

    def test_signal_order_invariant(self) -> None:
        a = _alert(signals=["a", "b"])
        b = _alert(signals=["b", "a"])
        assert fingerprint(a) == fingerprint(b)

    def test_ip24_masking(self) -> None:
        a = _alert(iocs=["203.0.113.1"])
        b = _alert(iocs=["203.0.113.99"])
        assert fingerprint(a) == fingerprint(b)

    def test_empty_returns_known_constant(self) -> None:
        alert = Alert(
            id="x",
            scenario_id="",
            title="",
            severity_baseline=Severity.INFO,
            signals=[],
            iocs=[],
            mitre={},
        )
        fp = fingerprint(alert)
        assert fp == empty_fingerprint()
        assert is_empty_fingerprint(fp)

    def test_resolve_explicit_wins(self) -> None:
        a = _alert(actor_id="team-x")
        actor_id, is_explicit = resolve_actor_id(a)
        assert actor_id == "team-x"
        assert is_explicit

    def test_resolve_falls_back_to_fingerprint(self) -> None:
        actor_id, is_explicit = resolve_actor_id(_alert())
        assert actor_id.startswith("fp:")
        assert not is_explicit


class TestActorWriteGate:
    @pytest.mark.asyncio
    async def test_rejects_non_tp(self) -> None:
        gate = ActorWriteGate(InMemoryActorStore())
        decision = await gate.submit(
            _alert(),
            EnvVerdict.CONFIRMED_FP,
            Provenance.AUTO,
        )
        assert decision.status == ActorWriteStatus.REJECTED_NOT_TP

    @pytest.mark.asyncio
    async def test_rejects_empty_fingerprint(self) -> None:
        empty = Alert(
            id="e",
            scenario_id="",
            title="",
            severity_baseline=Severity.INFO,
            signals=[],
            iocs=[],
            mitre={},
        )
        gate = ActorWriteGate(InMemoryActorStore())
        decision = await gate.submit(empty, EnvVerdict.CONFIRMED_TP, Provenance.AUTO)
        assert decision.status == ActorWriteStatus.REJECTED_EMPTY

    @pytest.mark.asyncio
    async def test_writes_and_merges(self) -> None:
        store = InMemoryActorStore()
        gate = ActorWriteGate(store)
        await gate.submit(_alert(), EnvVerdict.CONFIRMED_TP, Provenance.AUTO)
        await gate.submit(_alert(), EnvVerdict.CONFIRMED_TP, Provenance.AUTO)
        keys = list(store._by_id.keys())  # noqa: SLF001
        assert len(keys) == 1
        prof = await store.aload(keys[0])
        assert prof is not None
        assert prof.alert_count == 2
        # T1021 빈도 2
        stats = [s for s in prof.ttp_stats if s.technique == "T1021"]
        assert stats and stats[0].count == 2

    @pytest.mark.asyncio
    async def test_kill_chain_cap(self) -> None:
        store = InMemoryActorStore()
        gate = ActorWriteGate(store)
        for i in range(60):
            await gate.submit(
                _alert(id=f"a{i}"),
                EnvVerdict.CONFIRMED_TP,
                Provenance.AUTO,
            )
        prof = list(store._by_id.values())[0]  # noqa: SLF001
        assert len(prof.kill_chain) <= 50

    @pytest.mark.asyncio
    async def test_explicit_id_used(self) -> None:
        store = InMemoryActorStore()
        gate = ActorWriteGate(store)
        await gate.submit(
            _alert(actor_id="team-red"),
            EnvVerdict.CONFIRMED_TP,
            Provenance.AUTO,
        )
        prof = await store.aload("team-red")
        assert prof is not None
        assert prof.is_explicit


class TestActorReadGate:
    @pytest.mark.asyncio
    async def test_returns_none_when_missing(self) -> None:
        gate = ActorReadGate(InMemoryActorStore())
        assert await gate.recall("missing") is None

    @pytest.mark.asyncio
    async def test_drops_unsigned(self) -> None:
        from core.models import ActorProfile

        store = InMemoryActorStore()
        await store.awrite(ActorProfile(actor_id="x", is_explicit=True, alert_count=3))
        gate = ActorReadGate(store)
        assert await gate.recall("x") is None  # 미서명 폐기

    @pytest.mark.asyncio
    async def test_round_trip(self) -> None:
        store = InMemoryActorStore()
        write = ActorWriteGate(store)
        await write.submit(
            _alert(actor_id="team-blue"),
            EnvVerdict.CONFIRMED_TP,
            Provenance.AUTO,
        )
        read = ActorReadGate(store)
        prof = await read.recall("team-blue")
        assert prof is not None
        assert prof.alert_count == 1


class TestTriagePriorityBoost:
    @pytest.mark.asyncio
    async def test_explicit_active_actor_priority_reduced(self) -> None:
        store = InMemoryActorStore()
        write = ActorWriteGate(store)
        # explicit actor — 3회 누적
        for i in range(3):
            await write.submit(
                _alert(id=f"a{i}", actor_id="team-x"),
                EnvVerdict.CONFIRMED_TP,
                Provenance.AUTO,
            )
        read = ActorReadGate(store)
        triage = TriageAgent(
            Settings(), SeverityEngine(), actor_read=read, min_alerts=2
        )
        out: SOCState = await triage.run({"alert": _alert(actor_id="team-x")})
        # M baseline + asset T1+1 + phase 0 = M(2)+1+0 = 3=L → priority 3
        # explicit actor boost → priority 2
        assert out["priority"] >= 1
        assert any("priority -1" in r for r in out["severity_rationale"])

    @pytest.mark.asyncio
    async def test_fingerprint_actor_no_priority_change(self) -> None:
        store = InMemoryActorStore()
        write = ActorWriteGate(store)
        for i in range(3):
            await write.submit(
                _alert(id=f"a{i}"),
                EnvVerdict.CONFIRMED_TP,
                Provenance.AUTO,
            )
        read = ActorReadGate(store)
        triage = TriageAgent(
            Settings(), SeverityEngine(), actor_read=read, min_alerts=2
        )
        out: SOCState = await triage.run({"alert": _alert()})
        # actor_id 미설정 → 가중 안 됨
        assert not any("priority -1" in r for r in out["severity_rationale"])


class TestInvestigationConfidenceBoost:
    @pytest.mark.asyncio
    async def test_actor_ttp_match_boosts_confidence(self) -> None:
        store = InMemoryActorStore()
        write = ActorWriteGate(store)
        await write.submit(
            _alert(actor_id="team-x"),
            EnvVerdict.CONFIRMED_TP,
            Provenance.AUTO,
        )
        read = ActorReadGate(store)
        agent = InvestigationAgent(
            Settings(),
            retriever=None,
            actor_read=read,
        )
        out = await agent.run({"alert": _alert(actor_id="team-x")})
        inv = out["investigation"]
        # base 0.3 + 0.2 actor boost = 0.5
        assert inv.confidence >= 0.5
        flags = out.get("guardrail_flags", [])
        assert any("TTP 매치" in f for f in flags)

    @pytest.mark.asyncio
    async def test_no_actor_read_no_change(self) -> None:
        agent = InvestigationAgent(Settings(), retriever=None, actor_read=None)
        out = await agent.run({"alert": _alert(actor_id="team-x")})
        assert out["investigation"].confidence == 0.3
