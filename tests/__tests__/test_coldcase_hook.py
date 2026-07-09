"""ActorWriteGate reopener 훅 테스트 — TP 적립 시 과거 억제 재심 발동."""

import pytest

from core.actors import ActorWriteGate, InMemoryActorStore
from core.coldcase import ColdCaseReopener, ReopenLedger
from core.experience import InMemoryExperienceStore, Sha256Signer
from core.models import (
    Alert,
    EnvVerdict,
    ExperienceRecord,
    JudgeFeatures,
    Provenance,
    Severity,
    Verdict,
)


async def _seed_fp(
    store: InMemoryExperienceStore, *, actor_fp: str, signals: list[str]
) -> None:
    signer = Sha256Signer()
    rec = ExperienceRecord(
        scenario_id="S2",
        signals=signals,
        verdict=Verdict.FALSE_POSITIVE,
        severity=Severity.LOW,
        judge_features=JudgeFeatures(
            has_signal=True, has_rule=False, corroborated=False, confidence=0.3
        ),
        env_verdict=EnvVerdict.CONFIRMED_FP,
        provenance=Provenance.ENV_VERIFIED,
        actor_fingerprint=actor_fp,
    )
    fp = rec.fingerprint()
    await store.awrite(
        rec.model_copy(update={"content_hash": fp, "signature": signer.sign(fp)})
    )


def _tp_alert(technique: str, signals: list[str]) -> Alert:
    return Alert(
        id="trig-1",
        scenario_id="S2",
        title="C2 확정 공격",
        severity_baseline=Severity.HIGH,
        signals=signals,
        mitre={"tactics": ["TA0008"], "techniques": [technique]},
        actor_id="APT-C2",
    )


class TestReopenerHook:
    """TP 적립 시 reopener 발동(주입 시)."""

    @pytest.mark.asyncio
    async def test_tp_triggers_actor_reopen(self) -> None:
        """동일 actor 과거 FP → TP 적립이 재심 발동."""
        actor_store = InMemoryActorStore()
        exp_store = InMemoryExperienceStore()
        # actors 의 explicit actor_id 는 그대로 지문 역할.
        await _seed_fp(exp_store, actor_fp="APT-C2", signals=["옛 신호"])
        ledger = ReopenLedger()
        gate = ActorWriteGate(actor_store, reopener=ColdCaseReopener(exp_store, ledger))

        await gate.submit(
            _tp_alert("T0855", ["명령 시퀀스 불연속"]), EnvVerdict.CONFIRMED_TP
        )

        assert len(ledger.cases()) == 1
        assert ledger.cases()[0].reason.startswith("동일 actor")

    @pytest.mark.asyncio
    async def test_tp_triggers_signature_reopen(self) -> None:
        """동일 signature 겹침 과거 FP → 재심 발동."""
        exp_store = InMemoryExperienceStore()
        await _seed_fp(exp_store, actor_fp="other", signals=["명령 시퀀스 불연속"])
        ledger = ReopenLedger()
        gate = ActorWriteGate(
            InMemoryActorStore(), reopener=ColdCaseReopener(exp_store, ledger)
        )

        await gate.submit(
            _tp_alert("T0855", ["명령 시퀀스 불연속"]), EnvVerdict.CONFIRMED_TP
        )

        assert len(ledger.cases()) == 1
        assert "signature" in ledger.cases()[0].reason

    @pytest.mark.asyncio
    async def test_fp_does_not_trigger_reopen(self) -> None:
        """비 TP 는 재심 발동 안 함(비대칭 신뢰 — 억제는 TP 로만 푼다)."""
        exp_store = InMemoryExperienceStore()
        await _seed_fp(exp_store, actor_fp="APT-C2", signals=["명령 시퀀스 불연속"])
        ledger = ReopenLedger()
        gate = ActorWriteGate(
            InMemoryActorStore(), reopener=ColdCaseReopener(exp_store, ledger)
        )

        await gate.submit(
            _tp_alert("T0855", ["명령 시퀀스 불연속"]), EnvVerdict.CONFIRMED_FP
        )

        assert ledger.cases() == []

    @pytest.mark.asyncio
    async def test_no_reopener_no_error(self) -> None:
        """reopener 미주입 시 기존 동작 유지(하위호환)."""
        gate = ActorWriteGate(InMemoryActorStore())

        decision = await gate.submit(
            _tp_alert("T0855", ["sig"]), EnvVerdict.CONFIRMED_TP
        )

        assert decision.written
