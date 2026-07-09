"""ColdCaseReopener 단위 테스트 — 억제 재심(revoke + 재심 큐)."""

import pytest

from core.coldcase import ColdCaseReopener, ReopenLedger
from core.experience import (
    InMemoryExperienceStore,
    MemoryReadGate,
    RecallPurpose,
    Sha256Signer,
)
from core.models import (
    EnvVerdict,
    ExperienceRecord,
    JudgeFeatures,
    Provenance,
    Severity,
    Verdict,
)


def _fp_rec(**overrides: object) -> ExperienceRecord:
    base: dict[str, object] = {
        "scenario_id": "S2",
        "signals": ["명령 시퀀스 불연속"],
        "verdict": Verdict.FALSE_POSITIVE,
        "severity": Severity.LOW,
        "judge_features": JudgeFeatures(
            has_signal=True, has_rule=False, corroborated=False, confidence=0.3
        ),
        "env_verdict": EnvVerdict.CONFIRMED_FP,
        "provenance": Provenance.ENV_VERIFIED,
    }
    base.update(overrides)
    return ExperienceRecord.model_validate(base)


async def _seed(store: InMemoryExperienceStore, rec: ExperienceRecord) -> None:
    signer = Sha256Signer()
    fp = rec.fingerprint()
    signed = rec.model_copy(update={"content_hash": fp, "signature": signer.sign(fp)})
    await store.awrite(signed)


class TestReopenByActor:
    """동일 actor 확정 트리거 — 그 actor 의 과거 FP 재심."""

    @pytest.mark.asyncio
    async def test_matching_actor_revokes_fp(self) -> None:
        """동일 actor_fingerprint FP → revoke + 큐 적재."""
        store = InMemoryExperienceStore()
        await _seed(store, _fp_rec(actor_fingerprint="fp:apt-x"))
        ledger = ReopenLedger()
        reopener = ColdCaseReopener(store, ledger)

        reopened = await reopener.reopen_for_actor("fp:apt-x", "trig-1")

        assert len(reopened) == 1
        # 회상에서 사라졌는지 확인
        hits = await MemoryReadGate(store).recall("S2", RecallPurpose.SUPPRESSION)
        assert hits == []
        assert len(ledger.cases()) == 1
        assert ledger.cases()[0].trigger_alert_id == "trig-1"

    @pytest.mark.asyncio
    async def test_different_actor_untouched(self) -> None:
        """다른 actor FP 는 건드리지 않음."""
        store = InMemoryExperienceStore()
        await _seed(store, _fp_rec(actor_fingerprint="fp:other"))
        reopener = ColdCaseReopener(store, ReopenLedger())

        reopened = await reopener.reopen_for_actor("fp:apt-x", "trig-1")

        assert reopened == []
        hits = await MemoryReadGate(store).recall("S2", RecallPurpose.SUPPRESSION)
        assert len(hits) == 1

    @pytest.mark.asyncio
    async def test_empty_actor_fingerprint_noop(self) -> None:
        """빈 actor_fingerprint 트리거는 무동작(전체 revoke 방지)."""
        store = InMemoryExperienceStore()
        await _seed(store, _fp_rec(actor_fingerprint=""))
        reopener = ColdCaseReopener(store, ReopenLedger())

        reopened = await reopener.reopen_for_actor("", "trig-1")

        assert reopened == []


class TestReopenBySignature:
    """동일 signature 후속 TP 트리거 — 신호 겹침 FP 재심."""

    @pytest.mark.asyncio
    async def test_overlapping_signals_revoked(self) -> None:
        """TP signals 와 겹치는 과거 FP → revoke."""
        store = InMemoryExperienceStore()
        await _seed(store, _fp_rec(signals=["명령 시퀀스 불연속", "비인가 GCS"]))
        reopener = ColdCaseReopener(store, ReopenLedger())

        reopened = await reopener.reopen_for_signature(["명령 시퀀스 불연속"], "trig-1")

        assert len(reopened) == 1

    @pytest.mark.asyncio
    async def test_disjoint_signals_untouched(self) -> None:
        """신호 교집합 없으면 재심 안 함."""
        store = InMemoryExperienceStore()
        await _seed(store, _fp_rec(signals=["펌웨어 해시 변경"]))
        reopener = ColdCaseReopener(store, ReopenLedger())

        reopened = await reopener.reopen_for_signature(["명령 시퀀스 불연속"], "trig-1")

        assert reopened == []


class TestIdempotency:
    """이미 revoke 된 케이스는 재revoke·중복 적재 안 함."""

    @pytest.mark.asyncio
    async def test_already_revoked_not_requeued(self) -> None:
        """revoke 된 레코드는 다시 큐에 안 들어감."""
        store = InMemoryExperienceStore()
        await _seed(store, _fp_rec(actor_fingerprint="fp:apt-x"))
        ledger = ReopenLedger()
        reopener = ColdCaseReopener(store, ledger)

        await reopener.reopen_for_actor("fp:apt-x", "trig-1")
        second = await reopener.reopen_for_actor("fp:apt-x", "trig-2")

        assert second == []
        assert len(ledger.cases()) == 1
