"""재심 메트릭 테스트 — soc_coldcase_reopened_total 카운터 + 렌더."""

import pytest

from app.metrics import _Counters, render_text
from core.coldcase import ColdCaseReopener, ReopenLedger
from core.experience import InMemoryExperienceStore, Sha256Signer
from core.models import (
    EnvVerdict,
    ExperienceRecord,
    JudgeFeatures,
    Provenance,
    Severity,
    Verdict,
)


class TestReopenCounter:
    """record_reopen 누적 + 렌더."""

    def test_record_and_total(self) -> None:
        c = _Counters()

        c.record_reopen()
        c.record_reopen()

        assert c.coldcase_reopened_total == 2

    def test_render_exposes_metric(self) -> None:
        from app.metrics import metrics

        metrics().record_reopen()

        assert "soc_coldcase_reopened_total" in render_text()


async def _seed(store: InMemoryExperienceStore, actor_fp: str) -> None:
    signer = Sha256Signer()
    rec = ExperienceRecord(
        scenario_id="S2",
        signals=["sig"],
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


class TestReopenerCallback:
    """ColdCaseReopener on_reopen 콜백 — revoke 마다 발동."""

    @pytest.mark.asyncio
    async def test_callback_fires_per_reopen(self) -> None:
        store = InMemoryExperienceStore()
        await _seed(store, "fp:x")
        count = {"n": 0}

        def _cb() -> None:
            count["n"] += 1

        reopener = ColdCaseReopener(store, ReopenLedger(), on_reopen=_cb)
        await reopener.reopen_for_actor("fp:x", "trig-1")

        assert count["n"] == 1
