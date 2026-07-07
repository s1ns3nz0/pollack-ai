"""예측 적중률 메트릭 단위 테스트 — 카운터 + 렌더 + 게이트 훅."""

import pytest

from app.metrics import _Counters, render_text
from core.actors import ActorWriteGate, InMemoryActorStore
from core.models import (
    ActorProfile,
    Alert,
    EnvVerdict,
    PendingPrediction,
    Severity,
)


class TestPredictionCounters:
    """record_prediction 누적 + 비율 산출."""

    def test_record_and_ratio(self) -> None:
        """hit 2 / miss 1 → ratio 0.667."""
        c = _Counters()

        c.record_prediction(hit=True)
        c.record_prediction(hit=True)
        c.record_prediction(hit=False)

        stats = c.prediction_stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert stats["hit_ratio"] == 0.667

    def test_empty_stats(self) -> None:
        """판정 0건이면 ratio 없음(division 방지)."""
        c = _Counters()

        assert c.prediction_stats() == {}

    def test_render_text_exposes_prediction_metrics(self) -> None:
        """/metrics 텍스트에 soc_prediction 라인 노출."""
        from app.metrics import metrics

        metrics().record_prediction(hit=True)

        text = render_text()
        assert "soc_prediction_hit_total" in text
        assert "soc_prediction_hit_ratio" in text


class TestGateSettleHook:
    """ActorWriteGate on_settle 훅 — hit/miss 판정 시 콜백."""

    @pytest.mark.asyncio
    async def test_hook_called_on_hit_and_miss(self) -> None:
        """hit 1건 + TTL miss 1건 → 훅 2회(True, False)."""
        calls: list[bool] = []
        store = InMemoryActorStore()
        gate = ActorWriteGate(
            store,
            prediction_ttl_alerts=1,
            on_settle=calls.append,
        )
        seed = ActorProfile(
            actor_id="APT-X",
            is_explicit=True,
            pending_predictions=[
                PendingPrediction(
                    technique="T0855", probability=0.8, source_alert_id="a0"
                ),
                PendingPrediction(
                    technique="T0999", probability=0.7, source_alert_id="a0"
                ),
            ],
        )
        seed.content_hash = seed.fingerprint()
        seed.signature = gate._signer.sign(seed.content_hash)
        await store.awrite(seed)

        alert = Alert(
            id="a1",
            scenario_id="S2",
            title="t",
            severity_baseline=Severity.HIGH,
            signals=["sig"],
            mitre={"techniques": ["T0855"]},
            actor_id="APT-X",
        )
        await gate.submit(alert, EnvVerdict.CONFIRMED_TP)

        assert sorted(calls) == [False, True]
