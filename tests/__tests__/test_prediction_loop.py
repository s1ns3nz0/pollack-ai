"""예측 폐루프 — ActorWriteGate 발행/적중/만료 단위 테스트."""

import pytest

from core.actors import ActorWriteGate, InMemoryActorStore
from core.models import (
    ActorProfile,
    Alert,
    AttackPrediction,
    EnvVerdict,
    PendingPrediction,
    Severity,
)


def _tp_alert(alert_id: str, technique: str) -> Alert:
    return Alert(
        id=alert_id,
        scenario_id="S2",
        title="test",
        severity_baseline=Severity.HIGH,
        signals=["sig"],
        mitre={"tactics": ["TA0008"], "techniques": [technique]},
        actor_id="APT-X",
    )


class _FixedPredictor:
    """항상 고정 예측을 반환하는 테스트 더블."""

    def __init__(self, techniques: list[str]) -> None:
        self._techniques = techniques

    def predict(self, profile: ActorProfile, current: str) -> list[AttackPrediction]:
        return [
            AttackPrediction(
                next_technique=t,
                probability=0.8,
                support_count=3,
                basis_actor_id=profile.actor_id,
            )
            for t in self._techniques
        ]


class TestPredictionIssuance:
    """TP 적립 시 예측 발행 테스트."""

    @pytest.mark.asyncio
    async def test_tp_submit_issues_pending_prediction(self) -> None:
        """이력 있는 actor 의 TP 적립 시 predictor 결과가 pending 으로 적립.

        첫 알람은 이력(existing) 이 없어 발행하지 않는다 — 무근거 예측 방지.
        """
        store = InMemoryActorStore()
        gate = ActorWriteGate(store, predictor=_FixedPredictor(["T0855"]))

        await gate.submit(_tp_alert("a1", "T0830"), EnvVerdict.CONFIRMED_TP)
        first = await store.aload("APT-X")
        assert first is not None and first.pending_predictions == []

        await gate.submit(_tp_alert("a2", "T0831"), EnvVerdict.CONFIRMED_TP)

        profile = await store.aload("APT-X")
        assert profile is not None
        assert [p.technique for p in profile.pending_predictions] == ["T0855"]
        assert profile.pending_predictions[0].source_alert_id == "a2"

    @pytest.mark.asyncio
    async def test_non_tp_issues_nothing(self) -> None:
        """비 TP 는 기존 게이트대로 거부 — 예측도 미발행."""
        store = InMemoryActorStore()
        gate = ActorWriteGate(store, predictor=_FixedPredictor(["T0855"]))

        decision = await gate.submit(_tp_alert("a1", "T0830"), EnvVerdict.CONFIRMED_FP)

        assert not decision.written
        assert await store.aload("APT-X") is None

    @pytest.mark.asyncio
    async def test_duplicate_technique_not_reissued(self) -> None:
        """이미 pending 인 technique 은 중복 발행 안 함."""
        store = InMemoryActorStore()
        gate = ActorWriteGate(store, predictor=_FixedPredictor(["T0855"]))

        await gate.submit(_tp_alert("a1", "T0830"), EnvVerdict.CONFIRMED_TP)
        await gate.submit(_tp_alert("a2", "T0831"), EnvVerdict.CONFIRMED_TP)

        profile = await store.aload("APT-X")
        assert profile is not None
        pending_t0855 = [
            p for p in profile.pending_predictions if p.technique == "T0855"
        ]
        assert len(pending_t0855) == 1


class TestRealPredictorIntegration:
    """실제 SequencePredictor 와의 계약 검증 — pre-merge (prev, curr) 정렬."""

    @pytest.mark.asyncio
    async def test_full_loop_with_real_predictor(self) -> None:
        """반복 킬체인 4회 → 예측 발행 → 다음 알람 적중까지 전체 루프."""
        from core.predictor import SequencePredictor

        store = InMemoryActorStore()
        gate = ActorWriteGate(store, predictor=SequencePredictor())
        chain = ["T0814", "T0855", "T0831"]
        n = 0
        for _round in range(4):
            for tech in chain:
                n += 1
                await gate.submit(_tp_alert(f"a{n}", tech), EnvVerdict.CONFIRMED_TP)

        profile = await store.aload("APT-X")
        assert profile is not None
        # 12번째(T0831) 시점: (T0855,T0831)→T0814 support 3 → 발행돼 있어야 함.
        # (11번째 발행 T0831 은 12번째 알람에서 이미 hit 처리됨.)
        assert "T0814" in [p.technique for p in profile.pending_predictions]
        assert profile.prediction_hits == 1

        # 13번째 T0814 알람 → 두 번째 적중
        await gate.submit(_tp_alert("a13", "T0814"), EnvVerdict.CONFIRMED_TP)
        profile = await store.aload("APT-X")
        assert profile is not None
        assert profile.prediction_hits == 2


class TestPredictionSettlement:
    """후속 TP 알람 대조 — hit/miss 판정 테스트."""

    @pytest.mark.asyncio
    async def test_matching_alert_settles_hit(self) -> None:
        """pending technique 과 일치하는 TP 알람 → hit 적립 + pending 제거."""
        store = InMemoryActorStore()
        gate = ActorWriteGate(store, predictor=_FixedPredictor(["T0855"]))

        await gate.submit(_tp_alert("a0", "T0829"), EnvVerdict.CONFIRMED_TP)
        await gate.submit(_tp_alert("a1", "T0830"), EnvVerdict.CONFIRMED_TP)
        await gate.submit(_tp_alert("a2", "T0855"), EnvVerdict.CONFIRMED_TP)

        profile = await store.aload("APT-X")
        assert profile is not None
        assert profile.prediction_hits == 1
        assert all(
            p.source_alert_id != "a1" or p.technique != "T0855"
            for p in profile.pending_predictions
        )

    @pytest.mark.asyncio
    async def test_ttl_expiry_counts_miss(self) -> None:
        """TTL 알람 수 경과 시 miss 적립 + pending 제거."""
        store = InMemoryActorStore()
        gate = ActorWriteGate(
            store,
            predictor=_FixedPredictor([]),
            prediction_ttl_alerts=2,
        )
        seed = ActorProfile(
            actor_id="APT-X",
            is_explicit=True,
            pending_predictions=[
                PendingPrediction(
                    technique="T0999", probability=0.9, source_alert_id="a0"
                )
            ],
        )
        seed.content_hash = seed.fingerprint()
        seed.signature = gate._signer.sign(seed.content_hash)
        await store.awrite(seed)

        await gate.submit(_tp_alert("a1", "T0830"), EnvVerdict.CONFIRMED_TP)
        await gate.submit(_tp_alert("a2", "T0831"), EnvVerdict.CONFIRMED_TP)

        profile = await store.aload("APT-X")
        assert profile is not None
        assert profile.prediction_misses == 1
        assert profile.pending_predictions == []

    @pytest.mark.asyncio
    async def test_pending_survives_below_ttl(self) -> None:
        """TTL 미만이면 pending 유지 + age 증가."""
        store = InMemoryActorStore()
        gate = ActorWriteGate(
            store,
            predictor=_FixedPredictor(["T0999"]),
            prediction_ttl_alerts=5,
        )

        await gate.submit(_tp_alert("a1", "T0830"), EnvVerdict.CONFIRMED_TP)
        await gate.submit(_tp_alert("a2", "T0831"), EnvVerdict.CONFIRMED_TP)
        await gate.submit(_tp_alert("a3", "T0832"), EnvVerdict.CONFIRMED_TP)

        profile = await store.aload("APT-X")
        assert profile is not None
        pending = [p for p in profile.pending_predictions if p.technique == "T0999"]
        assert pending and pending[0].age_alerts == 1
        assert profile.prediction_misses == 0
