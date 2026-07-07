"""PredictionMatcher 단위 테스트 — 읽기 전용 pending 대조 enrich."""

import pytest

from core.actors import (
    ActorReadGate,
    InMemoryActorStore,
    Sha256ActorSigner,
)
from core.models import ActorProfile, Alert, PendingPrediction, Severity
from core.predictor import PredictionMatcher


def _alert(technique: str, actor_id: str | None = "APT-X") -> Alert:
    return Alert(
        id="a-next",
        scenario_id="S2",
        title="test",
        severity_baseline=Severity.MEDIUM,
        signals=["sig"],
        mitre={"techniques": [technique]},
        actor_id=actor_id,
    )


async def _seed_profile(store: InMemoryActorStore, pending_technique: str) -> None:
    signer = Sha256ActorSigner()
    profile = ActorProfile(
        actor_id="APT-X",
        is_explicit=True,
        pending_predictions=[
            PendingPrediction(
                technique=pending_technique,
                probability=0.8,
                source_alert_id="a0",
            )
        ],
    )
    profile.content_hash = profile.fingerprint()
    profile.signature = signer.sign(profile.content_hash)
    await store.awrite(profile)


class TestPredictionMatcher:
    """읽기 전용 대조 — Alert.prediction_match 세팅."""

    @pytest.mark.asyncio
    async def test_matching_technique_sets_flag(self) -> None:
        """pending technique 일치 시 prediction_match=True."""
        store = InMemoryActorStore()
        await _seed_profile(store, "T0855")
        matcher = PredictionMatcher(ActorReadGate(store))

        enriched = await matcher.enrich(_alert("T0855"))

        assert enriched.prediction_match is True

    @pytest.mark.asyncio
    async def test_non_matching_technique_no_flag(self) -> None:
        """불일치면 False 유지."""
        store = InMemoryActorStore()
        await _seed_profile(store, "T0855")
        matcher = PredictionMatcher(ActorReadGate(store))

        enriched = await matcher.enrich(_alert("T0999"))

        assert enriched.prediction_match is False

    @pytest.mark.asyncio
    async def test_no_actor_id_no_flag(self) -> None:
        """actor 식별 불가(빈 fingerprint)면 대조 생략."""
        store = InMemoryActorStore()
        await _seed_profile(store, "T0855")
        matcher = PredictionMatcher(ActorReadGate(store))
        alert = Alert(
            id="a-next",
            scenario_id="S2",
            title="test",
            severity_baseline=Severity.MEDIUM,
        )

        enriched = await matcher.enrich(alert)

        assert enriched.prediction_match is False

    @pytest.mark.asyncio
    async def test_matcher_does_not_mutate_store(self) -> None:
        """읽기 전용 — 대조가 프로필(pending/카운터)을 바꾸지 않는다."""
        store = InMemoryActorStore()
        await _seed_profile(store, "T0855")
        matcher = PredictionMatcher(ActorReadGate(store))

        await matcher.enrich(_alert("T0855"))

        profile = await store.aload("APT-X")
        assert profile is not None
        assert len(profile.pending_predictions) == 1
        assert profile.prediction_hits == 0

    @pytest.mark.asyncio
    async def test_tampered_profile_ignored(self) -> None:
        """서명 불일치 프로필은 읽기 게이트가 기각 — 대조 안 됨(포이즈닝 면역)."""
        store = InMemoryActorStore()
        profile = ActorProfile(
            actor_id="APT-X",
            is_explicit=True,
            pending_predictions=[
                PendingPrediction(
                    technique="T0855", probability=0.8, source_alert_id="a0"
                )
            ],
            signature="forged",
            content_hash="forged",
        )
        await store.awrite(profile)
        matcher = PredictionMatcher(ActorReadGate(store))

        enriched = await matcher.enrich(_alert("T0855"))

        assert enriched.prediction_match is False
