"""KillChainProgressor 테스트 — actor 누적 진행도 → 후반단계 격상 플래그."""

import pytest

from core.actors import (
    ActorReadGate,
    InMemoryActorStore,
    Sha256ActorSigner,
)
from core.killchain import KillChainProgressor
from core.models import (
    ActorProfile,
    ActorTtpStat,
    Alert,
    Severity,
)
from tools.coverage import CoverageMatrix


async def _seed_actor(store: InMemoryActorStore, tactics: list[str]) -> None:
    signer = Sha256ActorSigner()
    profile = ActorProfile(
        actor_id="APT-X",
        is_explicit=True,
        ttp_stats=[
            ActorTtpStat(tactic=t, technique=f"T{i}", count=1, last_seen="t")
            for i, t in enumerate(tactics)
        ],
    )
    profile.content_hash = profile.fingerprint()
    profile.signature = signer.sign(profile.content_hash)
    await store.awrite(profile)


def _alert(tactics: list[str], actor_id: str | None = "APT-X") -> Alert:
    return Alert(
        id="a1",
        scenario_id="S2",
        title="t",
        severity_baseline=Severity.MEDIUM,
        signals=["sig"],
        mitre={"tactics": tactics, "techniques": ["T9"]},
        actor_id=actor_id,
    )


def _progressor(store: InMemoryActorStore) -> KillChainProgressor:
    return KillChainProgressor(
        ActorReadGate(store), CoverageMatrix.from_yaml(), advanced_order=11
    )


class TestKillChainProgressor:
    """actor 누적 tactic → max order → 임계 비교 → kill_chain_advanced."""

    @pytest.mark.asyncio
    async def test_late_stage_actor_flags_advanced(self) -> None:
        """actor 가 후반 단계(Impact=15) 이력 → kill_chain_advanced=True."""
        store = InMemoryActorStore()
        await _seed_actor(store, ["InitialAccess", "Impact"])

        enriched = await _progressor(store).enrich(_alert(["Execution"]))

        assert enriched.kill_chain_advanced is True

    @pytest.mark.asyncio
    async def test_early_stage_actor_no_flag(self) -> None:
        """초기 단계만(InitialAccess=3) 도달 → 격상 안 함."""
        store = InMemoryActorStore()
        await _seed_actor(store, ["InitialAccess"])

        enriched = await _progressor(store).enrich(_alert(["Execution"]))

        assert enriched.kill_chain_advanced is False

    @pytest.mark.asyncio
    async def test_current_alert_tactic_counts(self) -> None:
        """actor 이력 초기여도 현 alert tactic 이 후반이면 누적 max 로 격상."""
        store = InMemoryActorStore()
        await _seed_actor(store, ["InitialAccess"])

        # 현 alert 가 Impact(15) — 누적 max = 15 ≥ 11
        enriched = await _progressor(store).enrich(_alert(["Impact"]))

        assert enriched.kill_chain_advanced is True

    @pytest.mark.asyncio
    async def test_no_actor_uses_alert_only(self) -> None:
        """actor 없는 알람은 현 alert tactic 단발 진행도만."""
        store = InMemoryActorStore()

        enriched = await _progressor(store).enrich(_alert(["Impact"], actor_id=None))

        assert enriched.kill_chain_advanced is True

    @pytest.mark.asyncio
    async def test_read_only_no_mutation(self) -> None:
        """enrich 는 actor 프로필을 변이하지 않는다."""
        store = InMemoryActorStore()
        await _seed_actor(store, ["Impact"])

        await _progressor(store).enrich(_alert(["Execution"]))

        profile = await store.aload("APT-X")
        assert profile is not None
        assert len(profile.ttp_stats) == 1
