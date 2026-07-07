"""예측 폐루프 그래프 통합 테스트 — pending 적중 알람이 파이프라인에서 격상."""

import pytest

from agents.graph import build_soc_graph
from core.actors import (
    ActorReadGate,
    ActorWriteGate,
    InMemoryActorStore,
    Sha256ActorSigner,
)
from core.models import (
    ActorProfile,
    Alert,
    PendingPrediction,
    Severity,
)
from core.settings import Settings


async def _seeded_gates() -> tuple[ActorReadGate, ActorWriteGate]:
    store = InMemoryActorStore()
    signer = Sha256ActorSigner()
    profile = ActorProfile(
        actor_id="APT-X",
        is_explicit=True,
        pending_predictions=[
            PendingPrediction(technique="T0855", probability=0.8, source_alert_id="a0")
        ],
    )
    profile.content_hash = profile.fingerprint()
    profile.signature = signer.sign(profile.content_hash)
    await store.awrite(profile)
    return ActorReadGate(store), ActorWriteGate(store)


def _alert(technique: str) -> Alert:
    return Alert(
        id="a-next",
        scenario_id="S2",
        title="C2 이상 명령",
        asset_tier="T2-Important",
        severity_baseline=Severity.MEDIUM,
        signals=["명령 시퀀스 불연속"],
        mitre={"techniques": [technique]},
        expected_detection={"sigma_rule": "uav_c2_unauthorized_cmd.yml"},
        actor_id="APT-X",
    )


class TestPredictionGraphWiring:
    """그래프 수준 폐루프 — matcher 배선 + dynamics 격상."""

    @pytest.mark.asyncio
    async def test_predicted_alert_escalated_in_pipeline(self) -> None:
        """pending 예측 적중 알람 → severity 가 미적중 대비 격상."""
        read, write = await _seeded_gates()
        graph = build_soc_graph(settings=Settings(), actor_read=read, actor_write=write)
        state_hit = await graph.ainvoke({"alert": _alert("T0855")})

        read2, write2 = await _seeded_gates()
        graph2 = build_soc_graph(
            settings=Settings(), actor_read=read2, actor_write=write2
        )
        state_base = await graph2.ainvoke({"alert": _alert("T0999")})

        order = {"i": 0, "l": 1, "m": 2, "h": 3}
        assert order[str(state_hit["severity"])] > order[str(state_base["severity"])]

    @pytest.mark.asyncio
    async def test_report_contains_staged_defenses_when_predictions(
        self,
    ) -> None:
        """기본 배선에서 예측 발생 시 report.staged_defenses 노출 준비 확인.

        (예측은 kill_chain 이 충분할 때만 나옴 — 여기선 stager 배선 자체를
        검증: 예측 없으면 빈 리스트여야 한다.)
        """
        read, write = await _seeded_gates()
        graph = build_soc_graph(settings=Settings(), actor_read=read, actor_write=write)

        state = await graph.ainvoke({"alert": _alert("T0855")})

        assert state["report"].staged_defenses == []
