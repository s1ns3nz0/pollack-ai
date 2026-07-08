"""캠페인 report 노출 테스트 — actor 시나리오 이력 → 진행 캠페인 report 노출."""

import pytest

from agents.report_agent import ReportAgent
from core.actors import (
    ActorReadGate,
    InMemoryActorStore,
    Sha256ActorSigner,
)
from core.campaign import CampaignChains, CampaignDetector
from core.models import (
    ActorKillChainStep,
    ActorProfile,
    Alert,
    Severity,
    SOCState,
    Verdict,
)
from core.settings import Settings
from core.severity import SeverityEngine


async def _actor_read(store: InMemoryActorStore, scenarios: list[str]) -> ActorReadGate:
    signer = Sha256ActorSigner()
    p = ActorProfile(
        actor_id="APT-CAMP",
        is_explicit=True,
        kill_chain=[
            ActorKillChainStep(
                ts="t", alert_id=f"a{i}", scenario_id=s, technique=f"T{i}"
            )
            for i, s in enumerate(scenarios)
        ],
    )
    p.content_hash = p.fingerprint()
    p.signature = signer.sign(p.content_hash)
    await store.awrite(p)
    return ActorReadGate(store)


def _detector() -> CampaignDetector:
    return CampaignDetector(CampaignChains.from_yaml())


def _state(scenario_id: str) -> SOCState:
    return {
        "alert": Alert(
            id="a-now",
            scenario_id=scenario_id,
            title="t",
            severity_baseline=Severity.HIGH,
            signals=["sig"],
            actor_id="APT-CAMP",
        ),
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
    }


class TestCampaignReport:
    @pytest.mark.asyncio
    async def test_campaign_progress_exposed(self) -> None:
        """actor 가 S14→S4 관측 후 현 S1 → C2 캠페인 완료 매칭 노출."""
        store = InMemoryActorStore()
        # kill_chain 에 S14, S4 이력(신번호 접두 포함 형식)
        read = await _actor_read(store, ["S14-TI-SOURCE-POISON", "S4-FW-TAMPER"])
        agent = ReportAgent(
            Settings(),
            SeverityEngine(),
            actor_read=read,
            campaign_detector=_detector(),
        )

        out = await agent.run(_state("S1-GNSS-SPOOF"))

        matches = out["report"].campaign_matches
        c2 = next((m for m in matches if m.chain_id == "C2"), None)
        assert c2 is not None
        assert c2.matched == 3  # S14, S4, S1 전부

    @pytest.mark.asyncio
    async def test_next_expected_when_partial(self) -> None:
        """부분 진행(S6→S13) → C1 다음 예상 S15."""
        store = InMemoryActorStore()
        read = await _actor_read(store, ["S6-GCS-COMPROMISE"])
        agent = ReportAgent(
            Settings(),
            SeverityEngine(),
            actor_read=read,
            campaign_detector=_detector(),
        )

        out = await agent.run(_state("S13-CT-LEVEL-TAMPER"))

        c1 = next(
            (m for m in out["report"].campaign_matches if m.chain_id == "C1"), None
        )
        assert c1 is not None
        assert c1.matched == 2
        assert c1.next_expected == "S15"

    @pytest.mark.asyncio
    async def test_no_detector_empty(self) -> None:
        """detector 미주입 시 빈 리스트."""
        store = InMemoryActorStore()
        read = await _actor_read(store, ["S6-GCS-COMPROMISE"])
        agent = ReportAgent(Settings(), SeverityEngine(), actor_read=read)

        out = await agent.run(_state("S13-CT-LEVEL-TAMPER"))

        assert out["report"].campaign_matches == []
