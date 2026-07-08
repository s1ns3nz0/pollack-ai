"""MITRE Engage 적 교전 폐루프 — 상태 전진·adversary_cost·플래너·COA enrich.

Codex 하드닝 회귀 가드 포함:
- 신뢰 canary→TP + explicit actor 만 전진(untrusted decoy_hit / auto-fp 전진 금지).
- alert_id 멱등(replay 이중계상 금지).
- engagement 서명 포함(변조 → read gate 거부), 단 기본값은 레거시 해시 호환.
"""

from typing import cast

import pytest

from core.actors import (
    ActorReadGate,
    ActorWriteGate,
    InMemoryActorStore,
    Sha256ActorSigner,
)
from core.coa import CoaMatrix, CoaPlanner
from core.engage import EngageAdvancer, EngageMatrix, EngagePlanner
from core.models import (
    ActorEngagement,
    ActorProfile,
    Alert,
    EngageGoal,
    EnvVerdict,
    Severity,
)
from core.outcome import Observation, ProbeEngine
from tools.coverage import CoverageMatrix


def _alert(
    *, aid: str = "a1", actor_id: str | None = "APT-X", tactic: str = "Reconnaissance"
) -> Alert:
    return Alert(
        id=aid,
        scenario_id="S2",
        title="t",
        severity_baseline=Severity.MEDIUM,
        signals=["sig"],
        mitre={"tactics": [tactic], "techniques": ["T1071"]},
        actor_id=actor_id,
    )


class TestEngageAdvancer:
    """상태 전진 + adversary_cost(멱등)."""

    def test_advance_expose_elicit_understand(self) -> None:
        """round 1/2/4 → EXPOSE/ELICIT/UNDERSTAND 단조 전진."""
        adv = EngageAdvancer()
        p = ActorProfile(actor_id="APT-X")
        adv.advance(p, _alert(aid="a1"))
        assert p.engagement.state == EngageGoal.EXPOSE
        adv.advance(p, _alert(aid="a2"))
        # cast: advance 변이하나 mypy 가 이전 리터럴 narrowing 유지(오탐)
        assert cast(EngageGoal, p.engagement.state) == EngageGoal.ELICIT
        adv.advance(p, _alert(aid="a3"))
        # round 3 아직 ELICIT
        assert cast(EngageGoal, p.engagement.state) == EngageGoal.ELICIT
        adv.advance(p, _alert(aid="a4"))
        assert cast(EngageGoal, p.engagement.state) == EngageGoal.UNDERSTAND

    def test_adversary_cost_accrues_stage_order(self) -> None:
        """후반단계(C2 order=11) 교전이 정찰(order=1)보다 큰 cost 를 누적."""
        adv = EngageAdvancer()
        p = ActorProfile(actor_id="APT-X")
        adv.advance(p, _alert(aid="a1", tactic="Reconnaissance"))
        assert p.engagement.adversary_cost == 1
        adv.advance(p, _alert(aid="a2", tactic="CommandAndControl"))
        assert p.engagement.adversary_cost == 12  # 1 + 11

    def test_replay_idempotent(self) -> None:
        """동일 alert_id 재관측 → 전진 skip(rounds/cost 불변)."""
        adv = EngageAdvancer()
        p = ActorProfile(actor_id="APT-X")
        assert adv.advance(p, _alert(aid="dup")) is True
        assert adv.advance(p, _alert(aid="dup")) is False
        assert p.engagement.rounds == 1
        assert p.engagement.state == EngageGoal.EXPOSE

    def test_empty_alert_id_no_advance(self) -> None:
        """빈 alert_id 는 dedup 불가 → 전진 금지(Codex M-b 회귀 가드)."""
        adv = EngageAdvancer()
        p = ActorProfile(actor_id="APT-X")
        assert adv.advance(p, _alert(aid="")) is False
        assert p.engagement.rounds == 0
        assert p.engagement.state == EngageGoal.NONE


class TestProbeEngagement:
    """ProbeEngine.decide 가 engagement 을 canary 와 독립 산출(Codex M-a)."""

    def _obs(self, **kw: object) -> Observation:
        base: dict[str, object] = {"alert_id": "a1", "scenario_id": "S2", "ts": "t"}
        base.update(kw)
        return Observation.model_validate(base)

    def test_canary_only_engages(self) -> None:
        """canary 단독 → CONFIRMED_TP + engagement=True."""
        d = ProbeEngine().decide(self._obs(canary_hit=True))
        assert d.env_verdict == EnvVerdict.CONFIRMED_TP and d.engagement is True

    def test_canary_with_mission_effect_still_engages(self) -> None:
        """canary + mission_effect 동시 → engagement 유지(루프 정지 방지)."""
        d = ProbeEngine().decide(
            self._obs(mission_effect_observed=True, reoccurred=True, canary_hit=True)
        )
        assert d.env_verdict == EnvVerdict.CONFIRMED_TP
        assert d.effect == 0.0  # mission_effect 효과등급 유지
        assert d.engagement is True  # canary 도 반영(M-a 회귀 가드)

    def test_mission_effect_without_canary_no_engage(self) -> None:
        """mission_effect 만(canary 없음) → engagement=False."""
        d = ProbeEngine().decide(self._obs(mission_effect_observed=True))
        assert d.engagement is False


class TestEngageThroughGate:
    """ActorWriteGate 경유 — 신뢰경로/explicit 한정 전진(포이즈닝 면역)."""

    async def _write(
        self, gate: ActorWriteGate, alert: Alert, engagement: bool
    ) -> None:
        await gate.submit(alert, EnvVerdict.CONFIRMED_TP, engagement=engagement)

    @pytest.mark.asyncio
    async def test_canary_explicit_advances(self) -> None:
        """engagement=True + explicit actor → 전진."""
        store = InMemoryActorStore()
        gate = ActorWriteGate(store, engage_advancer=EngageAdvancer())
        await self._write(gate, _alert(actor_id="APT-X"), engagement=True)
        p = await store.aload("APT-X")
        assert p is not None and p.engagement.state == EngageGoal.EXPOSE

    @pytest.mark.asyncio
    async def test_untrusted_decoy_no_advance(self) -> None:
        """engagement=False(decoy_hit only) → 상태 NONE 유지(포이즈닝 회귀 가드)."""
        store = InMemoryActorStore()
        gate = ActorWriteGate(store, engage_advancer=EngageAdvancer())
        await self._write(gate, _alert(actor_id="APT-X"), engagement=False)
        p = await store.aload("APT-X")
        assert p is not None and p.engagement.state == EngageGoal.NONE

    @pytest.mark.asyncio
    async def test_auto_fingerprint_no_advance(self) -> None:
        """engagement=True 라도 auto-fingerprint actor 면 전진 안 함(Codex High-2)."""
        store = InMemoryActorStore()
        gate = ActorWriteGate(store, engage_advancer=EngageAdvancer())
        # actor_id 없음 → fingerprint 기반(is_explicit=False)
        await self._write(gate, _alert(actor_id=None), engagement=True)
        # 적립은 되나 engagement 은 NONE 유지
        loaded = [await store.aload(k) for k in store._by_id]
        assert loaded and all(
            p is not None and p.engagement.state == EngageGoal.NONE for p in loaded
        )


class TestEngagementSignature:
    """서명 변조 방어 + 레거시 해시 호환."""

    def test_default_engagement_omitted_from_hash(self) -> None:
        """기본(미교전) engagement 은 fingerprint payload 에서 생략 → 레거시 호환."""
        p_default = ActorProfile(actor_id="APT-X")
        p_explicit = ActorProfile(actor_id="APT-X", engagement=ActorEngagement())
        assert p_default.fingerprint() == p_explicit.fingerprint()

    def test_engaged_state_changes_hash(self) -> None:
        """교전 상태 진입 시 해시 변화(서명 대상 — 변조탐지)."""
        base = ActorProfile(actor_id="APT-X").fingerprint()
        engaged = ActorProfile(
            actor_id="APT-X",
            engagement=ActorEngagement(state=EngageGoal.EXPOSE, rounds=1),
        ).fingerprint()
        assert base != engaged

    @pytest.mark.asyncio
    async def test_tampered_engagement_rejected(self) -> None:
        """저장 후 engagement 변조 → read gate 서명검증 거부."""
        store = InMemoryActorStore()
        signer = Sha256ActorSigner()
        gate = ActorWriteGate(store, signer, engage_advancer=EngageAdvancer())
        await gate.submit(
            _alert(actor_id="APT-X"), EnvVerdict.CONFIRMED_TP, engagement=True
        )
        tampered = await store.aload("APT-X")
        assert tampered is not None
        tampered.engagement.adversary_cost += 999  # 변조
        await store.awrite(tampered)
        assert await ActorReadGate(store, signer).recall("APT-X") is None


class TestEnginePlannerAndCoa:
    """EngagePlanner 조회 + COA Deceive enrich."""

    def test_planner_recommends_by_goal_stage(self) -> None:
        """목표×tactic → 활동 조회, NONE/미정의 → None."""
        planner = EngagePlanner()
        p = ActorProfile(
            actor_id="APT-X",
            engagement=ActorEngagement(state=EngageGoal.EXPOSE),
        )
        rec = planner.recommend(p, ["Reconnaissance"])
        assert rec is not None and rec.activity == "Lures"
        none_p = ActorProfile(actor_id="Y")
        assert planner.recommend(none_p, ["Reconnaissance"]) is None

    def test_matrix_star_fallback(self) -> None:
        """미정의 tactic → '*' 폴백."""
        m = EngageMatrix.from_yaml()
        rec = m.recommend(EngageGoal.EXPOSE, ["NonexistentTactic"])
        assert rec is not None and rec.activity == "Decoy System"

    def test_coa_deceive_enriched(self) -> None:
        """actor engagement 있을 때 current Deceive 셀에 Engage 주석 주입."""
        planner = CoaPlanner(
            CoverageMatrix.from_yaml(),
            CoaMatrix.from_yaml(),
            engage=EngageMatrix.from_yaml(),
        )
        eng = ActorEngagement(state=EngageGoal.EXPOSE, rounds=1, adversary_cost=3)
        opts = planner.plan(["Reconnaissance"], [], engagement=eng)
        deceive = [o for o in opts if o.defense == "Deceive" and o.stage == "current"]
        assert deceive and "Engage[expose]" in deceive[0].engage
        assert "adv_cost=3" in deceive[0].engage

    def test_coa_no_engagement_no_annotation(self) -> None:
        """engagement 미주입 → Deceive 셀 engage 빈값(회귀 가드)."""
        planner = CoaPlanner(
            CoverageMatrix.from_yaml(),
            CoaMatrix.from_yaml(),
            engage=EngageMatrix.from_yaml(),
        )
        opts = planner.plan(["Reconnaissance"], [], engagement=None)
        deceive = [o for o in opts if o.defense == "Deceive"]
        assert all(o.engage == "" for o in deceive)
