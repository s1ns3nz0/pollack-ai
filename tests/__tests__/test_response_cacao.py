"""ResponseAgent CACAO 배선 — 카탈로그 선택 + mission-gate 결정론 평가(권고전용).

카탈로그 로직은 test_cacao.py 커버. 여기선 response 배선: tactic 선택·분기·폴백.
Spec: docs/superpowers/specs/2026-07-09-response-cacao-wiring-design.md
"""

import pytest

from agents.graph import build_soc_graph
from agents.response_agent import ResponseAgent
from core.actors import ActorReadGate, ActorWriteGate, InMemoryActorStore
from core.cacao import evaluate_condition, load_playbooks
from core.degradation import DegradationAssessor, DegradationMatrix
from core.exceptions import PlaybookError
from core.models import (
    Alert,
    EnvVerdict,
    MissionRisk,
    Provenance,
    Severity,
    SOCState,
    Verdict,
)
from core.playbook_outcome import ActorPlaybookOutcomeGate, PlaybookOutcome
from core.settings import Settings
from core.severity import SeverityEngine

_CATALOG = load_playbooks()
_MAP = {"S-IMP": "Impact", "S-DISC": "Discovery"}


def _degradation() -> DegradationAssessor:
    return DegradationAssessor(DegradationMatrix.from_yaml())


def _agent(*, wired: bool = True, resilience: bool = False) -> ResponseAgent:
    return ResponseAgent(
        Settings(),
        SeverityEngine(),
        playbooks=_CATALOG if wired else None,
        scenario_tactic=_MAP if wired else None,
        degradation=_degradation() if resilience else None,
    )


def _state(scenario: str, mr: MissionRisk | None) -> SOCState:
    alert = Alert(
        id="A",
        scenario_id=scenario,
        title="t",
        severity_baseline=Severity.HIGH,
        defense_playbook={"id": "PB-FALLBACK", "actions": ["기존 조치"]},
        actor_id="team-red",
    )
    state: SOCState = {
        "alert": alert,
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
    }
    if mr is not None:
        state["mission_risk"] = mr
    return state


def _asset_state(scenario: str, mr: MissionRisk | None, asset_id: str) -> SOCState:
    state = _state(scenario, mr)
    state["alert"].asset_id = asset_id
    return state


class TestCatalogSelection:
    @pytest.mark.asyncio
    async def test_high_mission_conservative_branch(self) -> None:
        """Impact 전술 + 高 임무위험 → CACAO 선택 + 보수(HITL) 분기."""
        out = await _agent().run(_state("S-IMP", MissionRisk(score=8)))
        r = out["response"]
        assert r.cacao_playbook_id is not None
        assert r.mission_branch == "conservative"
        assert r.cacao_steps

    @pytest.mark.asyncio
    async def test_low_mission_auto_branch(self) -> None:
        """低 임무위험(civil 없음) → auto 분기."""
        out = await _agent().run(_state("S-IMP", MissionRisk(score=2, factors={})))
        assert out["response"].mission_branch == "auto"

    @pytest.mark.asyncio
    async def test_none_mission_defaults_conservative(self) -> None:
        """mission_risk 부재 → 보수 분기 fail-safe + 인간검토 권고."""
        out = await _agent().run(_state("S-IMP", None))
        r = out["response"]
        assert r.mission_branch == "conservative"
        assert r.mission_risk_note and "인간검토" in r.mission_risk_note

    @pytest.mark.asyncio
    async def test_discovery_tactic_selects_cacao_playbook(self) -> None:
        """UAV ATT&CK Discovery 전술 → CACAO 카탈로그에서 직접 선택."""
        out = await _agent().run(_state("S-DISC", MissionRisk(score=8)))
        r = out["response"]
        assert r.cacao_playbook_id == "playbook--uav-disc-0001"
        assert r.cacao_steps
        assert r.mission_branch == "auto"

    @pytest.mark.asyncio
    async def test_no_catalog_falls_back(self) -> None:
        """카탈로그 미주입 → 현행 defense_playbook 경로(회귀 안전)."""
        out = await _agent(wired=False).run(_state("S-IMP", MissionRisk(score=8)))
        r = out["response"]
        assert r.cacao_playbook_id is None
        assert r.playbook_id == "PB-FALLBACK"

    @pytest.mark.asyncio
    async def test_steps_walk_phases(self) -> None:
        """resolve 가 contain→recover→adapt phase step 수집."""
        out = await _agent().run(_state("S-IMP", MissionRisk(score=8)))
        phases = {s.get("phase") for s in (out["response"].cacao_steps or [])}
        assert {"contain", "recover", "adapt"} <= phases

    @pytest.mark.asyncio
    async def test_auto_response_still_severity_gated(self) -> None:
        """auto 분기여도 auto_response 는 severity 등급메타 기반(권고전용 불변)."""
        engine = SeverityEngine()
        out = await _agent().run(_state("S-IMP", MissionRisk(score=2, factors={})))
        r = out["response"]
        assert r.mission_branch == "auto"
        assert r.auto_response == engine.level_meta(Severity.HIGH).get("auto_response")

    @pytest.mark.asyncio
    async def test_actor_pb_effect_is_reflected_in_response_note(self) -> None:
        """선택 CACAO PB 의 과거 효과를 response 표면에 부착한다."""
        store = InMemoryActorStore()
        alert = _state("S-IMP", MissionRisk(score=2, factors={}))["alert"]
        await ActorWriteGate(store).submit(
            alert, EnvVerdict.CONFIRMED_TP, Provenance.ENV_VERIFIED
        )
        await ActorPlaybookOutcomeGate(store).submit(
            PlaybookOutcome(
                actor_id="team-red",
                playbook_id="playbook--uav-impact-0001",
                effect=0.8,
                ts="2026-07-09T00:00:00Z",
            )
        )
        agent = ResponseAgent(
            Settings(),
            SeverityEngine(),
            playbooks=_CATALOG,
            scenario_tactic=_MAP,
            actor_read=ActorReadGate(store),
        )

        out = await agent.run(_state("S-IMP", MissionRisk(score=2, factors={})))

        note = out["response"].mission_risk_note or ""
        assert "PB 효과" in note
        assert "playbook--uav-impact-0001=0.80(1)" in note

    @pytest.mark.asyncio
    async def test_actor_pb_effect_strips_actor_id_before_recall(self) -> None:
        """alert actor_id 공백은 actors 쓰기 경로와 동일하게 정규화한다."""
        store = InMemoryActorStore()
        clean_state = _state("S-IMP", MissionRisk(score=2, factors={}))
        await ActorWriteGate(store).submit(
            clean_state["alert"], EnvVerdict.CONFIRMED_TP, Provenance.ENV_VERIFIED
        )
        await ActorPlaybookOutcomeGate(store).submit(
            PlaybookOutcome(
                actor_id="team-red",
                playbook_id="playbook--uav-impact-0001",
                effect=0.8,
                ts="2026-07-09T00:00:00Z",
            )
        )
        dirty_state = _state("S-IMP", MissionRisk(score=2, factors={}))
        dirty_state["alert"].actor_id = " team-red "
        agent = ResponseAgent(
            Settings(),
            SeverityEngine(),
            playbooks=_CATALOG,
            scenario_tactic=_MAP,
            actor_read=ActorReadGate(store),
        )

        out = await agent.run(dirty_state)

        assert "playbook--uav-impact-0001=0.80(1)" in (
            out["response"].mission_risk_note or ""
        )

    @pytest.mark.asyncio
    async def test_resilience_overlay_exposes_abort_fallback(self) -> None:
        """정탐 AUTOPILOT 손상 → response 에 ABORT resilience fallback 표면."""
        out = await _agent(resilience=True).run(
            _asset_state("S-IMP", MissionRisk(score=8), "AUTOPILOT")
        )

        r = out["response"]
        assert r.mission_continuity is not None
        assert r.mission_continuity.level == "ABORT"
        assert r.resilience_note is not None
        assert "비행제어" in r.resilience_note
        assert "안전착륙" in r.resilience_note

    @pytest.mark.asyncio
    async def test_mission_context_card_exposes_operator_posture(self) -> None:
        """response 는 임무 맥락 카드로 판단 근거와 운용 posture 를 구조화한다."""
        mission_risk = MissionRisk(
            asset_id="AUTOPILOT",
            mission_phase="terminal",
            score=8,
            is_key_terrain=True,
            dependents=["PAYLOAD"],
            factors={"terrain_key": 2, "troops_tier": 4, "enemy_advanced": 2},
            rationale=["KEY TERRAIN(terminal) — 임무 핵심자산"],
        )

        out = await _agent(resilience=True).run(
            _asset_state("S-IMP", mission_risk, "AUTOPILOT")
        )

        context = out["response"].mission_context
        assert context is not None
        assert context.asset_id == "AUTOPILOT"
        assert context.mission_phase == "terminal"
        assert context.is_key_terrain is True
        assert context.dependents == ["PAYLOAD"]
        assert context.risk_factors["terrain_key"] == 2
        assert context.continuity_level == "ABORT"
        assert context.fallback
        assert context.operator_posture == "ABORT_SAFE_LAND"
        assert "AUTOPILOT" in context.summary
        assert "terminal" in context.summary
        assert "안전착륙" in context.summary


class TestGraphWiring:
    @pytest.mark.asyncio
    async def test_graph_injects_actor_read_into_response(self) -> None:
        """build_soc_graph actor_read 주입이 response PB 효과 노출까지 이어진다."""
        store = InMemoryActorStore()
        alert = Alert(
            id="A-GRAPH",
            scenario_id="S5-RAG-POISON",
            title="RAG 포이즈닝",
            severity_baseline=Severity.HIGH,
            signals=["정책 기대등급-판정 괴리"],
            expected_detection={"sigma_rule": "s5.yml"},
            defense_playbook={"id": "PB-FALLBACK", "actions": ["기존 조치"]},
            actor_id="team-red",
        )
        await ActorWriteGate(store).submit(
            alert, EnvVerdict.CONFIRMED_TP, Provenance.ENV_VERIFIED
        )
        await ActorPlaybookOutcomeGate(store).submit(
            PlaybookOutcome(
                actor_id="team-red",
                playbook_id="playbook--uav-impact-0001",
                effect=0.7,
                ts="2026-07-09T00:00:00Z",
            )
        )
        graph = build_soc_graph(
            settings=Settings(),
            actor_read=ActorReadGate(store),
            actor_write=ActorWriteGate(store),
        )

        out = await graph.ainvoke({"alert": alert})

        note = out["response"].mission_risk_note or ""
        assert out["response"].cacao_playbook_id == "playbook--uav-impact-0001"
        assert "PB 효과 playbook--uav-impact-0001=0.70(1)" in note


class TestEvaluateCondition:
    def test_deterministic_eval(self) -> None:
        """결정론 평가 — 비교/and/or/factors 정확."""
        mr = MissionRisk(score=8, factors={"civil_geo": 1})
        assert evaluate_condition("mission_risk.score >= 6", mr) is True
        assert evaluate_condition("mission_risk.score >= 9", mr) is False
        assert evaluate_condition('mission_risk.factors["civil_geo"] >= 1', mr) is True
        low = MissionRisk(score=2, factors={})
        assert evaluate_condition("mission_risk.score >= 6", low) is False

    def test_malicious_condition_rejected(self) -> None:
        """비허용식(함수호출) → PlaybookError(eval 금지)."""
        with pytest.raises(PlaybookError):
            evaluate_condition('__import__("os").system("x")', MissionRisk(score=1))
