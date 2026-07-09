"""ResponseAgent CACAO 배선 — 카탈로그 선택 + mission-gate 결정론 평가(권고전용).

카탈로그 로직은 test_cacao.py 커버. 여기선 response 배선: tactic 선택·분기·폴백.
Spec: docs/superpowers/specs/2026-07-09-response-cacao-wiring-design.md
"""

import pytest

from agents.response_agent import ResponseAgent
from core.cacao import evaluate_condition, load_playbooks
from core.exceptions import PlaybookError
from core.models import Alert, MissionRisk, Severity, SOCState, Verdict
from core.settings import Settings
from core.severity import SeverityEngine

_CATALOG = load_playbooks()
_MAP = {"S-IMP": "Impact", "S-DISC": "Discovery"}  # Discovery = 미커버 전술


def _agent(*, wired: bool = True) -> ResponseAgent:
    return ResponseAgent(
        Settings(),
        SeverityEngine(),
        playbooks=_CATALOG if wired else None,
        scenario_tactic=_MAP if wired else None,
    )


def _state(scenario: str, mr: MissionRisk | None) -> SOCState:
    alert = Alert(
        id="A",
        scenario_id=scenario,
        title="t",
        severity_baseline=Severity.HIGH,
        defense_playbook={"id": "PB-FALLBACK", "actions": ["기존 조치"]},
    )
    state: SOCState = {
        "alert": alert,
        "severity": Severity.HIGH,
        "verdict": Verdict.TRUE_POSITIVE,
    }
    if mr is not None:
        state["mission_risk"] = mr
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
    async def test_uncovered_tactic_falls_back(self) -> None:
        """미커버 전술(Discovery) → CACAO 없음, defense_playbook 폴백."""
        out = await _agent().run(_state("S-DISC", MissionRisk(score=8)))
        r = out["response"]
        assert r.cacao_playbook_id is None
        assert r.playbook_id == "PB-FALLBACK"

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
