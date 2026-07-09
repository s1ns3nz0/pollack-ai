"""METT-TC 가중 트리아지 — priority 상승(delta·cap) + HITL 강제(approval) + 맥락.

결정론 검증. severity 레벨은 METT 로 불변(정책 엔진 권한). 위조 wire 필드는 상승-전용
+ cap 으로 blast 반경 제한. Spec: 2026-07-09-mett-tc-weighted-triage-design.md
"""

from typing import Any, cast

from langgraph.types import Command
import pytest

from agents.approval_agent import ApprovalAgent
from agents.graph import build_soc_graph
from agents.report_agent import ReportAgent
from agents.response_agent import ResponseAgent
from agents.triage_agent import TriageAgent
from core.models import Alert, MissionRisk, Severity, SOCState, Verdict
from core.settings import Settings
from core.severity import SeverityEngine, _load_mett_tc
from core.terrain import KeyTerrainMap, MissionRiskAssessor


def _settings() -> Settings:
    return Settings()


def _assessor() -> MissionRiskAssessor:
    return MissionRiskAssessor(KeyTerrainMap.from_yaml())


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "id": "ALERT-METT",
        "scenario_id": "UAV-GPS-SPOOF-001",
        "title": "테스트",
        "asset_id": "C2_LINK",
        "asset_tier": "T2-Important",
        "mission_phase": "pre-flight",
        "posture": "normal",
        "severity_baseline": Severity.LOW,
        "signals": ["GNSS-INS 잔차 급증"],
        "defense_playbook": {"id": "PB-NAV-RTB-01", "actions": ["INS 페일오버"]},
        "ground_truth": Verdict.TRUE_POSITIVE,
    }
    base.update(overrides)
    return Alert.model_validate(base)


class TestMettTcConfigParse:
    """정책 파서 — escalate-only 불변식 코드 강제(Codex diff M)."""

    def test_negative_cap_clamped_to_zero(self) -> None:
        """오설정 음수 cap → 0 클램프(de-escalation 벡터 차단)."""
        cfg = _load_mett_tc({"priority_delta_cap": -3, "priority_delta_min": -1})
        assert cfg.priority_delta_cap == 0
        assert cfg.priority_delta_min == 0

    def test_missing_section_defaults(self) -> None:
        """섹션 결측 → 안전 기본값."""
        cfg = _load_mett_tc(None)
        assert cfg.priority_delta_cap == 1
        assert cfg.priority_delta_min == 2
        assert cfg.hitl_force_threshold == 6
        assert cfg.priority_delta_factors == ("terrain_dependents", "civil_geo")


class TestTriageMettPriority:
    """METT-TC delta 로 트리아지 priority 상승-전용 가중."""

    @pytest.mark.asyncio
    async def test_delta_escalates_priority(self) -> None:
        """의존자산+민간지리 delta≥min → priority 1밴드 상승(3→2)."""
        agent = TriageAgent(_settings(), SeverityEngine(), mission_risk=_assessor())
        # C2_LINK 의존자산 다수(terrain_dependents=3) + lat(civil_geo=1) → delta 4.
        out = await agent.run({"alert": _alert(lat=36.7)})
        assert out["priority"] == 2  # baseline l→priority 3, METT -1
        assert "mission_risk" in out

    @pytest.mark.asyncio
    async def test_cap_limits_to_one_band(self) -> None:
        """큰 delta 여도 priority 최대 1밴드만 상승(4→3, not →1)."""
        agent = TriageAgent(_settings(), SeverityEngine(), mission_risk=_assessor())
        out = await agent.run(
            {"alert": _alert(severity_baseline=Severity.INFO, lat=36.7)}
        )
        assert out["priority"] == 3  # i→priority 4, cap +1 → 3 (not lower)

    @pytest.mark.asyncio
    async def test_below_min_no_escalation(self) -> None:
        """delta<min(의존1·민간0) → priority 불변, 상승 근거 없음."""
        agent = TriageAgent(_settings(), SeverityEngine(), mission_risk=_assessor())
        # GNSS 의존자산 1(AUTOPILOT)만, lat 없음 → delta=1 < 2.
        out = await agent.run({"alert": _alert(asset_id="GNSS")})
        assert out["priority"] == 3  # 불변
        assert not any("METT-TC" in r for r in out["severity_rationale"])
        assert "mission_risk" in out  # 산출물은 여전히 부착

    @pytest.mark.asyncio
    async def test_severity_level_untouched(self) -> None:
        """METT 는 severity 레벨을 바꾸지 않음(정책 엔진 권한 — auto 오발동 방지)."""
        engine = SeverityEngine()
        agent = TriageAgent(_settings(), engine, mission_risk=_assessor())
        alert = _alert(lat=36.7)
        expected, _ = engine.compute(alert)
        out = await agent.run({"alert": alert})
        assert out["severity"] == expected == Severity.LOW

    @pytest.mark.asyncio
    async def test_no_assessor_no_mission_risk_key(self) -> None:
        """assessor 미주입 → mission_risk 미부착(하위호환)."""
        agent = TriageAgent(_settings(), SeverityEngine())
        out = await agent.run({"alert": _alert(lat=36.7)})
        assert "mission_risk" not in out
        assert out["priority"] == 3  # METT 미적용


class TestApprovalMettGate:
    """approval 노드가 임무위험으로 HITL 게이트 강제(상향만)."""

    @pytest.mark.asyncio
    async def test_low_mission_below_high_auto_approves(self) -> None:
        """severity<h + 임무위험<임계 → 자동승인(무인터럽트)."""
        agent = ApprovalAgent(_settings(), hitl_force_threshold=6)
        state: SOCState = {
            "alert": _alert(),
            "severity": Severity.MEDIUM,
            "mission_risk": MissionRisk(score=3),
        }
        out = await agent.run(state)
        assert out["approval"].required is False
        assert out["approval"].approved is True

    @pytest.mark.asyncio
    async def test_no_mission_risk_below_high_auto_approves(self) -> None:
        """mission_risk 부재 + severity<h → 자동승인."""
        agent = ApprovalAgent(_settings(), hitl_force_threshold=6)
        out = await agent.run({"alert": _alert(), "severity": Severity.LOW})
        assert out["approval"].required is False


class TestMettHitlEnforceable:
    """핵심: severity<h 라도 임무위험 高면 실제 interrupt(Codex High 반영)."""

    @pytest.mark.asyncio
    async def test_high_mission_forces_hitl_under_medium_severity(self) -> None:
        """SATCOM on-station: severity=m 이지만 mission_risk≥임계 → 인터럽트 강제."""
        graph = build_soc_graph(retriever=None, hitl=True)
        config: Any = {"configurable": {"thread_id": "t-mett-force"}}
        # severity: l + key_terrain(+1)=m. mission_risk: terrain_key2+dependents1+
        # troops3+civil1=7 ≥ 6. dwelling 미설정 → severity h 로 안 올라감.
        alert = _alert(
            asset_id="SATCOM",
            asset_tier="T2-Important",
            mission_phase="on-station",
            lat=36.7,
        )
        paused = await graph.ainvoke({"alert": alert}, config=config)
        assert "__interrupt__" in paused  # 임무위험으로 인간 게이트 강제
        final = cast(
            SOCState,
            await graph.ainvoke(Command(resume={"approved": True}), config=config),
        )
        assert final["approval"].required is True
        assert final["severity"] != Severity.HIGH  # METT 는 HITL 만, severity 아님
        assert final["report"].mission_risk is not None
        assert final["report"].mission_risk.score >= 6


class TestResponseMettContext:
    """response 가 mission_risk 맥락 부착(강제 게이트는 approval 이 처리)."""

    @pytest.mark.asyncio
    async def test_high_mission_attaches_note(self) -> None:
        """임무위험≥임계 → mission_risk_score + note 부착."""
        agent = ResponseAgent(_settings(), SeverityEngine())
        state: SOCState = {
            "alert": _alert(),
            "severity": Severity.MEDIUM,
            "mission_risk": MissionRisk(score=8),
        }
        out = await agent.run(state)
        r = out["response"]
        assert r.mission_risk_score == 8
        assert r.mission_risk_note and "임무위험" in r.mission_risk_note

    @pytest.mark.asyncio
    async def test_low_mission_score_only_no_note(self) -> None:
        """임무위험<임계 → score 만, note 없음."""
        agent = ResponseAgent(_settings(), SeverityEngine())
        state: SOCState = {
            "alert": _alert(),
            "severity": Severity.MEDIUM,
            "mission_risk": MissionRisk(score=3),
        }
        out = await agent.run(state)
        r = out["response"]
        assert r.mission_risk_score == 3
        assert r.mission_risk_note is None

    @pytest.mark.asyncio
    async def test_mett_does_not_lower_hitl(self) -> None:
        """response 는 level_meta hitl 만 반영 — mission_risk 로 낮추지 않음."""
        engine = SeverityEngine()
        agent = ResponseAgent(_settings(), engine)
        state: SOCState = {
            "alert": _alert(),
            "severity": Severity.HIGH,
            "mission_risk": MissionRisk(score=1),
        }
        out = await agent.run(state)
        assert out["response"].hitl == engine.level_meta(Severity.HIGH).get("hitl")


class TestReportReuse:
    """report 는 triage 산출 mission_risk 재사용(재계산 발산 방지 — Codex 반영)."""

    @pytest.mark.asyncio
    async def test_reuses_state_mission_risk(self) -> None:
        """state 에 mission_risk 있으면 report 가 그대로 사용(재계산 안 함)."""
        # assessor 있어도 alert 산정과 다른 sentinel 이 그대로면 재사용 증명.
        agent = ReportAgent(_settings(), SeverityEngine(), mission_risk=_assessor())
        sentinel = MissionRisk(asset_id="SENTINEL", score=99)
        state: SOCState = {
            "alert": _alert(),
            "severity": Severity.LOW,
            "verdict": Verdict.TRUE_POSITIVE,
            "mission_risk": sentinel,
        }
        out = await agent.run(state)
        assert out["report"].mission_risk is not None
        assert out["report"].mission_risk.score == 99  # 재계산이면 99 안 나옴
        assert out["report"].mission_risk.asset_id == "SENTINEL"
