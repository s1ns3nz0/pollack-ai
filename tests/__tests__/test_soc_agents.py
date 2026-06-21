"""6-에이전트 SOC 파이프라인 단위/통합 테스트.

RAG·LLM 외부 의존은 mock(또는 None)으로 격리해 결정론적으로 검증한다.
"""

from typing import Any, cast

from langgraph.types import Command
import pytest

from agents.graph import build_soc_graph
from agents.investigation_agent import InvestigationAgent
from agents.triage_agent import TriageAgent
from core.models import (
    Alert,
    InvestigationResult,
    RetrievedChunk,
    Severity,
    SOCReport,
    SOCState,
    Verdict,
)
from core.settings import Settings
from core.severity import SeverityEngine


def _settings() -> Settings:
    return Settings()


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "id": "ALERT-TEST",
        "scenario_id": "UAV-GPS-SPOOF-001",
        "title": "GPS 스푸핑",
        "asset_tier": "T1-Critical",
        "mission_phase": "ingress",
        "posture": "normal",
        "severity_baseline": Severity.HIGH,
        "signals": ["GNSS-INS 잔차 급증"],
        "expected_detection": {"sigma_rule": "uav_gps_spoof_residual.yml"},
        "defense_playbook": {"id": "PB-NAV-RTB-01", "actions": ["INS 페일오버"]},
        "ground_truth": Verdict.TRUE_POSITIVE,
    }
    base.update(overrides)
    return Alert.model_validate(base)


class _StubRetriever:
    """ContextRetriever 스텁 — 고정 kb/ 청크 반환."""

    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        return [RetrievedChunk(text="유사사례", source="kb/incident.md", score=0.9)]


class TestSeverityEngine:
    """정책 엔진 산정 검증."""

    def test_high_baseline_stays_high(self) -> None:
        """h baseline + T1 + ingress → h."""
        engine = SeverityEngine()
        level, _ = engine.compute(_alert())
        assert level == Severity.HIGH

    def test_posture_lock_blocks_downgrade(self) -> None:
        """elevated + no_effect_sustained → 하향 차단(lock)."""
        engine = SeverityEngine()
        alert = _alert(
            severity_baseline=Severity.MEDIUM,
            asset_tier="T2-Important",
            mission_phase="on-station",
            posture="elevated",
            no_effect_sustained=True,
        )
        level, _ = engine.compute(alert)
        assert level == Severity.HIGH  # m + elevated(+1) = h, no_effect 무시


class TestTriageAgent:
    """Triage 가드레일 검증."""

    @pytest.mark.asyncio
    async def test_adversarial_downgrade_ignored(self) -> None:
        """주입된 낮은 제안등급('i')은 무시되고 가드레일 기록."""
        agent = TriageAgent(_settings(), SeverityEngine())
        state: SOCState = {"alert": _alert(llm_suggested_severity=Severity.INFO)}
        out = await agent.run(state)
        assert out["severity"] == Severity.HIGH
        assert out.get("guardrail_flags")


class TestInvestigationAgent:
    """Investigation 출처 가드레일 검증."""

    @pytest.mark.asyncio
    async def test_only_trusted_sources_kept(self) -> None:
        """kb/ 출처만 similar_cases 로 채택."""
        agent = InvestigationAgent(_settings(), _StubRetriever())
        out = await agent.run({"alert": _alert()})
        inv = out["investigation"]
        assert isinstance(inv, InvestigationResult)
        assert all(c.source.startswith("kb/") for c in inv.similar_cases)

    @pytest.mark.asyncio
    async def test_no_retriever_yields_empty(self) -> None:
        """리트리버 None 이면 빈 컨텍스트로 안전 동작."""
        agent = InvestigationAgent(_settings(), None)
        out = await agent.run({"alert": _alert()})
        assert out["investigation"].similar_cases == []


class TestSocGraph:
    """6-에이전트 end-to-end 그래프."""

    @pytest.mark.asyncio
    async def test_true_positive_routes_to_response(self) -> None:
        """정탐 → response 경로 + 전체 trace + 리포트."""
        graph = build_soc_graph(retriever=_StubRetriever())
        result = cast(SOCState, await graph.ainvoke({"alert": _alert()}))
        assert result["trace"] == [
            "triage",
            "investigation",
            "validation",
            "response",
            "report",
        ]
        report = result["report"]
        assert isinstance(report, SOCReport)
        assert report.action_taken == "response"
        assert report.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_false_positive_routes_to_rule_update(self) -> None:
        """오탐 → rule_update 경로."""
        graph = build_soc_graph(retriever=None)
        alert = _alert(ground_truth=Verdict.FALSE_POSITIVE)
        result = cast(SOCState, await graph.ainvoke({"alert": alert}))
        assert "rule_update" in result["trace"]
        assert result["report"].action_taken == "rule_update"

    @pytest.mark.asyncio
    async def test_s5_injection_does_not_downgrade(self) -> None:
        """S5 방어: 적대 제안등급 주입에도 정책 등급 유지 + 가드레일."""
        graph = build_soc_graph(retriever=None)
        alert = _alert(llm_suggested_severity=Severity.INFO)
        result = cast(SOCState, await graph.ainvoke({"alert": alert}))
        assert result["severity"] == Severity.HIGH
        assert result["guardrail_flags"]


class TestHitlInterrupt:
    """HITL 승인 인터럽트(hitl=True)."""

    @pytest.mark.asyncio
    async def test_high_severity_pauses_then_resumes_approved(self) -> None:
        """고위험 정탐 → 승인 대기(interrupt) → 승인 시 response 실행."""
        graph = build_soc_graph(retriever=None, hitl=True)
        config: Any = {"configurable": {"thread_id": "t-approve"}}
        paused = await graph.ainvoke({"alert": _alert()}, config=config)
        assert "__interrupt__" in paused  # 승인 대기로 멈춤
        final = cast(
            SOCState,
            await graph.ainvoke(Command(resume={"approved": True}), config=config),
        )
        assert final["approval"].approved
        assert final["report"].action_taken == "response"

    @pytest.mark.asyncio
    async def test_rejected_holds_auto_response(self) -> None:
        """승인 거부 시 자동대응 보류."""
        graph = build_soc_graph(retriever=None, hitl=True)
        config: Any = {"configurable": {"thread_id": "t-reject"}}
        await graph.ainvoke({"alert": _alert()}, config=config)
        final = cast(
            SOCState,
            await graph.ainvoke(Command(resume={"approved": False}), config=config),
        )
        assert final["approval"].approved is False
        assert "보류" in (final["response"].auto_response or "")
