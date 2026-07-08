"""spec D1 + C1 + A1 — RAGAS evaluator / SequencePredictor / CausalReasoner 통합."""

from __future__ import annotations

from pathlib import Path

import pytest

from agents.investigation_agent import InvestigationAgent
from agents.report_agent import ReportAgent
from app.metrics import _METRICS
from core.causal import CausalReasoner
from core.models import (
    ActorKillChainStep,
    ActorProfile,
    Alert,
    CausalChain,
    InvestigationResult,
    RagasResult,
    RetrievedChunk,
    Severity,
    SOCState,
    Verdict,
)
from core.predictor import SequencePredictor
from core.settings import Settings
from core.severity import SeverityEngine
from tools.ragas_evaluator import RagasEvaluator


def _alert(**kwargs: object) -> Alert:
    base: dict[str, object] = {
        "id": "a1",
        "scenario_id": "S1-GNSS-001",
        "title": "X",
        "severity_baseline": Severity.MEDIUM,
        "signals": ["GPS_GLITCH_FLAG", "EKF_HIGH_VARIANCE"],
        "expected_detection": {"sigma_rule": "r1"},
        "asset_id": "GNSS",
    }
    base.update(kwargs)
    return Alert.model_validate(base)


class TestRagasEvaluatorGraceful:
    @pytest.mark.asyncio
    async def test_missing_dep_returns_none(self) -> None:
        eva = RagasEvaluator(Settings())
        # ragas/datasets 일반적으로 미설치 — None 기대
        result = await eva.aevaluate(
            _alert(), "summary", [RetrievedChunk(text="t", source="kb/x", score=0.9)]
        )
        # 설치된 환경에선 RagasResult 일 수 있음 — None 또는 모델 둘 다 허용
        assert result is None or isinstance(result, RagasResult)

    @pytest.mark.asyncio
    async def test_empty_inputs_none(self) -> None:
        eva = RagasEvaluator(Settings())
        assert await eva.aevaluate(_alert(), "", []) is None


class _FakeRagas:
    async def aevaluate(self, alert, summary, contexts):  # type: ignore[no-untyped-def]
        return RagasResult(
            faithfulness=0.4,
            answer_relevancy=0.9,
            context_relevancy=0.85,
            evaluated_at="2026-06-30T00:00:00Z",
            n_contexts=len(contexts),
        )


class TestRagasMetricsUpdate:
    @pytest.mark.asyncio
    async def test_observe_ragas_updates_metric(self) -> None:
        # 깨끗한 카운터로
        _METRICS.ragas_evaluations_total = 0
        _METRICS._ragas_faith_sum = 0.0
        _METRICS._ragas_ans_rel_sum = 0.0
        _METRICS._ragas_ctx_rel_sum = 0.0
        agent = InvestigationAgent(Settings(), retriever=None, ragas=_FakeRagas())
        # 인위적으로 summary + trusted 가 있도록 retriever stub
        await agent._evaluate_ragas(
            _alert(),
            "분석 요약",
            [RetrievedChunk(text="t", source="kb/x", score=0.9)],
        )
        avg = _METRICS.ragas_avgs()
        assert avg["faithfulness"] == pytest.approx(0.4)
        assert avg["context_relevancy"] == pytest.approx(0.85)


def _chain(seq: list[str]) -> list[ActorKillChainStep]:
    return [
        ActorKillChainStep(
            ts="2026-06-30T00:00:00Z",
            alert_id=f"a{i}",
            scenario_id="s",
            technique=t,
        )
        for i, t in enumerate(seq)
    ]


class TestSequencePredictor:
    def test_known_sequence_predicts_next(self) -> None:
        # chain 끝 = "A", current="B" 호출 → ngram (A,B)→C count=3 prob=1.0
        prof = ActorProfile(
            actor_id="x",
            is_explicit=True,
            kill_chain=_chain(["A", "B", "C", "A", "B", "C", "A", "B", "C", "A"]),
        )
        pred = SequencePredictor(min_support=3, min_probability=0.5, top_k=3)
        out = pred.predict(prof, "B")
        assert len(out) == 1
        assert out[0].next_technique == "C"
        assert out[0].probability == 1.0
        assert out[0].support_count >= 3

    def test_low_support_filtered(self) -> None:
        prof = ActorProfile(
            actor_id="x",
            is_explicit=True,
            kill_chain=_chain(["A", "B", "C"]),
        )
        pred = SequencePredictor(min_support=3, min_probability=0.5)
        assert pred.predict(prof, "B") == []

    def test_no_chain_or_current(self) -> None:
        prof = ActorProfile(actor_id="x", is_explicit=True)
        pred = SequencePredictor()
        assert pred.predict(prof, "B") == []
        assert pred.predict(prof, "") == []


class TestCausalReasoner:
    @pytest.mark.asyncio
    async def test_s1_chain_matches(self) -> None:
        rules_path = Path(Settings().causal_rules_path)
        assert rules_path.exists()
        r = CausalReasoner(rules_path)
        chain = await r.build_chain(_alert())
        assert len(chain.steps) == 3
        assert chain.basis_rules == ["S1-GNSS-SPOOF"]
        techs = [s.mitre_technique for s in chain.steps]
        assert "T0830" in techs

    @pytest.mark.asyncio
    async def test_no_match_empty(self) -> None:
        r = CausalReasoner(Path(Settings().causal_rules_path))
        chain = await r.build_chain(_alert(signals=["unknown"]))
        assert chain.steps == []

    @pytest.mark.asyncio
    async def test_missing_yaml_empty(self) -> None:
        r = CausalReasoner(Path("/tmp/__nonexistent__.yaml"))
        chain = await r.build_chain(_alert())
        assert chain.steps == []


class TestReportAgentIntegration:
    @pytest.mark.asyncio
    async def test_hunt_candidates_from_predictions(self) -> None:
        engine = SeverityEngine()
        from core.models import AttackPrediction

        agent = ReportAgent(Settings(), engine)
        state: SOCState = {
            "alert": _alert(),
            "severity": Severity.MEDIUM,
            "verdict": Verdict.TRUE_POSITIVE,
            "investigation": InvestigationResult(
                predictions=[
                    AttackPrediction(
                        next_technique="T9999",
                        probability=0.8,
                        support_count=3,
                        basis_actor_id="x",
                    )
                ]
            ),
        }
        out = await agent.run(state)
        assert out["report"].hunt_candidates == ["T9999"]

    @pytest.mark.asyncio
    async def test_causal_summary_embedded(self) -> None:
        engine = SeverityEngine()
        r = CausalReasoner(Path(Settings().causal_rules_path))
        agent = ReportAgent(Settings(), engine, reasoner=r)
        state: SOCState = {
            "alert": _alert(),
            "severity": Severity.HIGH,
            "verdict": Verdict.TRUE_POSITIVE,
        }
        out = await agent.run(state)
        assert isinstance(out["report"].causal_summary, CausalChain)
        assert out["oscal_evidence"].causal_chain is not None
