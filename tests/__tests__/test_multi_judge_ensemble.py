"""spec B1 Multi-Judge Ensemble — 각 judge + ensemble + ValidationAgent 통합."""

from __future__ import annotations

import pytest

from agents.judges.base import JudgeScore
from agents.judges.ensemble import EnsembleResult, ensemble
from agents.judges.experience_judge import ExperienceJudge
from agents.judges.llm_judge import LlmJudge, _parse_judge_text
from agents.judges.signal_judge import SignalJudge
from agents.validation_agent import ValidationAgent
from core.exceptions import LLMError
from core.models import Alert as AlertModel
from core.models import (
    InvestigationResult,
    RetrievedChunk,
    Severity,
    SOCState,
    Verdict,
)
from core.settings import Settings


def _alert(**kwargs: object) -> AlertModel:
    base: dict[str, object] = {
        "id": "a1",
        "scenario_id": "S2-MOVEMENT",
        "title": "X",
        "severity_baseline": Severity.MEDIUM,
        "signals": ["sig.a"],
        "expected_detection": {"sigma_rule": "r1"},
    }
    base.update(kwargs)
    return AlertModel.model_validate(base)


def _inv(
    confidence: float = 0.0,
    exp: int = 0,
    sup: int = 0,
    cases: int = 0,
) -> InvestigationResult:
    return InvestigationResult(
        confidence=confidence,
        experience_corroboration=exp,
        suppression_corroboration=sup,
        similar_cases=[
            RetrievedChunk(text="t", source="kb/x", score=0.9) for _ in range(cases)
        ],
    )


class TestSignalJudge:
    @pytest.mark.asyncio
    async def test_no_signal_veto(self) -> None:
        state: SOCState = {"alert": _alert(signals=[])}
        s = await SignalJudge().ascore(state)
        assert s.veto and s.judge == "signal"

    @pytest.mark.asyncio
    async def test_suppression_veto(self) -> None:
        state: SOCState = {
            "alert": _alert(),
            "investigation": _inv(sup=1),
        }
        s = await SignalJudge().ascore(state)
        assert s.veto

    @pytest.mark.asyncio
    async def test_corroborated_full(self) -> None:
        state: SOCState = {
            "alert": _alert(),
            "investigation": _inv(cases=2),
        }
        s = await SignalJudge().ascore(state)
        assert s.score == 1.0 and not s.veto

    @pytest.mark.asyncio
    async def test_partial(self) -> None:
        state: SOCState = {"alert": _alert(), "investigation": _inv()}
        s = await SignalJudge().ascore(state)
        assert s.score == 0.5


class TestExperienceJudge:
    @pytest.mark.asyncio
    async def test_no_inv_neutral(self) -> None:
        s = await ExperienceJudge().ascore({"alert": _alert()})
        assert s.score == 0.5

    @pytest.mark.asyncio
    async def test_exp_only(self) -> None:
        s = await ExperienceJudge().ascore(
            {"alert": _alert(), "investigation": _inv(exp=2)}
        )
        assert s.score == 0.75

    @pytest.mark.asyncio
    async def test_sup_only(self) -> None:
        s = await ExperienceJudge().ascore(
            {"alert": _alert(), "investigation": _inv(sup=1)}
        )
        assert s.score == 0.25

    @pytest.mark.asyncio
    async def test_cancel(self) -> None:
        s = await ExperienceJudge().ascore(
            {"alert": _alert(), "investigation": _inv(exp=1, sup=1)}
        )
        assert s.score == 0.5


class TestLlmJudgeParse:
    def test_parse_valid(self) -> None:
        s = _parse_judge_text("score=0.78; reason=명확 정탐 신호")
        assert s.score == 0.78
        assert "명확" in s.rationale

    def test_parse_clip_above_one(self) -> None:
        s = _parse_judge_text("score=1.5; reason=x")
        # base.JudgeScore 가 0..1 clip
        assert s.score == 1.0

    def test_parse_no_score_neutral(self) -> None:
        s = _parse_judge_text("그냥 의견 — score 없음")
        assert s.score == 0.5

    def test_parse_bad_score_neutral(self) -> None:
        s = _parse_judge_text("score=zzz; reason=foo")
        assert s.score == 0.5


class _FakeLLM:
    def __init__(self, out: str = "score=0.8; reason=ok") -> None:
        self._out = out

    async def acomplete(self, system: str, user: str) -> str:
        return self._out


class _FailingLLM:
    async def acomplete(self, system: str, user: str) -> str:
        raise LLMError("simulated failure")


class TestLlmJudge:
    @pytest.mark.asyncio
    async def test_no_llm_neutral(self) -> None:
        s = await LlmJudge(None).ascore({"alert": _alert()})
        assert s.score == 0.5

    @pytest.mark.asyncio
    async def test_llm_success(self) -> None:
        s = await LlmJudge(_FakeLLM()).ascore(
            {"alert": _alert(), "investigation": _inv(cases=1)}
        )
        assert s.score == 0.8

    @pytest.mark.asyncio
    async def test_llm_failure_neutral(self) -> None:
        s = await LlmJudge(_FailingLLM()).ascore({"alert": _alert()})
        assert s.score == 0.5
        assert "장애" in s.rationale


class TestEnsemble:
    def test_signal_veto_forces_fp(self) -> None:
        r = ensemble(
            [
                JudgeScore("signal", 0.0, veto=True),
                JudgeScore("llm", 1.0),
                JudgeScore("experience", 1.0),
            ],
            {"signal": 0.4, "llm": 0.3, "experience": 0.3},
        )
        assert r.verdict == Verdict.FALSE_POSITIVE
        assert r.veto_triggered

    def test_llm_veto_ignored(self) -> None:
        r = ensemble(
            [
                JudgeScore("signal", 1.0),
                JudgeScore("llm", 1.0, veto=True),
                JudgeScore("experience", 1.0),
            ],
            {"signal": 0.4, "llm": 0.3, "experience": 0.3},
        )
        assert r.verdict == Verdict.TRUE_POSITIVE  # LLM veto 무시

    def test_weighted_above_threshold_tp(self) -> None:
        r = ensemble(
            [
                JudgeScore("signal", 1.0),
                JudgeScore("llm", 0.6),
                JudgeScore("experience", 0.6),
            ],
            {"signal": 0.4, "llm": 0.3, "experience": 0.3},
            threshold=0.5,
        )
        assert r.verdict == Verdict.TRUE_POSITIVE

    def test_weighted_below_threshold_fp(self) -> None:
        r = ensemble(
            [
                JudgeScore("signal", 0.5),
                JudgeScore("llm", 0.0),
                JudgeScore("experience", 0.0),
            ],
            {"signal": 0.4, "llm": 0.3, "experience": 0.3},
            threshold=0.5,
        )
        assert r.verdict == Verdict.FALSE_POSITIVE

    def test_weights_normalized_when_judge_missing(self) -> None:
        # llm 빠짐 → signal 0.4 / exp 0.3 정규화 → signal=0.57, exp=0.43
        r = ensemble(
            [
                JudgeScore("signal", 1.0),
                JudgeScore("experience", 0.0),
            ],
            {"signal": 0.4, "llm": 0.3, "experience": 0.3},
            threshold=0.5,
        )
        assert r.weights["signal"] == pytest.approx(0.571, abs=0.01)
        assert r.verdict == Verdict.TRUE_POSITIVE

    def test_zero_weights_uniform_fallback(self) -> None:
        r = ensemble(
            [JudgeScore("signal", 1.0), JudgeScore("llm", 0.0)],
            {"signal": 0.0, "llm": 0.0},
            threshold=0.5,
        )
        # 균등 → composite=0.5 → threshold>=0.5 TP
        assert r.composite_score == pytest.approx(0.5, abs=0.01)


class TestValidationAgentEnsembleMode:
    @pytest.mark.asyncio
    async def test_single_judge_mode_preserved(self) -> None:
        # ensemble_judges 미주입 → 기존 callable 모드
        agent = ValidationAgent(Settings())
        state: SOCState = {
            "alert": _alert(),
            "investigation": _inv(cases=1),
        }
        out = await agent.run(state)
        assert "verdict" in out
        assert "ensemble" not in out

    @pytest.mark.asyncio
    async def test_ensemble_mode_emits_ensemble(self) -> None:
        agent = ValidationAgent(
            Settings(),
            ensemble_judges=[
                SignalJudge(),
                LlmJudge(_FakeLLM("score=0.9; reason=ok")),
                ExperienceJudge(),
            ],
        )
        state: SOCState = {
            "alert": _alert(),
            "investigation": _inv(cases=1),
        }
        out = await agent.run(state)
        assert isinstance(out["ensemble"], EnsembleResult)
        assert out["verdict"] == Verdict.TRUE_POSITIVE

    @pytest.mark.asyncio
    async def test_ensemble_signal_veto_routes_fp(self) -> None:
        agent = ValidationAgent(
            Settings(),
            ensemble_judges=[
                SignalJudge(),
                LlmJudge(_FakeLLM("score=1.0; reason=강한 정탐")),
                ExperienceJudge(),
            ],
        )
        # 신호 없음 → veto FP
        state: SOCState = {
            "alert": _alert(signals=[]),
            "investigation": _inv(cases=2),
        }
        out = await agent.run(state)
        assert out["verdict"] == Verdict.FALSE_POSITIVE
        result = out["ensemble"]
        assert isinstance(result, EnsembleResult) and result.veto_triggered
