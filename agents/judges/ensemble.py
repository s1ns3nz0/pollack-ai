"""Ensemble — 가중 평균 + signal 단독 hard veto(spec B1)."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, Field

from agents.judges.base import JudgeScore
from core.models import Verdict


class EnsembleResult(BaseModel):
    """Ensemble 결정 + 트레이스."""

    verdict: Verdict
    composite_score: float = Field(ge=0.0, le=1.0)
    threshold: float = Field(ge=0.0, le=1.0)
    scores: list[dict[str, object]] = Field(default_factory=list)
    weights: dict[str, float] = Field(default_factory=dict)
    veto_triggered: bool = False
    veto_judge: str = ""


def ensemble(
    scores: Iterable[JudgeScore],
    weights: dict[str, float],
    threshold: float = 0.5,
) -> EnsembleResult:
    """signal-only veto → 가중 평균 → threshold 분기."""
    score_list = list(scores)
    veto_score = next((s for s in score_list if s.veto and s.judge == "signal"), None)
    serialized: list[dict[str, object]] = [
        {
            "judge": s.judge,
            "score": s.score,
            "rationale": s.rationale,
            "veto": s.veto,
        }
        for s in score_list
    ]
    if veto_score is not None:
        return EnsembleResult(
            verdict=Verdict.FALSE_POSITIVE,
            composite_score=veto_score.score,
            threshold=threshold,
            scores=serialized,
            weights=dict(weights),
            veto_triggered=True,
            veto_judge="signal",
        )
    active: dict[str, float] = {
        str(s.judge): weights.get(s.judge, 0.0) for s in score_list
    }
    total = sum(active.values())
    norm: dict[str, float]
    if total <= 0.0:
        # weights 합 0 → 균등 분배 (운영 가이드: 미설정 회피)
        n = max(1, len(score_list))
        norm = {str(s.judge): 1.0 / n for s in score_list}
    else:
        norm = {k: v / total for k, v in active.items()}
    composite = sum(s.score * norm.get(s.judge, 0.0) for s in score_list)
    verdict = (
        Verdict.TRUE_POSITIVE if composite >= threshold else Verdict.FALSE_POSITIVE
    )
    return EnsembleResult(
        verdict=verdict,
        composite_score=round(composite, 3),
        threshold=threshold,
        scores=serialized,
        weights=norm,
        veto_triggered=False,
    )
