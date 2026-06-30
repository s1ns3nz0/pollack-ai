"""ExperienceJudge — exp 회상 기반 0~1 점수(spec B1)."""

from __future__ import annotations

from agents.judges.base import JudgeScore
from core.models import SOCState


class ExperienceJudge:
    """investigation 의 exp/suppression corroboration 을 점수화.

    중립(0.5) 기준으로 정탐 회상 +0.25 / 신뢰 과거 FP -0.25 적용. base 한도 (0~1).
    """

    async def ascore(self, state: SOCState) -> JudgeScore:
        inv = state.get("investigation")
        if inv is None:
            return JudgeScore(
                judge="experience",
                score=0.5,
                rationale="investigation 미수행 — 중립",
            )
        base = 0.5
        if inv.experience_corroboration > 0:
            base = min(1.0, base + 0.25)
        if inv.suppression_corroboration > 0:
            base = max(0.0, base - 0.25)
        return JudgeScore(
            judge="experience",
            score=round(base, 3),
            rationale=(
                f"exp+{inv.experience_corroboration} "
                f"sup-{inv.suppression_corroboration}"
            ),
        )
