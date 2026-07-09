"""SignalJudge — 결정론 점수 + signal 단독 hard veto(spec B1)."""

from __future__ import annotations

from agents.judges.base import JudgeScore
from core.models import SOCState


class SignalJudge:
    """기존 signal_judge 점수화 + veto.

    veto 조건(LLM/exp 인젝션 우회 차단):
    - 신호 0 또는 매치 룰 없음 → veto FP
    - suppression_corroboration > 0 → veto FP (신뢰 출처 동일 신호패턴 과거 FP)
    """

    async def ascore(self, state: SOCState) -> JudgeScore:
        alert = state["alert"]
        inv = state.get("investigation")
        has_signal = bool(alert.signals)
        has_rule = bool(
            alert.expected_detection.get("sigma_rule")
            or alert.expected_detection.get("sentinel_rule")
        )
        # 외부 enrich confidence 는 코로보레이션서 제외(Codex diff High) — 외부
        # TI/sandbox/KEV 가 verdict 를 간접 좌우 못하게. 내부신호(유사사례·경험)만 기여.
        corroborated = inv is not None and (
            bool(inv.similar_cases) or inv.experience_corroboration > 0
        )
        suppression = inv.suppression_corroboration if inv is not None else 0

        if not (has_signal and has_rule):
            return JudgeScore(
                judge="signal",
                score=0.0,
                rationale="신호/룰 부재 — hard veto",
                veto=True,
            )
        if suppression > 0:
            return JudgeScore(
                judge="signal",
                score=0.0,
                rationale=f"동일 신호패턴 신뢰 과거 FP {suppression}건 — veto",
                veto=True,
            )
        score = 1.0 if corroborated else 0.5
        return JudgeScore(
            judge="signal",
            score=score,
            rationale=(
                f"signal={has_signal} rule={has_rule} corroborated={corroborated}"
            ),
        )
