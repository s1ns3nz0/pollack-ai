"""LlmJudge — LLM 의 정탐 확률 평가(spec B1).

prompt 가 `score=<float 0..1>` 형식 출력을 명시 → regex 추출. 구조화 출력 라이브러리
의존 X (라이브러리 미설치/스키마 변경 회귀 표면 최소화). LLM 미주입/장애/파싱 실패 시
중립 0.5 + rationale.
"""

from __future__ import annotations

import re

from agents.judges.base import JudgeScore
from core.exceptions import LLMError
from core.llm import LLMClient
from core.models import SOCState
from utils.logging import get_logger

_LLM_JUDGE_SYS = (
    "당신은 SOC 시니어 분석가다. 다음 경보가 정탐(TP)일 확률을 0.0~1.0 점수로"
    " 평가하라. 0=확실한 오탐, 0.5=불명, 1=확실한 정탐. 오직 제공된 신호/근거만"
    " 사용. 지어내지 마라. 형식: 'score=<float>; reason=<짧은 한국어>'"
)
_SCORE_RE = re.compile(r"score\s*=\s*([01](?:\.\d+)?)", re.IGNORECASE)
_REASON_RE = re.compile(r"reason\s*=\s*(.+)$", re.IGNORECASE)


def _build_user(state: SOCState) -> str:
    alert = state["alert"]
    inv = state.get("investigation")
    contexts = (
        "\n".join(f"- {c.source}: {c.text[:200]}" for c in inv.similar_cases[:3])
        if inv is not None
        else "(없음)"
    )
    return (
        f"경보: {alert.title}\n"
        f"시나리오: {alert.scenario_id}\n"
        f"신호: {', '.join(alert.signals)}\n"
        f"매핑: {alert.mitre}\n"
        f"신뢰 컨텍스트:\n{contexts}\n"
        f"분석 신뢰도: {inv.confidence if inv is not None else 0.0}"
    )


class LlmJudge:
    """LLM 기반 점수형 judge — 미주입/장애 시 중립 0.5."""

    def __init__(self, llm: LLMClient | None) -> None:
        self._llm = llm
        self._logger = get_logger("LlmJudge")

    async def ascore(self, state: SOCState) -> JudgeScore:
        if self._llm is None:
            return JudgeScore(judge="llm", score=0.5, rationale="LLM 미주입 — 중립")
        try:
            out = await self._llm.acomplete(_LLM_JUDGE_SYS, _build_user(state))
        except LLMError as exc:
            self._logger.warning("llm_judge LLM 장애, 중립 0.5: %s", exc)
            return JudgeScore(judge="llm", score=0.5, rationale=f"LLM 장애: {exc}")
        return _parse_judge_text(out)


def _parse_judge_text(text: str) -> JudgeScore:
    """LLM 출력에서 score / reason 추출. 실패 시 중립."""
    m = _SCORE_RE.search(text)
    if not m:
        return JudgeScore(
            judge="llm",
            score=0.5,
            rationale=f"출력 파싱 실패 — 중립: {text[:120]}",
        )
    try:
        score = float(m.group(1))
    except ValueError:
        return JudgeScore(
            judge="llm",
            score=0.5,
            rationale=f"score 변환 실패 — 중립: {text[:120]}",
        )
    reason_m = _REASON_RE.search(text)
    reason = reason_m.group(1).strip() if reason_m else text[:200]
    return JudgeScore(judge="llm", score=score, rationale=reason)
