"""Judge Protocol — Multi-Judge Ensemble 공통 계약(spec B1)."""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable

from core.models import SOCState


class JudgeScore:
    """점수형 judge 결과. pydantic 회피해 import cycle 최소화.

    Attributes:
        judge: "signal" | "llm" | "experience".
        score: 0.0 ~ 1.0. 정탐 확률.
        rationale: 사람이 읽을 근거.
        veto: True 면 ensemble 이 signal 단독에 한해 hard veto FP 채택.
    """

    __slots__ = ("judge", "score", "rationale", "veto")

    def __init__(
        self,
        judge: Literal["signal", "llm", "experience"],
        score: float,
        rationale: str = "",
        veto: bool = False,
    ) -> None:
        self.judge = judge
        self.score = max(0.0, min(1.0, float(score)))
        self.rationale = rationale
        self.veto = veto

    def __repr__(self) -> str:  # pragma: no cover - debug
        return (
            f"JudgeScore(judge={self.judge!r}, score={self.score!r}, "
            f"veto={self.veto!r})"
        )


@runtime_checkable
class Judge(Protocol):
    """모든 judge 의 공통 인터페이스. 비동기 점수 산정."""

    async def ascore(self, state: SOCState) -> JudgeScore:
        """state 를 점수화해 반환한다."""
        ...
