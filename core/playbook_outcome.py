"""PB 효과 점수 학습 — outcome → ActorProfile.pb_scores 누적(spec B-1).

`ActorWriteGate` 와 페어 — 같은 ActorStore + signer 공유. 호출자가 outcome.effect
(0~1) 결정 책임. 본 모듈은 *측정·적립*만 한다 (PB 자동 선택은 후속 사이클).

Spec: docs/superpowers/specs/2026-06-30-playbook-outcome-learning-design.md
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from core.actors import (
    ActorSigner,
    ActorStore,
    ActorWriteDecision,
    ActorWriteStatus,
    Sha256ActorSigner,
)
from core.exceptions import SOCPlatformError
from core.models import ActorPlaybookScore
from utils.logging import get_logger


class PlaybookOutcome(BaseModel):
    """PB 실행 결과 측정값 한 건.

    Attributes:
        actor_id: 측정 대상 공격자 식별자.
        playbook_id: 실행된 PB 식별자.
        effect: 0~1 점수. 0=차단 실패, 1=완전 차단.
        ts: ISO8601 측정 시각.
        reason: 사람이 읽을 설명 (선택).
    """

    actor_id: str
    playbook_id: str
    effect: float = Field(ge=0.0, le=1.0)
    ts: str
    reason: str = ""


class ActorPlaybookOutcomeGate:
    """PB 효과 점수 적립 단일 통로.

    같은 ActorStore + signer 를 ActorWriteGate 와 공유한다 — 서명 검증 round-trip
    호환. actor 미존재 시 REJECTED_NO_ACTOR (측정 의미 X).
    """

    def __init__(self, store: ActorStore, signer: ActorSigner | None = None) -> None:
        self._store = store
        self._signer = signer or Sha256ActorSigner()
        self._logger = get_logger("ActorPlaybookOutcomeGate")

    async def submit(self, outcome: PlaybookOutcome) -> ActorWriteDecision:
        """outcome 을 점수 누적·서명 갱신·저장."""
        actor_id = outcome.actor_id.strip()
        playbook_id = outcome.playbook_id.strip()
        if not actor_id or not playbook_id:
            return ActorWriteDecision(
                status=ActorWriteStatus.REJECTED_EMPTY,
                reason="actor_id/playbook_id 빈값",
            )
        try:
            existing = await self._store.aload(actor_id)
        except SOCPlatformError as exc:
            return ActorWriteDecision(
                status=ActorWriteStatus.REJECTED_STORE_ERROR,
                reason=f"store 조회 실패: {exc}",
            )
        if existing is None:
            return ActorWriteDecision(
                status=ActorWriteStatus.REJECTED_NO_ACTOR,
                reason="actor 미적립 — outcome 측정 불가",
            )
        score = existing.pb_scores.get(playbook_id) or ActorPlaybookScore(
            playbook_id=playbook_id
        )
        score.count += 1
        score.sum_effect = round(score.sum_effect + outcome.effect, 4)
        score.avg_effect = round(score.sum_effect / score.count, 4)
        score.last_seen = outcome.ts
        existing.pb_scores[playbook_id] = score
        existing.content_hash = existing.fingerprint()
        existing.signature = self._signer.sign(existing.content_hash)
        try:
            await self._store.awrite(existing)
        except SOCPlatformError as exc:
            return ActorWriteDecision(
                status=ActorWriteStatus.REJECTED_STORE_ERROR,
                reason=f"store 저장 실패: {exc}",
            )
        self._logger.info(
            "pb outcome: actor=%s pb=%s count=%d avg=%.3f",
            actor_id,
            playbook_id,
            score.count,
            score.avg_effect,
        )
        return ActorWriteDecision(status=ActorWriteStatus.WRITTEN, actor_id=actor_id)
