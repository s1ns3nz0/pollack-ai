"""꺼진 불 재심(cold-case reopener) — 억제(FP) 학습의 결정론 재검토.

억제는 위험한 단방향이다: 한번 CONFIRMED_FP 로 학습되면 동일 신호 알람이 계속
묻힌다. 나중에 **같은 actor 가 확정 공격자로 드러나거나 같은 signature 가 후속
CONFIRMED_TP** 로 확인되면, 그 과거 FP 는 진짜 공격의 흔적이었을 수 있다.

ColdCaseReopener 는 그 두 트리거로 과거 억제를 revoke(회상 제외)하고 재심 큐
(`ReopenLedger`)에 올려 운영자 검토를 받게 한다. 트리거는 CONFIRMED_TP(최고 신뢰)
에서만 발동 — 미검증 알람은 억제를 못 푼다(FN 유발 포이즈닝 차단, 예측 폐루프와
동일한 비대칭 신뢰).
"""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel

from core.experience import ReopenableStore
from core.models import ExperienceRecord
from utils.logging import get_logger

_logger = get_logger("ColdCaseReopener")


class ReopenedCase(BaseModel):
    """재심으로 억제가 무효화된 케이스 한 건(운영자 검토 큐 항목).

    Attributes:
        fingerprint: revoke 된 경험 레코드 지문.
        scenario_id: 원 억제 시나리오.
        reason: 재심 근거(트리거 종류 + 식별자).
        trigger_alert_id: 재심을 발동시킨 CONFIRMED_TP 알람 id.
    """

    fingerprint: str
    scenario_id: str
    reason: str
    trigger_alert_id: str


class ReopenLedger:
    """재심 큐 — revoke 된 케이스를 운영자 검토용으로 누적(프로세스 내 MVP)."""

    def __init__(self) -> None:
        self._cases: list[ReopenedCase] = []

    def add(self, case: ReopenedCase) -> None:
        """재심 케이스를 큐에 적재한다."""
        self._cases.append(case)

    def cases(self) -> list[ReopenedCase]:
        """적재된 재심 케이스 전체를 반환한다."""
        return list(self._cases)

    def __len__(self) -> int:
        return len(self._cases)


class ColdCaseReopener:
    """억제 재심기 — 두 트리거로 과거 FP 를 revoke + 큐 적재(결정론).

    Args:
        store: 재심 가능 저장소(`ReopenableStore`).
        ledger: 재심 큐. 생략 시 내부 신규 생성.
    """

    def __init__(
        self,
        store: ReopenableStore,
        ledger: ReopenLedger | None = None,
        on_reopen: Callable[[], None] | None = None,
    ) -> None:
        self._store = store
        # `ledger or ...` 금지 — ReopenLedger.__len__ 이 빈 큐를 falsy 로 만들어
        # 주입된 빈 ledger 를 새 인스턴스로 갈아치운다(호출자 큐와 분리되는 버그).
        self._ledger = ledger if ledger is not None else ReopenLedger()
        self._on_reopen = on_reopen

    @property
    def ledger(self) -> ReopenLedger:
        """재심 큐."""
        return self._ledger

    async def reopen_for_actor(
        self, actor_fingerprint: str, trigger_alert_id: str
    ) -> list[ReopenedCase]:
        """동일 actor 확정 트리거 — 그 actor 의 과거 억제를 재심한다.

        Args:
            actor_fingerprint: 확정 공격자로 드러난 actor 지문.
            trigger_alert_id: 재심을 발동한 CONFIRMED_TP 알람 id.

        Returns:
            revoke 된 케이스 목록. 빈 지문이면 무동작(전체 revoke 방지).
        """
        if not actor_fingerprint:
            return []
        return await self._reopen(
            lambda rec: rec.actor_fingerprint == actor_fingerprint,
            reason=f"동일 actor 확정({actor_fingerprint})",
            trigger_alert_id=trigger_alert_id,
        )

    async def reopen_for_signature(
        self, signals: list[str], trigger_alert_id: str
    ) -> list[ReopenedCase]:
        """동일 signature 후속 TP 트리거 — 신호 겹침 과거 억제를 재심한다.

        Args:
            signals: 후속 CONFIRMED_TP 알람의 신호 목록.
            trigger_alert_id: 재심을 발동한 알람 id.

        Returns:
            revoke 된 케이스 목록. 신호 없으면 무동작.
        """
        sig_set = set(signals)
        if not sig_set:
            return []
        return await self._reopen(
            lambda rec: bool(sig_set & set(rec.signals)),
            reason=f"동일 signature 후속 TP({trigger_alert_id})",
            trigger_alert_id=trigger_alert_id,
        )

    async def _reopen(
        self,
        match: Callable[[ExperienceRecord], bool],
        reason: str,
        trigger_alert_id: str,
    ) -> list[ReopenedCase]:
        """매칭 술어에 걸린 미revoke 억제를 revoke + 큐 적재한다."""
        reopened: list[ReopenedCase] = []
        for rec in await self._store.ascan_suppressions():
            if not match(rec):
                continue
            ok = await self._store.arevoke(rec.content_hash, reason)
            if not ok:
                continue
            case = ReopenedCase(
                fingerprint=rec.content_hash,
                scenario_id=rec.scenario_id,
                reason=reason,
                trigger_alert_id=trigger_alert_id,
            )
            self._ledger.add(case)
            reopened.append(case)
            if self._on_reopen is not None:
                self._on_reopen()
            _logger.info(
                "cold-case reopen: scenario=%s reason=%s trigger=%s",
                rec.scenario_id,
                reason,
                trigger_alert_id,
            )
        return reopened
