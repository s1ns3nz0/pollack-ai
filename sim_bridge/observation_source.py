"""SimBridgeObservationSource — sim_bridge OutcomeAssessment → core Observation 어댑터.

sim_bridge.OutcomeProbe 가 텔레메트리 윈도우로 산정한 `OutcomeAssessment` 를
`core.outcome.Observation` 으로 변환한다. `core.outcome.OutcomeProbeAgent` 가
이 source 를 apoll 해 exp/actors/pb_scores 3 gate 에 fan-out 한다.

내부 인메모리 FIFO 큐 + (actor, scenario) 재발 추적. 같은 페어가 두 번 이상
enqueue 되면 두 번째부터 `reoccurred=True`.

관련 spec: A-1 (OutcomeProbe), A-2 후속.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.models import (
    Alert,
    EnvVerdict,
    JudgeFeatures,
    Severity,
    Verdict,
)
from core.outcome import Observation
from sim_bridge.outcome import OutcomeAssessment
from utils.logging import get_logger


@dataclass
class _QueueItem:
    """apoll 시점에 Observation 으로 변환할 대기 항목."""

    alert_id: str
    scenario_id: str
    actor_id: str | None
    playbook_id: str | None
    ts: str
    dwelling_min: int
    assessment: OutcomeAssessment
    alert_signals: list[str]
    alert_severity: Severity | None
    alert_verdict: Verdict | None
    alert_iocs: list[str]
    alert_mitre: dict[str, object]
    asset_id: str
    asset_tier: str
    judge_features: JudgeFeatures | None = None


@dataclass
class _ReoccurrenceTracker:
    """(actor, scenario) 페어의 이전 관측 여부."""

    seen: dict[str, set[str]] = field(default_factory=dict)

    def observe_and_check(self, actor_id: str | None, scenario_id: str) -> bool:
        """관측 등록 + 재발 여부 반환 (같은 (actor, scenario) 재관측 = True)."""
        if not actor_id:
            return False
        actor_seen = self.seen.setdefault(actor_id, set())
        if scenario_id in actor_seen:
            return True
        actor_seen.add(scenario_id)
        return False


class SimBridgeObservationSource:
    """sim_bridge → core.outcome 어댑터.

    Args:
        records_per_minute: 텔레메트리 rate (assessment.observations → window_min 환산).
            디폴트 600 (10Hz 텔레메트리 가정).
    """

    def __init__(self, records_per_minute: int = 600) -> None:
        if records_per_minute <= 0:
            raise ValueError("records_per_minute must be > 0")
        self._queue: list[_QueueItem] = []
        self._records_per_min = records_per_minute
        self._reoccurrence = _ReoccurrenceTracker()
        self._logger = get_logger("SimBridgeObservationSource")

    def enqueue(
        self,
        alert: Alert,
        assessment: OutcomeAssessment,
        playbook_id: str | None,
        ts: str,
        dwelling_min: int = 0,
        judge_features: JudgeFeatures | None = None,
        alert_verdict: Verdict | None = None,
    ) -> None:
        """sim 측에서 관측·평가 결과를 큐잉."""
        self._queue.append(
            _QueueItem(
                alert_id=alert.id,
                scenario_id=alert.scenario_id,
                actor_id=alert.actor_id,
                playbook_id=playbook_id,
                ts=ts,
                dwelling_min=dwelling_min,
                assessment=assessment,
                alert_signals=list(alert.signals),
                alert_severity=alert.severity_baseline,
                alert_verdict=alert_verdict,
                alert_iocs=list(alert.iocs),
                alert_mitre=dict(alert.mitre),
                asset_id=alert.asset_id,
                asset_tier=alert.asset_tier,
                judge_features=judge_features,
            )
        )

    def pending(self) -> int:
        """현재 큐잉된 항목 수."""
        return len(self._queue)

    async def apoll(self) -> list[Observation]:
        """큐 flush + Observation 목록 반환."""
        items, self._queue = self._queue, []
        out: list[Observation] = []
        for item in items:
            out.append(self._to_observation(item))
        self._logger.info("apoll drained=%d", len(out))
        return out

    def _to_observation(self, item: _QueueItem) -> Observation:
        env = item.assessment.env_verdict
        mission_effect = env == EnvVerdict.CONFIRMED_TP
        no_effect = env == EnvVerdict.CONFIRMED_FP
        reoccurred = self._reoccurrence.observe_and_check(
            item.actor_id, item.scenario_id
        )
        window_min = max(
            1,
            round(item.assessment.observations / self._records_per_min),
        )
        return Observation(
            alert_id=item.alert_id,
            scenario_id=item.scenario_id,
            actor_id=item.actor_id,
            playbook_id=item.playbook_id,
            window_min=window_min,
            mission_effect_observed=mission_effect,
            no_effect_sustained=no_effect,
            reoccurred=reoccurred,
            dwelling_min=item.dwelling_min,
            ts=item.ts,
            alert_signals=item.alert_signals,
            alert_severity=item.alert_severity,
            alert_verdict=item.alert_verdict,
            alert_iocs=item.alert_iocs,
            alert_mitre=item.alert_mitre,
            asset_id=item.asset_id,
            asset_tier=item.asset_tier,
            judge_features=item.judge_features,
        )
