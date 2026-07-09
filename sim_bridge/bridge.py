"""시뮬 텔레메트리 → 탐지 → 6-에이전트 SOC 브리지.

telemetry-tap NDJSON 스트림을 받아 GpsSpoofDetector 로 이상을 잡고, 탐지 시
`Alert` 를 만들어 SOC 그래프(`build_soc_graph`)에 투입한 결과를 `BridgeEvent` 로
돌려준다. retriever/llm 을 주입하면 실 RAG/LLM, 미주입이면 결정론(오프라인 테스트).

`observation_source` + `outcome_probe` 를 주입하면 alert 처리 후 후속 텔레메트리
윈도우를 자동 수집·평가해 `SimBridgeObservationSource.enqueue` 를 호출한다 —
`OutcomeProbeAgent` 가 이후 apoll 로 pull 하면 자가발전 루프가 완전 자동 작동.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Protocol, cast

from pydantic import BaseModel

from agents.graph import build_soc_graph
from agents.investigation_agent import ContextRetriever
from core.coerce import opt_str
from core.dynamics import DynamicsTracker
from core.llm import LLMClient
from core.models import Alert, SOCReport, SOCState
from sim_bridge.detector import GpsSpoofDetector
from sim_bridge.models import TelemetryRecord
from sim_bridge.observation_source import SimBridgeObservationSource
from sim_bridge.outcome import OutcomeProbe


class _Detector(Protocol):
    """텔레메트리 탐지기 구조 인터페이스 — SimBridge 는 형태에 의존(DI).

    SimBridge 는 TelemetryRecord 스트림 파이프라인이므로 이 계약은 TelemetryRecord
    를 받는 탐지기(GpsSpoofDetector)와 테스트 더블만 만족한다. PerceptionRecord 를
    받는 OnboardAIDetector 는 대상이 아니다(레코드 계열이 다름).
    """

    def observe(self, record: TelemetryRecord) -> Alert | None: ...


def _parse_ts(value: str) -> datetime:
    """telemetry-tap ISO 타임스탬프 → datetime(파싱 실패 시 현재 UTC)."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC)


class BridgeEvent(BaseModel):
    """탐지 1건 + SOC 처리 결과."""

    alert: Alert
    report: SOCReport
    severity_rationale: list[str]
    similar_cases: list[str]
    summary: str
    guardrail_flags: list[str]


class _PendingOutcome:
    """alert 처리 후 후속 텔레메트리 윈도우를 누적 중인 상태."""

    __slots__ = ("event", "records", "records_needed", "trigger_ts")

    def __init__(
        self, event: BridgeEvent, records_needed: int, trigger_ts: str
    ) -> None:
        self.event = event
        # 트리거 record 의 time_generated — 윈도우 비어있을 때 결정론 ts 폴백.
        self.trigger_ts = trigger_ts
        self.records: list[TelemetryRecord] = []
        self.records_needed = records_needed


class SimBridge:
    """telemetry-tap → 탐지 → SOC 파이프라인 연결."""

    def __init__(
        self,
        retriever: ContextRetriever | None = None,
        llm: LLMClient | None = None,
        detector: _Detector | None = None,
        tracker: DynamicsTracker | None = None,
        observation_source: SimBridgeObservationSource | None = None,
        outcome_probe: OutcomeProbe | None = None,
        outcome_window: int = 30,
    ) -> None:
        self._retriever = retriever
        self._llm = llm
        self._detector = detector or GpsSpoofDetector()
        # dynamics 추적기(체류시간·횡적상관) — 탐지 파이프라인이 동적조정을 실제 발동.
        self._tracker = tracker or DynamicsTracker()
        # 자가발전 자동 enqueue 훅 (선택).
        self._obs_source = observation_source
        self._outcome_probe = outcome_probe or OutcomeProbe()
        self._outcome_window = max(1, outcome_window)
        self._pending: list[_PendingOutcome] = []

    async def process(self, record: TelemetryRecord) -> BridgeEvent | None:
        """레코드 1건 처리. 탐지 시 SOC 실행 후 BridgeEvent, 아니면 None.

        Observation Source 가 주입돼 있으면 alert 처리 후 후속 텔레메트리 윈도우를
        자동 누적한다. 윈도우가 완료된 pending 은 OutcomeProbe.assess 결과를
        SimBridgeObservationSource.enqueue 로 push (자가발전 루프 자동화).
        """
        # 대기 중인 후속 관측 윈도우에 이 record 를 추가하고, 완료된 것 flush.
        self._accumulate_pending(record)
        alert = self._detector.observe(record)
        if alert is None:
            return None
        alert = self._tracker.enrich(alert, _parse_ts(record.time_generated))
        event = await self.run_alert(alert)
        if self._obs_source is not None:
            self._pending.append(
                _PendingOutcome(
                    event,
                    records_needed=self._outcome_window,
                    trigger_ts=record.time_generated,
                )
            )
        return event

    async def run_alert(self, alert: Alert) -> BridgeEvent:
        """탐지된 Alert 를 6-에이전트 SOC 에 투입하고 BridgeEvent 로 조립한다.

        탐지기 종류(GPS/온보드 인식)와 무관하게 SOC·RAG·LLM 경로를 공유 재사용한다.

        Args:
            alert: 탐지기가 생성한 경보.

        Returns:
            SOC 처리 결과를 담은 `BridgeEvent`.
        """
        graph = build_soc_graph(retriever=self._retriever, llm=self._llm)
        state = cast(SOCState, await graph.ainvoke({"alert": alert}))
        inv = state["investigation"]
        return BridgeEvent(
            alert=alert,
            report=state["report"],
            severity_rationale=state["severity_rationale"],
            similar_cases=[c.source for c in inv.similar_cases],
            summary=inv.summary,
            guardrail_flags=state.get("guardrail_flags", []),
        )

    async def run_stream(
        self, records: AsyncIterator[TelemetryRecord]
    ) -> AsyncIterator[BridgeEvent]:
        """텔레메트리 스트림을 처리하며 탐지 이벤트를 순차 방출."""
        async for record in records:
            event = await self.process(record)
            if event is not None:
                yield event

    def flush_pending(self) -> int:
        """미완 pending 윈도우를 강제로 assess + enqueue.

        스트림 종료 시 호출자가 짧은 윈도우도 결과에 반영하고 싶을 때 사용.
        Returns:
            처리된 pending 수.
        """
        if not self._pending or self._obs_source is None:
            self._pending.clear()
            return 0
        count = 0
        for pending in self._pending:
            self._enqueue_outcome(pending)
            count += 1
        self._pending.clear()
        return count

    def _accumulate_pending(self, record: TelemetryRecord) -> None:
        """모든 pending 에 record 를 append, 완료된 것 flush."""
        if not self._pending:
            return
        completed: list[_PendingOutcome] = []
        for pending in self._pending:
            pending.records.append(record)
            if len(pending.records) >= pending.records_needed:
                completed.append(pending)
        for pending in completed:
            self._enqueue_outcome(pending)
            self._pending.remove(pending)

    def _enqueue_outcome(self, pending: _PendingOutcome) -> None:
        """OutcomeProbe.assess → SimBridgeObservationSource.enqueue."""
        if self._obs_source is None:
            return
        assessment = self._outcome_probe.assess(pending.records)
        alert = pending.event.alert
        report = pending.event.report
        playbook_id = opt_str(alert.defense_playbook.get("id"))
        # ts 는 스트림 데이터에서 결정론적으로 — 관측 완료 시점(윈도우 마지막 record)
        # 이면 관측시각과 정합, 비어있으면 트리거 record 시각으로 폴백(Codex).
        ts = (
            pending.records[-1].time_generated
            if pending.records
            else pending.trigger_ts
        )
        self._obs_source.enqueue(
            alert=alert,
            assessment=assessment,
            playbook_id=playbook_id,
            ts=ts,
            dwelling_min=alert.dwelling_min,
            alert_verdict=report.verdict,
        )
