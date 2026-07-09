"""SimBridge 자동 enqueue 훅 — 후속 window 자동 assess + enqueue."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from core.models import (
    Alert,
    EnvVerdict,
    Severity,
    SOCReport,
    Verdict,
)
from sim_bridge.bridge import BridgeEvent, SimBridge
from sim_bridge.observation_source import SimBridgeObservationSource
from sim_bridge.outcome import OutcomeAssessment


def _alert(**kwargs: object) -> Alert:
    base: dict[str, object] = {
        "id": "a1",
        "scenario_id": "S1",
        "title": "GPS spoof",
        "severity_baseline": Severity.MEDIUM,
        "signals": ["EKF_HIGH_VARIANCE"],
        "actor_id": "team-red",
        "defense_playbook": {"id": "pb_gnss_block", "actions": []},
    }
    base.update(kwargs)
    return Alert.model_validate(base)


def _bridge_event(alert: Alert) -> BridgeEvent:
    return BridgeEvent(
        alert=alert,
        report=SOCReport(
            alert_id=alert.id,
            scenario_id=alert.scenario_id,
            title=alert.title,
            severity=Severity.MEDIUM,
            verdict=Verdict.TRUE_POSITIVE,
            recommended_action="response",
        ),
        severity_rationale=[],
        similar_cases=[],
        summary="",
        guardrail_flags=[],
    )


class _StubProbe:
    """OutcomeProbe stub — assess() 결과 사전 지정."""

    def __init__(self, env_verdict: EnvVerdict = EnvVerdict.CONFIRMED_TP) -> None:
        self._env = env_verdict
        self.calls = 0

    def assess(self, records: object) -> OutcomeAssessment:
        self.calls += 1
        obs = len(records) if hasattr(records, "__len__") else 0
        return OutcomeAssessment(
            env_verdict=self._env,
            sustained_effect_records=5,
            observations=obs,
            rationale=["stub"],
        )


class _NullDetector:
    def observe(self, record: object) -> Alert | None:
        return None


class _EagerDetector:
    """첫 record 는 alert, 이후는 None."""

    def __init__(self, alert: Alert) -> None:
        self._alert = alert
        self._used = False

    def observe(self, record: object) -> Alert | None:
        if self._used:
            return None
        self._used = True
        return self._alert


class _FakeRecord:
    """TelemetryRecord stub."""

    time_generated = "2026-07-02T00:00:00Z"


class TestPendingWindow:
    @pytest.mark.asyncio
    async def test_no_source_no_pending(self) -> None:
        alert = _alert()
        bridge = SimBridge(
            detector=_EagerDetector(alert),
            observation_source=None,
        )
        # run_alert 를 스킵하고 process 를 직접 호출하려면 SOC 그래프가 필요 —
        # run_alert 를 mock 으로 대체.
        bridge.run_alert = AsyncMock(return_value=_bridge_event(alert))  # type: ignore[method-assign]
        await bridge.process(_FakeRecord())  # type: ignore[arg-type]
        # 이후 window record 여러 개 넣어도 assess 호출 없음
        for _ in range(50):
            await bridge.process(_FakeRecord())  # type: ignore[arg-type]
        # No exception, pending 비어있음
        assert bridge._pending == []  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_window_completes_and_enqueues(self) -> None:
        alert = _alert()
        source = SimBridgeObservationSource()
        probe = _StubProbe(EnvVerdict.CONFIRMED_TP)
        bridge = SimBridge(
            detector=_EagerDetector(alert),
            observation_source=source,
            outcome_probe=probe,  # type: ignore[arg-type]
            outcome_window=5,
        )
        bridge.run_alert = AsyncMock(return_value=_bridge_event(alert))  # type: ignore[method-assign]
        # 첫 record → alert 생성 (pending 에 추가됨)
        event = await bridge.process(_FakeRecord())  # type: ignore[arg-type]
        assert event is not None
        assert source.pending() == 0
        # 이후 5 record 로 window 완료 → enqueue
        for _ in range(5):
            await bridge.process(_FakeRecord())  # type: ignore[arg-type]
        assert source.pending() == 1
        assert probe.calls == 1

    @pytest.mark.asyncio
    async def test_partial_window_no_enqueue(self) -> None:
        alert = _alert()
        source = SimBridgeObservationSource()
        probe = _StubProbe()
        bridge = SimBridge(
            detector=_EagerDetector(alert),
            observation_source=source,
            outcome_probe=probe,  # type: ignore[arg-type]
            outcome_window=10,
        )
        bridge.run_alert = AsyncMock(return_value=_bridge_event(alert))  # type: ignore[method-assign]
        await bridge.process(_FakeRecord())  # type: ignore[arg-type]
        # window 반만 채움 → enqueue 없음
        for _ in range(4):
            await bridge.process(_FakeRecord())  # type: ignore[arg-type]
        assert source.pending() == 0
        assert probe.calls == 0

    @pytest.mark.asyncio
    async def test_flush_pending_forces_enqueue(self) -> None:
        alert = _alert()
        source = SimBridgeObservationSource()
        probe = _StubProbe(EnvVerdict.INCONCLUSIVE)
        bridge = SimBridge(
            detector=_EagerDetector(alert),
            observation_source=source,
            outcome_probe=probe,  # type: ignore[arg-type]
            outcome_window=100,
        )
        bridge.run_alert = AsyncMock(return_value=_bridge_event(alert))  # type: ignore[method-assign]
        await bridge.process(_FakeRecord())  # type: ignore[arg-type]
        # window 미완 상태에서 flush → 강제 enqueue
        count = bridge.flush_pending()
        assert count == 1
        assert source.pending() == 1
        assert probe.calls == 1

    @pytest.mark.asyncio
    async def test_flush_no_pending_returns_zero(self) -> None:
        source = SimBridgeObservationSource()
        bridge = SimBridge(detector=_NullDetector(), observation_source=source)
        assert bridge.flush_pending() == 0


class TestEnqueuePayload:
    @pytest.mark.asyncio
    async def test_enqueued_observation_has_expected_fields(self) -> None:
        alert = _alert()
        source = SimBridgeObservationSource()
        probe = _StubProbe(EnvVerdict.CONFIRMED_TP)
        bridge = SimBridge(
            detector=_EagerDetector(alert),
            observation_source=source,
            outcome_probe=probe,  # type: ignore[arg-type]
            outcome_window=3,
        )
        bridge.run_alert = AsyncMock(return_value=_bridge_event(alert))  # type: ignore[method-assign]
        await bridge.process(_FakeRecord())  # type: ignore[arg-type]
        for _ in range(3):
            await bridge.process(_FakeRecord())  # type: ignore[arg-type]
        obs_list = await source.apoll()
        assert len(obs_list) == 1
        obs = obs_list[0]
        assert obs.alert_id == alert.id
        assert obs.actor_id == "team-red"
        assert obs.playbook_id == "pb_gnss_block"
        assert obs.mission_effect_observed  # CONFIRMED_TP
        assert obs.alert_verdict == Verdict.TRUE_POSITIVE

    @pytest.mark.asyncio
    async def test_ts_is_deterministic_from_stream(self) -> None:
        """ts 는 벽시계 아님 — 스트림 record 시각에서 결정론(Codex 반영)."""

        async def _run() -> str:
            alert = _alert()
            source = SimBridgeObservationSource()
            bridge = SimBridge(
                detector=_EagerDetector(alert),
                observation_source=source,
                outcome_probe=_StubProbe(),  # type: ignore[arg-type]
                outcome_window=2,
            )
            bridge.run_alert = AsyncMock(  # type: ignore[method-assign]
                return_value=_bridge_event(alert)
            )
            for _ in range(3):
                await bridge.process(_FakeRecord())  # type: ignore[arg-type]
            return (await source.apoll())[0].ts

        first = await _run()
        second = await _run()
        # 벽시계였다면 두 실행 ts 가 달라짐 — record 시각이라 동일·고정.
        assert first == second == "2026-07-02T00:00:00Z"
