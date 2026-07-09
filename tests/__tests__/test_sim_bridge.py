"""sim_bridge 테스트 — 탐지기 + 브리지(합성 텔레메트리, 오프라인).

RAG/LLM 없이(None) 결정론적으로 검증한다.
"""

from typing import cast

import pytest

from core.models import Severity, Verdict
from sim_bridge.actuator import hold_then_rtb
from sim_bridge.bridge import SimBridge
from sim_bridge.detector import GpsSpoofDetector, OnboardAIDetector
from sim_bridge.models import PerceptionRecord, TelemetryRecord
from sim_bridge.perception_synth import (
    adversarial_perception,
    benign_perception,
    synth_perception_records,
    synth_perception_stream,
)
from sim_bridge.synth import (
    benign_ekf,
    benign_gps,
    spoof_ekf,
    spoof_ekf_glitch,
    spoof_gps,
    synth_stream,
)


class TestTelemetryRecord:
    """NDJSON 별칭 파싱."""

    def test_alias_parsing(self) -> None:
        """telemetry-tap 키(PosHorizVariance 등)가 필드로 매핑된다."""
        r = TelemetryRecord.from_ndjson(spoof_ekf())
        assert r.msg_type == "EKF_STATUS_REPORT"
        assert r.pos_horiz_variance == 1.35


class TestPerceptionRecord:
    """인식 추론 NDJSON 별칭 파싱."""

    def test_alias_parsing(self) -> None:
        """EoClass/IrConfidence 등 별칭 키가 필드로 매핑된다."""
        r = PerceptionRecord.from_ndjson(
            {
                "UAVId": "MPD-001",
                "MsgType": "PERCEPTION_INFERENCE",
                "TargetId": "TGT-01",
                "EoClass": "vehicle",
                "IrClass": "bird",
                "EoConfidence": 0.88,
                "IrConfidence": 0.42,
            }
        )
        assert r.msg_type == "PERCEPTION_INFERENCE"
        assert r.eo_class == "vehicle"
        assert r.ir_class == "bird"
        assert r.eo_conf == 0.88
        assert r.ir_conf == 0.42


class TestPerceptionSynth:
    """합성 인식 스트림(정상/적대) 값 검증."""

    def test_benign_classes_agree_small_gap(self) -> None:
        """정상: EO/IR 클래스 일치 + 신뢰도 gap 작음(<0.15)."""
        b = benign_perception()
        assert b["EoClass"] == b["IrClass"]
        eo = cast(float, b["EoConfidence"])
        ir = cast(float, b["IrConfidence"])
        assert abs(eo - ir) < 0.15

    def test_adversarial_mismatch_and_large_gap(self) -> None:
        """적대: EO/IR 클래스 불일치 + 신뢰도 gap≥0.15."""
        a = adversarial_perception()
        assert a["EoClass"] != a["IrClass"]
        eo = cast(float, a["EoConfidence"])
        ir = cast(float, a["IrConfidence"])
        assert abs(eo - ir) >= 0.15

    def test_synth_records_benign_then_adversarial(self) -> None:
        """정상 N건 → 적대 2건(확정 스트릭) 순서."""
        recs = synth_perception_records(benign_n=4)
        assert len(recs) == 6
        assert recs[0].eo_class == recs[0].ir_class  # 정상
        assert recs[-1].eo_class != recs[-1].ir_class  # 적대


class TestGpsSpoofDetector:
    """탐지기 동작."""

    def test_benign_no_alert(self) -> None:
        """정상 텔레메트리엔 경보 없음."""
        det = GpsSpoofDetector()
        assert det.observe(TelemetryRecord.from_ndjson(benign_gps())) is None
        assert det.observe(TelemetryRecord.from_ndjson(benign_ekf())) is None

    def test_spoof_fires_alert(self) -> None:
        """GPS 품질저하(Eph 급증/위성감소) + EKF 잔차 급증 → S1 경보."""
        det = GpsSpoofDetector()
        det.observe(TelemetryRecord.from_ndjson(benign_gps()))  # 기준선 Eph
        det.observe(TelemetryRecord.from_ndjson(spoof_gps()))  # Eph 급증
        alert = det.observe(TelemetryRecord.from_ndjson(spoof_ekf()))  # EKF 잔차
        assert alert is not None
        assert alert.scenario_id == "UAV-GPS-SPOOF-001"
        assert alert.severity_baseline == Severity.HIGH
        assert any("EKF" in s for s in alert.signals)

    def test_real_glitch_flag_fires_alert(self) -> None:
        """실 SITL 시그니처: 글리치 플래그(0x8000)+위성 급감 → 경보(잔차 낮아도)."""
        det = GpsSpoofDetector()
        det.observe(TelemetryRecord.from_ndjson(benign_gps()))
        det.observe(TelemetryRecord.from_ndjson(benign_ekf()))
        det.observe(TelemetryRecord.from_ndjson(spoof_gps()))  # 위성 급감/Eph 급증
        alert = det.observe(
            TelemetryRecord.from_ndjson(spoof_ekf_glitch())  # 글리치 플래그
        )
        assert alert is not None
        assert any("글리치" in s for s in alert.signals)

    def test_corr_window_combines_transient_ekf_with_later_gps(self) -> None:
        """온셋 EKF 스파이크가 잠깐이고 위성 급감이 몇 레코드 뒤 와도 결합·발화."""
        det = GpsSpoofDetector(corr_window=10)
        det.observe(TelemetryRecord.from_ndjson(benign_gps()))  # 위성 정상
        det.observe(TelemetryRecord.from_ndjson(spoof_ekf()))  # EKF 스파이크(온셋)
        # 이후 정상 EKF 가 여러 건 흘러도 윈도우 동안 EKF 신호 유지
        for _ in range(3):
            assert det.observe(TelemetryRecord.from_ndjson(benign_ekf())) is None
        alert = det.observe(
            TelemetryRecord.from_ndjson(spoof_gps())
        )  # 뒤늦은 위성 급감
        assert alert is not None

    def test_corr_window_expires(self) -> None:
        """상관 윈도우 만료 후 도착한 GPS 신호는 EKF 와 결합되지 않음."""
        det = GpsSpoofDetector(corr_window=3)
        det.observe(TelemetryRecord.from_ndjson(benign_gps()))
        det.observe(TelemetryRecord.from_ndjson(spoof_ekf()))  # 윈도우 무장(3)
        for _ in range(4):  # 윈도우 소진
            det.observe(TelemetryRecord.from_ndjson(benign_ekf()))
        assert det.observe(TelemetryRecord.from_ndjson(spoof_gps())) is None

    def test_glitch_flag_alone_no_alert(self) -> None:
        """EKF 글리치 플래그만 있고 GPS 신호 없으면 발화 안 함(단독 오탐 방지)."""
        det = GpsSpoofDetector()
        det.observe(TelemetryRecord.from_ndjson(benign_gps()))  # 위성 정상
        alert = det.observe(TelemetryRecord.from_ndjson(spoof_ekf_glitch()))
        assert alert is None

    def test_duplicate_suppressed(self) -> None:
        """동일 사건 중복 발화 억제."""
        det = GpsSpoofDetector()
        det.observe(TelemetryRecord.from_ndjson(benign_gps()))
        det.observe(TelemetryRecord.from_ndjson(spoof_gps()))
        first = det.observe(TelemetryRecord.from_ndjson(spoof_ekf()))
        second = det.observe(TelemetryRecord.from_ndjson(spoof_ekf()))
        assert first is not None
        assert second is None

    def test_auto_rearm_after_clean(self) -> None:
        """사건 종료 후 정상 복귀가 이어지면 재무장해 다음 공격을 다시 탐지(재촬영)."""
        det = GpsSpoofDetector(corr_window=2, rearm_after=3)
        # 1차 공격 → 발화
        det.observe(TelemetryRecord.from_ndjson(benign_gps()))
        det.observe(TelemetryRecord.from_ndjson(spoof_gps()))
        assert det.observe(TelemetryRecord.from_ndjson(spoof_ekf())) is not None
        # 정상 텔레메트리 지속 → 재무장
        for _ in range(5):
            det.observe(TelemetryRecord.from_ndjson(benign_gps()))
            det.observe(TelemetryRecord.from_ndjson(benign_ekf()))
        # 2차 공격 → 다시 발화
        det.observe(TelemetryRecord.from_ndjson(spoof_gps()))
        assert det.observe(TelemetryRecord.from_ndjson(spoof_ekf())) is not None


class TestOnboardAIDetector:
    """S8 온보드 인식 적대공격 탐지기."""

    def _benign(self) -> PerceptionRecord:
        return PerceptionRecord.from_ndjson(benign_perception())

    def _adversarial(self) -> PerceptionRecord:
        return PerceptionRecord.from_ndjson(adversarial_perception())

    def test_benign_no_alert(self) -> None:
        """정상 인식(클래스 일치·gap 작음)엔 경보 없음."""
        det = OnboardAIDetector()
        for _ in range(5):
            assert det.observe(self._benign()) is None

    def test_adversarial_fires_alert(self) -> None:
        """불일치+신뢰도 이상분포가 확정 스트릭만큼 지속되면 S8 경보."""
        det = OnboardAIDetector(confirm=2)
        det.observe(self._benign())
        first = det.observe(self._adversarial())  # streak 1 — 아직
        second = det.observe(self._adversarial())  # streak 2 — 발화
        assert first is None
        assert second is not None
        assert second.scenario_id == "AI-ONBOARD-EVADE-008"
        assert second.severity_baseline == Severity.MEDIUM
        assert second.asset_id == "PAYLOAD_EOIR"
        assert any("불일치" in s for s in second.signals)

    def test_mismatch_only_fires(self) -> None:
        """클래스 불일치만 있어도(신뢰도 gap 작아도) 지속 시 발화."""
        det = OnboardAIDetector(confirm=1)
        rec = PerceptionRecord.from_ndjson(
            {
                "UAVId": "MPD-001",
                "MsgType": "PERCEPTION_INFERENCE",
                "TargetId": "TGT-01",
                "EoClass": "vehicle",
                "IrClass": "bird",
                "EoConfidence": 0.80,
                "IrConfidence": 0.78,
            }
        )
        alert = det.observe(rec)
        assert alert is not None
        assert any("불일치" in s for s in alert.signals)

    def test_confidence_only_fires(self) -> None:
        """클래스 일치하지만 신뢰도 이상분포(gap≥0.15)만으로도 발화."""
        det = OnboardAIDetector(confirm=1)
        rec = PerceptionRecord.from_ndjson(
            {
                "UAVId": "MPD-001",
                "MsgType": "PERCEPTION_INFERENCE",
                "TargetId": "TGT-01",
                "EoClass": "vehicle",
                "IrClass": "vehicle",
                "EoConfidence": 0.90,
                "IrConfidence": 0.40,
            }
        )
        alert = det.observe(rec)
        assert alert is not None
        assert any("신뢰도" in s for s in alert.signals)

    def test_duplicate_suppressed(self) -> None:
        """동일 사건 중복 발화 억제."""
        det = OnboardAIDetector(confirm=1)
        first = det.observe(self._adversarial())
        second = det.observe(self._adversarial())
        assert first is not None
        assert second is None

    def test_auto_rearm_after_clean(self) -> None:
        """정상 복귀가 이어지면 재무장해 다음 공격을 다시 탐지(재촬영)."""
        det = OnboardAIDetector(confirm=1, rearm_after=3)
        assert det.observe(self._adversarial()) is not None  # 1차
        for _ in range(4):
            det.observe(self._benign())  # 정상 복귀 → 재무장
        assert det.observe(self._adversarial()) is not None  # 2차


class TestSimBridge:
    """브리지 → SOC 파이프라인(오프라인)."""

    @pytest.mark.asyncio
    async def test_stream_produces_soc_event(self) -> None:
        """합성 스트림 → 탐지 → 6-에이전트 처리 결과(BridgeEvent)."""
        bridge = SimBridge(retriever=None, llm=None)
        events = [e async for e in bridge.run_stream(synth_stream(benign_n=3))]
        assert len(events) == 1
        ev = events[0]
        assert ev.report.severity == Severity.HIGH
        assert ev.report.verdict == Verdict.TRUE_POSITIVE
        assert ev.report.recommended_action == "response"
        assert ev.alert.scenario_id == "UAV-GPS-SPOOF-001"

    @pytest.mark.asyncio
    async def test_run_alert_processes_onboard_alert(self) -> None:
        """OnboardAIDetector 탐지 → bridge.run_alert → S8 BridgeEvent(오프라인)."""
        bridge = SimBridge(retriever=None, llm=None)
        det = OnboardAIDetector(confirm=2)
        events = []
        async for rec in synth_perception_stream(benign_n=3):
            alert = det.observe(rec)
            if alert is not None:
                events.append(await bridge.run_alert(alert))
        assert len(events) == 1
        ev = events[0]
        assert ev.alert.scenario_id == "AI-ONBOARD-EVADE-008"
        # MBCRA: PAYLOAD_EOIR 는 on-station 핵심지형(KT-C) → key_terrain +1 격상 → HIGH.
        assert ev.report.severity == Severity.HIGH
        assert ev.report.verdict == Verdict.TRUE_POSITIVE


class _FakeOnboardActuator:
    """MAVLink 없이 호출 순서만 기록하는 가짜 작동기."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def send_loiter(self, uav_id: str) -> str:
        self.calls.append("loiter")
        return f"LOITER hold 송신({uav_id})"

    def send_rtb(self, uav_id: str) -> str:
        self.calls.append("rtb")
        return f"RTB 송신({uav_id})"


class TestHoldThenRtb:
    """자율교전 차단(hold) → 보수적 RTB 순서 작동."""

    def test_calls_loiter_then_rtb_in_order(self) -> None:
        """hold_then_rtb 는 LOITER 후 RTB 를 순서대로 호출하고 두 메시지를 반환."""
        fake = _FakeOnboardActuator()
        msgs = hold_then_rtb(fake, "MPD-001")
        assert fake.calls == ["loiter", "rtb"]
        assert len(msgs) == 2
        assert "LOITER" in msgs[0]
        assert "RTB" in msgs[1]
