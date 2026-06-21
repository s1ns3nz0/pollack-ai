"""sim_bridge 테스트 — 탐지기 + 브리지(합성 텔레메트리, 오프라인).

RAG/LLM 없이(None) 결정론적으로 검증한다.
"""

import pytest

from core.models import Severity, Verdict
from sim_bridge.bridge import SimBridge
from sim_bridge.detector import GpsSpoofDetector
from sim_bridge.models import TelemetryRecord
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
        assert ev.report.action_taken == "response"
        assert ev.alert.scenario_id == "UAV-GPS-SPOOF-001"
