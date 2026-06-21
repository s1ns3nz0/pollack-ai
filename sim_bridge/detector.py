"""실시간 GPS 스푸핑(S1) 탐지기.

telemetry-tap 스트림에서 EKF 잔차(PosHorizVariance/VelocityVariance) 급증 +
GPS 품질 저하(Eph 급증 / 위성수 급감)를 결합해 GNSS 스푸핑을 탐지하고 `Alert` 를
만든다. Sigma 룰 `uav_gps_spoof_residual.yml`(김수지 lane)의 런타임 근사판.

상태 기반(직전 정상 기준선 대비 급변)이라 단일 레코드가 아니라 스트림으로 본다.
"""

from __future__ import annotations

from core.models import Alert, Severity, Verdict
from sim_bridge.models import TelemetryRecord
from utils.logging import get_logger

# S1 시나리오 매핑(고정)
_S1_PLAYBOOK: dict[str, object] = {
    "id": "PB-NAV-RTB-01",
    "actions": [
        "GNSS 신뢰도 강등, INS/관성항법으로 페일오버",
        "마지막 신뢰 좌표 기준 항법 재계산",
        "운용자 경보 + 자동 RTB 후보 경로 제시",
    ],
    "failover": "INS 단독 항법으로 즉시 전환 후 RTB",
    "onboard_defense": [
        "온보드 센서퓨전(GPS-IMU 교차검증)으로 통신 없이 GPS 자율 강등",
    ],
}


def _build_alert(uav_id: str, signals: list[str]) -> Alert:
    return Alert(
        id=f"SIM-{uav_id}-GPSSPOOF",
        scenario_id="UAV-GPS-SPOOF-001",
        title="GPS/GNSS 스푸핑 의심 (시뮬 실시간 탐지)",
        asset_id="GNSS",
        asset_tier="T1-Critical",
        mission_phase="on-station",
        severity_baseline=Severity.HIGH,
        signals=signals,
        mitre={"attack_ics": ["T0830-AiTM", "T0856-SpoofReportingMessage"]},
        expected_detection={"sigma_rule": "uav_gps_spoof_residual.yml"},
        defense_playbook=_S1_PLAYBOOK,
        ground_truth=Verdict.TRUE_POSITIVE,
    )


class GpsSpoofDetector:
    """EKF 잔차 + GPS 품질 결합 GNSS 스푸핑 탐지기.

    Args:
        pos_var_threshold: PosHorizVariance 경보 임계(정상 ~0.2~0.5).
        eph_jump_cm: 직전 대비 Eph 급증 임계(cm).
        min_satellites: 위성수 하한(미만이면 의심 가중).
    """

    def __init__(
        self,
        pos_var_threshold: float = 0.8,
        eph_jump_cm: int = 300,
        min_satellites: int = 7,
    ) -> None:
        self._pos_var_threshold = pos_var_threshold
        self._eph_jump_cm = eph_jump_cm
        self._min_satellites = min_satellites
        self._last_eph: int | None = None
        self._fired = False
        self._logger = get_logger("GpsSpoofDetector")

    def observe(self, record: TelemetryRecord) -> Alert | None:
        """레코드 한 건을 보고, 스푸핑 패턴이 새로 확정되면 Alert 반환.

        Args:
            record: telemetry-tap 레코드.

        Returns:
            새 탐지면 `Alert`, 아니면 None(중복 발화 억제).
        """
        signals: list[str] = []

        phv = record.pos_horiz_variance
        if phv is not None and phv >= self._pos_var_threshold:
            signals.append(
                f"EKF PosHorizVariance 급증({phv:.2f}≥{self._pos_var_threshold})"
            )
        vv = record.velocity_variance
        if vv is not None and vv >= self._pos_var_threshold:
            signals.append(f"EKF VelocityVariance 급증({vv:.2f})")
        if record.eph_cm is not None:
            if (
                self._last_eph is not None
                and record.eph_cm - self._last_eph >= self._eph_jump_cm
            ):
                signals.append(f"GPS Eph 급증(+{record.eph_cm - self._last_eph}cm)")
            self._last_eph = record.eph_cm
        sats = record.satellites_visible
        if sats is not None and sats < self._min_satellites:
            signals.append(f"위성수 급감({sats}<{self._min_satellites})")

        ekf_fired = any(s.startswith("EKF") for s in signals)
        if ekf_fired and len(signals) >= 2:
            if self._fired:
                return None  # 동일 사건 중복 발화 억제
            self._fired = True
            self._logger.info("GPS 스푸핑 탐지: %s | %s", record.uav_id, signals)
            return _build_alert(record.uav_id, signals)
        return None

    def reset(self) -> None:
        """사건 종료 후 재무장."""
        self._fired = False
        self._last_eph = None
