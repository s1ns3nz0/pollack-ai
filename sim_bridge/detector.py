"""실시간 GPS 스푸핑(S1) 탐지기.

telemetry-tap 스트림에서 EKF 이상(PosHorizVariance/VelocityVariance 급증 **또는**
ArduPilot EKF GPS-글리치 플래그)과 GPS 품질 저하(Eph 급증 / 위성수 급감)를 결합해
GNSS 스푸핑을 탐지하고 `Alert` 를 만든다. 클라우드 측 Sentinel 분석룰
`S1_GNSS_Spoofing`(dah-sentinel-content, `UAVTelemetry_CL` 대상)의 런타임 근사판.

[실 SITL 검증 메모] Sentinel 룰은 PosHorizVariance AND VelocityVariance 둘 다
>0.05(z-score 3σ)를 요구하나, 실측 온셋에서 VelocityVariance 는 ~0.043 으로 게이트
미달(PosHorizVariance 는 ~4.8 로 충분). 본 런타임 탐지기는 EKF GPS_GLITCHING 플래그와
위성 급감을 추가로 결합해 그 사각을 보완한다. → docs/sim-validation-findings.md

EKF 신호와 GPS 신호는 **서로 다른 메시지 타입**(EKF_STATUS_REPORT / GPS_RAW_INT)으로
도착하므로, 단일 레코드가 아니라 메시지 타입을 가로질러 상태로 누적해 결합 판정한다.
실 ArduPilot SITL 에서는 일관된 GPS 글리치를 EKF 가 부드럽게 흡수해 잔차가 크게 튀지
않는 대신 **EKF_STATUS_REPORT 플래그의 GPS_GLITCHING 비트(0x8000)** 가 켜진다 —
이것이 실 시뮬의 1차 신호다.
"""

from __future__ import annotations

from core.models import Alert, Severity, Verdict
from sim_bridge.models import PerceptionRecord, TelemetryRecord
from utils.logging import get_logger

# ArduPilot EKF_STATUS_REPORT.flags 확장 비트 — GPS 글리치 감지(표준 enum 외 추가 비트).
EKF_GPS_GLITCHING = 0x8000

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
        expected_detection={
            "sigma_rule": "uav_gps_spoof_residual.yml",
            "sentinel_rule": "S1_GNSS_Spoofing",  # dah-sentinel-content/AnalyticsRules
        },
        defense_playbook=_S1_PLAYBOOK,
        ground_truth=Verdict.TRUE_POSITIVE,
    )


class GpsSpoofDetector:
    """EKF 이상 + GPS 품질 결합 GNSS 스푸핑 탐지기(상태 기반).

    EKF 신호(`EKF_STATUS_REPORT`)와 GPS 신호(`GPS_RAW_INT`)가 별도 메시지로 오므로
    각 신호를 상태에 누적해 두고, 매 레코드마다 결합 조건을 재평가한다. 발화 조건은
    **EKF 이상 1개 이상 + 전체 신호 2개 이상**(EKF 단독 오탐 방지).

    실 ArduPilot 의 EKF 이상(잔차 급증·글리치 플래그)은 스푸핑 **온셋 순간에만 잠깐**
    나타나고 곧 흡수되는 반면, 위성 급감 같은 GPS 열화는 지속된다. 두 신호가 정확히
    같은 레코드에서 겹치지 않아도 결합되도록 EKF 이상을 `corr_window` 레코드 동안
    유지(상관 윈도우)한다.

    Args:
        pos_var_threshold: PosHorizVariance/VelocityVariance 경보 임계(정상 ~0.2~0.5).
        eph_jump_cm: 직전 대비 Eph 급증 임계(cm).
        min_satellites: 위성수 하한(미만이면 의심).
        corr_window: EKF 이상을 GPS 신호와 상관시키려 유지할 레코드 수
            (telemetry ~6Hz 기준 40 ≈ 6~7초).
    """

    def __init__(
        self,
        pos_var_threshold: float = 0.8,
        eph_jump_cm: int = 300,
        min_satellites: int = 7,
        corr_window: int = 40,
        rearm_after: int = 30,
    ) -> None:
        self._pos_var_threshold = pos_var_threshold
        self._eph_jump_cm = eph_jump_cm
        self._min_satellites = min_satellites
        self._corr_window = corr_window
        self._rearm_after = rearm_after
        self._last_eph: int | None = None
        self._ekf_signal: str | None = None
        self._ekf_ttl = 0
        self._gps_signals: list[str] = []
        self._fired = False
        self._clean_streak = 0
        self._logger = get_logger("GpsSpoofDetector")

    def observe(self, record: TelemetryRecord) -> Alert | None:
        """레코드 한 건으로 상태를 갱신하고, 스푸핑이 새로 확정되면 Alert 반환.

        Args:
            record: telemetry-tap 레코드(EKF_STATUS_REPORT / GPS_RAW_INT).

        Returns:
            새 탐지면 `Alert`, 아니면 None(중복 발화 억제).
        """
        if record.msg_type == "EKF_STATUS_REPORT":
            self._update_ekf(record)
        elif record.msg_type == "GPS_RAW_INT":
            self._update_gps(record)

        # 상관 윈도우: EKF 이상을 일정 레코드 유지(온셋 트랜지언트↔지속 GPS 결합).
        if self._ekf_ttl > 0:
            self._ekf_ttl -= 1
            if self._ekf_ttl == 0:
                self._ekf_signal = None

        signals = ([self._ekf_signal] if self._ekf_signal else []) + self._gps_signals

        # 자동 재무장: 텔레메트리가 일정 기간 정상으로 돌아오면 다음 사건을 다시 탐지.
        # (사건 종료 후 재촬영/반복 시 브리지 재시작 없이 재사용 가능)
        if not signals:
            self._clean_streak += 1
            if self._fired and self._clean_streak >= self._rearm_after:
                self._fired = False
                self._logger.info("정상 복귀 — 탐지기 재무장")
        else:
            self._clean_streak = 0

        if self._ekf_signal is not None and len(signals) >= 2:
            if self._fired:
                return None  # 동일 사건 중복 발화 억제
            self._fired = True
            self._logger.info("GPS 스푸핑 탐지: %s | %s", record.uav_id, signals)
            return _build_alert(record.uav_id, signals)
        return None

    def _update_ekf(self, record: TelemetryRecord) -> None:
        """EKF 이상(잔차 급증/글리치 플래그) 감지 시 신호 설정 + 상관 윈도우 무장.

        이상이 없는 정상 레코드에서는 즉시 지우지 않고 윈도우(TTL) 만료에 맡긴다 —
        온셋 트랜지언트가 짧아도 지속 GPS 신호와 결합되도록.
        """
        phv = record.pos_horiz_variance
        vv = record.velocity_variance
        signal: str | None = None
        if record.ekf_flags is not None and record.ekf_flags & EKF_GPS_GLITCHING:
            signal = "EKF GPS 글리치 플래그(0x8000) 설정됨"
        elif phv is not None and phv >= self._pos_var_threshold:
            signal = f"EKF PosHorizVariance 급증({phv:.2f}≥{self._pos_var_threshold})"
        elif vv is not None and vv >= self._pos_var_threshold:
            signal = f"EKF VelocityVariance 급증({vv:.2f})"
        if signal is not None:
            self._ekf_signal = signal
            self._ekf_ttl = self._corr_window

    def _update_gps(self, record: TelemetryRecord) -> None:
        """GPS_RAW_INT 신호(Eph 급증 / 위성수 급감) 갱신."""
        signals: list[str] = []
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
        self._gps_signals = signals

    def reset(self) -> None:
        """사건 종료 후 재무장."""
        self._fired = False
        self._last_eph = None
        self._ekf_signal = None
        self._ekf_ttl = 0
        self._gps_signals = []
        self._clean_streak = 0


# S8 시나리오 매핑(고정) — projects/dah2026/scenarios/S8-onboard-ai-evade.yaml
_S8_PLAYBOOK: dict[str, object] = {
    "id": "PB-ONBOARDAI-08",
    "actions": [
        "다중센서 융합 교차검증, 불일치 표적 보류",
        "탐지 신뢰도 이상 시 자율교전 차단 + HITL 표적확인",
        "적대적 견고화(robust) 모델/입력 정규화 런타임 방어",
        "인식 신뢰 불가 시 보수적 RTB",
    ],
    "onboard_defense": [
        "메타 AI 가 주 비전모델 출력 신뢰도·판단 패턴 상시 감시(AI 가 AI 를 감시)",
        "적대 의심 시 경량 백업 비전모델 자동 전환 + 주 모델 격리",
    ],
    "failover": "인식 신뢰 불가 시 자율교전 금지, 보수적 RTB 후 운용자 수동 식별",
    "hitl": "severity=m → 자율교전 차단 후 표적확인",
}


def _build_onboard_alert(uav_id: str, signals: list[str]) -> Alert:
    return Alert(
        id=f"SIM-{uav_id}-ONBOARDAI",
        scenario_id="AI-ONBOARD-EVADE-008",
        title="온보드 표적인식 AI 적대공격 의심 (시뮬 실시간 탐지)",
        asset_id="PAYLOAD_EOIR",
        asset_tier="T2-Important",
        mission_phase="on-station",
        severity_baseline=Severity.MEDIUM,
        signals=signals,
        mitre={"atlas": ["AML.T0015-EvadeMLModel", "AML.T0043-CraftAdversarialData"]},
        expected_detection={"sigma_rule": "onboard_ai_adversarial_evade.yml"},
        defense_playbook=_S8_PLAYBOOK,
        ground_truth=Verdict.TRUE_POSITIVE,
    )


class OnboardAIDetector:
    """다중센서(EO/IR) 표적 불일치 + 탐지 신뢰도 이상분포 결합 S8 탐지기.

    yaml `expected_detection.logic`("센서간 표적 불일치 OR 탐지 신뢰도 이상분포 시
    적대 공격 의심 → HITL 승급")을 런타임 근사한다. 단발 오탐을 막기 위해 신호가
    `confirm` 레코드 연속 지속될 때만 발화하고, `_fired` 로 중복을 억제하며, 정상
    복귀가 `rearm_after` 만큼 이어지면 자동 재무장한다(재촬영 대비 — GpsSpoofDetector
    와 동일 패턴).

    Args:
        conf_gap_threshold: |EO신뢰도 − IR신뢰도| 이상분포 임계(FULL-EXPORT
            MaxConfidenceGap_d=0.15).
        confirm: 발화 전 신호가 연속 지속되어야 하는 레코드 수(트랜지언트 오탐 방지).
        rearm_after: 정상 복귀가 이어지면 재무장할 정상 레코드 수.
    """

    def __init__(
        self,
        conf_gap_threshold: float = 0.15,
        confirm: int = 2,
        rearm_after: int = 10,
    ) -> None:
        self._conf_gap_threshold = conf_gap_threshold
        self._confirm = confirm
        self._rearm_after = rearm_after
        self._signal_streak = 0
        self._clean_streak = 0
        self._fired = False
        self._logger = get_logger("OnboardAIDetector")

    def observe(self, record: PerceptionRecord) -> Alert | None:
        """인식 레코드 한 건으로 상태를 갱신하고, 적대공격이 새로 확정되면 Alert 반환.

        Args:
            record: 온보드 EO/IR 인식 추론 레코드.

        Returns:
            새 탐지면 `Alert`, 아니면 None(중복/미확정 억제).
        """
        signals = self._evaluate(record)
        if not signals:
            self._signal_streak = 0
            self._clean_streak += 1
            if self._fired and self._clean_streak >= self._rearm_after:
                self._fired = False
                self._logger.info("정상 복귀 — 탐지기 재무장")
            return None

        self._clean_streak = 0
        self._signal_streak += 1
        if self._signal_streak < self._confirm:
            return None
        if self._fired:
            return None  # 동일 사건 중복 발화 억제
        self._fired = True
        self._logger.info("온보드 인식 적대공격 탐지: %s | %s", record.uav_id, signals)
        return _build_onboard_alert(record.uav_id, signals)

    def _evaluate(self, record: PerceptionRecord) -> list[str]:
        """레코드에서 S8 신호(센서 불일치 / 신뢰도 이상분포)를 추출."""
        signals: list[str] = []
        if (
            record.eo_class is not None
            and record.ir_class is not None
            and record.eo_class != record.ir_class
        ):
            signals.append(
                f"EO/IR 표적 불일치(EO={record.eo_class} vs IR={record.ir_class})"
            )
        if record.eo_conf is not None and record.ir_conf is not None:
            gap = abs(record.eo_conf - record.ir_conf)
            if gap >= self._conf_gap_threshold:
                signals.append(
                    f"탐지 신뢰도 이상분포(gap={gap:.2f}≥{self._conf_gap_threshold})"
                )
        return signals

    def reset(self) -> None:
        """사건 종료 후 재무장."""
        self._signal_streak = 0
        self._clean_streak = 0
        self._fired = False
