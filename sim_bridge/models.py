"""telemetry-tap NDJSON 레코드 모델.

uav-sim-env `telemetry-tap/tap.py` 가 내보내는 NDJSON 한 줄에 대응. 탐지에 쓰는
필드만 둔다(나머지는 무시). 필드명은 telemetry-tap 스키마와 동일.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class TelemetryRecord(BaseModel):
    """telemetry-tap NDJSON 한 줄(탐지 관련 필드)."""

    model_config = ConfigDict(extra="ignore")

    time_generated: str = Field(default="", alias="TimeGenerated")
    uav_id: str = Field(default="UNKNOWN", alias="UAVId")
    msg_type: str = Field(default="", alias="MsgType")

    # EKF_STATUS_REPORT (S1 GNSS 스푸핑 핵심 신호 — 잔차 비율 + 글리치 플래그)
    pos_horiz_variance: float | None = Field(default=None, alias="PosHorizVariance")
    velocity_variance: float | None = Field(default=None, alias="VelocityVariance")
    compass_variance: float | None = Field(default=None, alias="CompassVariance")
    ekf_flags: int | None = Field(default=None, alias="EkfFlags")

    # GPS_RAW_INT
    fix_type: int | None = Field(default=None, alias="FixType")
    eph_cm: int | None = Field(default=None, alias="Eph_cm")
    satellites_visible: int | None = Field(default=None, alias="SatellitesVisible")

    @classmethod
    def from_ndjson(cls, data: dict[str, object]) -> TelemetryRecord:
        """NDJSON dict(원본 키) → TelemetryRecord."""
        return cls.model_validate(data)


class PerceptionRecord(BaseModel):
    """온보드 EO/IR 표적인식 추론 NDJSON 한 줄(S8 탐지 관련 필드).

    SITL 엔 실제 인식 모델이 없어 합성 스트림으로 대체한다. 필드명은 perception-tap
    NDJSON 스키마(가상)와 동일하게 별칭으로 매핑한다.
    """

    model_config = ConfigDict(extra="ignore")

    time_generated: str = Field(default="", alias="TimeGenerated")
    uav_id: str = Field(default="UNKNOWN", alias="UAVId")
    msg_type: str = Field(default="", alias="MsgType")
    target_id: str = Field(default="", alias="TargetId")

    # 다중센서 융합 — EO(가시) vs IR(열) 표적 클래스/신뢰도
    eo_class: str | None = Field(default=None, alias="EoClass")
    ir_class: str | None = Field(default=None, alias="IrClass")
    eo_conf: float | None = Field(default=None, alias="EoConfidence")
    ir_conf: float | None = Field(default=None, alias="IrConfidence")

    @classmethod
    def from_ndjson(cls, data: dict[str, object]) -> PerceptionRecord:
        """NDJSON dict(원본 키) → PerceptionRecord."""
        return cls.model_validate(data)


class GcsAccessRecord(BaseModel):
    """noVNC/VNC/QGC GCS 원격접속 세션 1건 — `UAVGcsAccess_CL` 스키마 미러.

    `deploy/sentinel-tables/UAVGcsAccess_CL.json` 컬럼/타입과 1:1 매칭. Logs
    Ingestion API 로 보낼 행을 `model_dump(by_alias=True)` 로 생성한다.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    time_generated: str = Field(alias="TimeGenerated")
    session_id: str = Field(alias="SessionId")
    client_ip: str = Field(alias="ClientIp")
    transport: str = Field(alias="Transport")
    operator: str = Field(alias="Operator")
    action: str = Field(alias="Action")
    user_agent: str = Field(alias="UserAgent")
    bytes_sent: int = Field(alias="BytesSent")
    bytes_received: int = Field(alias="BytesReceived")
    duration_sec: float = Field(alias="DurationSec")
    result: str = Field(alias="Result")

    def to_row(self) -> dict[str, object]:
        """Logs Ingestion API POST 용 dict(원본 컬럼명)."""
        return self.model_dump(by_alias=True)
