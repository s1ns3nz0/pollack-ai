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
