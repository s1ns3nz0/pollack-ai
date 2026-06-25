"""mavlink_source — MAVLink 메시지 → TelemetryRecord 매핑 검증."""

from sim_bridge.detector import GpsSpoofDetector
from sim_bridge.mavlink_source import mav_to_record


class TestMavToRecord:
    """MAVLink dict → TelemetryRecord 필드 매핑."""

    def test_ekf_status_mapping(self) -> None:
        """EKF_STATUS_REPORT 의 flags/잔차가 매핑된다."""
        r = mav_to_record(
            "EKF_STATUS_REPORT",
            {
                "flags": 33599,
                "pos_horiz_variance": 4.7,
                "velocity_variance": 0.04,
                "compass_variance": 0.1,
            },
        )
        assert r.msg_type == "EKF_STATUS_REPORT"
        assert r.ekf_flags == 33599
        assert r.pos_horiz_variance == 4.7

    def test_gps_raw_mapping(self) -> None:
        """GPS_RAW_INT 의 fix/eph/위성수가 매핑된다."""
        r = mav_to_record(
            "GPS_RAW_INT",
            {"fix_type": 6, "eph": 121, "satellites_visible": 5},
        )
        assert r.msg_type == "GPS_RAW_INT"
        assert r.eph_cm == 121
        assert r.satellites_visible == 5

    def test_mapped_records_drive_detector(self) -> None:
        """매핑된 레코드로 탐지기가 실제 발화(글리치 플래그 + 위성 급감)."""
        det = GpsSpoofDetector()
        det.observe(
            mav_to_record(
                "GPS_RAW_INT", {"fix_type": 6, "eph": 121, "satellites_visible": 14}
            )
        )
        det.observe(
            mav_to_record(
                "GPS_RAW_INT", {"fix_type": 6, "eph": 121, "satellites_visible": 5}
            )
        )
        alert = det.observe(
            mav_to_record(
                "EKF_STATUS_REPORT",
                {"flags": 33599, "pos_horiz_variance": 0.05, "velocity_variance": 0.04},
            )
        )
        assert alert is not None
        assert alert.scenario_id == "UAV-GPS-SPOOF-001"
