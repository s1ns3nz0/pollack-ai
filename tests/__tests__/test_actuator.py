"""sim_bridge.actuator 테스트 — RTB 판정 + MAVLink 작동기(연결 mock).

실제 SITL 없이 pymavlink 연결을 mock 으로 치환해 결정론적으로 검증한다.
"""

import importlib
from unittest.mock import MagicMock, patch

import pytest

from core.models import Severity, SOCReport, Verdict
from sim_bridge.actuator import ActuatorError, MavlinkActuator, rtb_recommended

# `from pymavlink import mavutil` 가 런타임 임포트라, patch 대상이 미리 존재하도록 로드.
importlib.import_module("pymavlink.mavutil")


def _report(verdict: Verdict) -> SOCReport:
    return SOCReport(
        alert_id="SIM-UAV-GPSSPOOF",
        scenario_id="UAV-GPS-SPOOF-001",
        title="GPS 스푸핑",
        severity=Severity.HIGH,
        verdict=verdict,
        action_taken="response" if verdict == Verdict.TRUE_POSITIVE else "rule_update",
    )


class TestRtbRecommended:
    """RTB 작동 판정 로직."""

    def test_true_positive_with_rtb_playbook(self) -> None:
        """정탐 + RTB 포함 플레이북 → True."""
        pb: dict[str, object] = {
            "failover": "INS 단독 항법으로 즉시 전환 후 RTB",
            "actions": [],
        }
        assert rtb_recommended(_report(Verdict.TRUE_POSITIVE), pb) is True

    def test_false_positive_never_actuates(self) -> None:
        """오탐이면 RTB 플레이북이라도 작동 안 함."""
        pb: dict[str, object] = {"failover": "INS 전환 후 RTB", "actions": []}
        assert rtb_recommended(_report(Verdict.FALSE_POSITIVE), pb) is False

    def test_true_positive_without_rtb(self) -> None:
        """정탐이라도 RTB 가 없는 플레이북엔 작동 안 함."""
        pb: dict[str, object] = {"failover": "운용자 알림만", "actions": ["로그 보존"]}
        assert rtb_recommended(_report(Verdict.TRUE_POSITIVE), pb) is False

    def test_rtb_in_actions(self) -> None:
        """failover 가 비어도 actions 에 RTB 가 있으면 True."""
        pb: dict[str, object] = {
            "failover": "",
            "actions": ["운용자 경보 + 자동 RTB 후보 경로 제시"],
        }
        assert rtb_recommended(_report(Verdict.TRUE_POSITIVE), pb) is True


class TestMavlinkActuator:
    """MAVLink RTB 송신(연결 mock)."""

    def test_send_rtb_emits_rtl_command(self) -> None:
        """HEARTBEAT 수신 후 RETURN_TO_LAUNCH COMMAND_LONG 을 송신한다."""
        fake_conn = MagicMock()
        fake_conn.wait_heartbeat.return_value = MagicMock()  # not None
        fake_conn.target_system = 1
        fake_conn.target_component = 1
        with patch("pymavlink.mavutil") as mavutil:
            mavutil.mavlink_connection.return_value = fake_conn
            mavutil.mavlink.MAV_CMD_NAV_RETURN_TO_LAUNCH = 20
            result = MavlinkActuator().send_rtb(uav_id="SIM-UAV")
        fake_conn.mav.command_long_send.assert_called_once()
        args = fake_conn.mav.command_long_send.call_args.args
        assert args[2] == 20  # MAV_CMD_NAV_RETURN_TO_LAUNCH
        assert "RETURN_TO_LAUNCH" in result

    def test_no_heartbeat_raises(self) -> None:
        """HEARTBEAT 타임아웃 시 ActuatorError."""
        fake_conn = MagicMock()
        fake_conn.wait_heartbeat.return_value = None
        with patch("pymavlink.mavutil") as mavutil:
            mavutil.mavlink_connection.return_value = fake_conn
            with pytest.raises(ActuatorError):
                MavlinkActuator(heartbeat_timeout=0.1).send_rtb(uav_id="X")

    def test_connection_error_wrapped(self) -> None:
        """소켓 오류(OSError)는 ActuatorError 로 래핑된다."""
        with patch("pymavlink.mavutil") as mavutil:
            mavutil.mavlink_connection.side_effect = ConnectionRefusedError("거부됨")
            with pytest.raises(ActuatorError):
                MavlinkActuator().send_rtb(uav_id="X")
