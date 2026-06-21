"""SOC 결정 → 시뮬 폐루프 작동기(actuator).

telemetry-tap 입력의 역방향. SOC 6-에이전트가 정탐(RTB)을 판정하면 MAVLink
COMMAND_LONG(MAV_CMD_NAV_RETURN_TO_LAUNCH)을 av-mpd(ArduPilot SITL)에 송신해
드론을 실제 복귀시킨다 — '권고만 출력'에서 '실제 작동'으로. QGroundControl
(noVNC)에서 복귀가 시각화된다.

작동기는 `RtbActuator` Protocol 로 추상화되어 테스트/오프라인에서 mock 치환된다.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from core.exceptions import SOCPlatformError
from core.models import SOCReport, Verdict
from utils.logging import get_logger


class ActuatorError(SOCPlatformError):
    """폐루프 작동기 오류(연결/송신 실패)."""


def rtb_recommended(report: SOCReport, playbook: dict[str, object]) -> bool:
    """SOC 결과가 RTB(자동 복귀) 작동을 요구하는지 판정한다.

    정탐(TRUE_POSITIVE)이고 플레이북의 failover/actions 에 RTB 가 포함될 때만 True.
    오탐이거나 RTB 가 없는 플레이북에는 작동을 걸지 않는다.

    Args:
        report: SOC 최종 리포트(verdict 포함).
        playbook: 경보의 방어 플레이북(failover/actions 키 포함).

    Returns:
        RTB 명령을 송신해야 하면 True, 아니면 False.
    """
    if report.verdict != Verdict.TRUE_POSITIVE:
        return False
    failover = str(playbook.get("failover", ""))
    raw_actions = playbook.get("actions", [])
    actions = raw_actions if isinstance(raw_actions, list) else []
    text = f"{failover} {' '.join(str(a) for a in actions)}"
    return "RTB" in text.upper()


@runtime_checkable
class RtbActuator(Protocol):
    """RTB 명령 송신 인터페이스(테스트 시 mock 치환 가능)."""

    def send_rtb(self, uav_id: str) -> str:
        """RTB(자동 복귀) 명령을 기체에 송신하고 사람이 읽을 결과 문자열을 반환한다."""
        ...


class MavlinkActuator:
    """av-mpd(ArduPilot SITL)로 MAVLink RTB 명령을 송신하는 작동기.

    Args:
        connection: MAVLink 접속 문자열(기본 av-mpd SITL 직접 포트).
        heartbeat_timeout: HEARTBEAT 대기 한도(초).
    """

    def __init__(
        self,
        connection: str = "tcp:127.0.0.1:5760",
        heartbeat_timeout: float = 30.0,
    ) -> None:
        self._connection = connection
        self._heartbeat_timeout = heartbeat_timeout
        self._logger = get_logger("MavlinkActuator")

    def send_rtb(self, uav_id: str) -> str:
        """기체에 RETURN_TO_LAUNCH(자동 복귀) 명령을 송신한다.

        Args:
            uav_id: 대상 기체 식별자(로깅용).

        Returns:
            송신 결과 요약 문자열(대시보드 출력용).

        Raises:
            ActuatorError: HEARTBEAT 수신 실패 또는 MAVLink 송신 오류 시.
        """
        from pymavlink import mavutil  # 지연 임포트(오프라인/테스트 시 불요)

        try:
            conn = mavutil.mavlink_connection(self._connection)
            if conn.wait_heartbeat(timeout=self._heartbeat_timeout) is None:
                raise ActuatorError(
                    f"HEARTBEAT 수신 실패(타임아웃): {self._connection}"
                )
            conn.mav.command_long_send(
                conn.target_system,
                conn.target_component,
                mavutil.mavlink.MAV_CMD_NAV_RETURN_TO_LAUNCH,
                0,  # confirmation
                0,
                0,
                0,
                0,
                0,
                0,
                0,  # param1~7 (RTL 은 파라미터 불요)
            )
            self._logger.info(
                "RTB 송신: uav=%s via %s (sys=%s)",
                uav_id,
                self._connection,
                conn.target_system,
            )
            return (
                f"MAVLink RETURN_TO_LAUNCH 송신 완료 "
                f"(sys={conn.target_system}, via {self._connection})"
            )
        except OSError as e:
            raise ActuatorError(f"RTB 송신 실패({self._connection}): {e}") from e
