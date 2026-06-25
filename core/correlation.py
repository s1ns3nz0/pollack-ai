"""다중경보 상관·집약 (S9 군집 포화 / SOC 과부하 대응).

개별 경보 N건을 한 곳에 모아(슬라이딩 윈도우) **경보 폭주(alert storm)** 와 **다축
동시침해(multi-axis)** 를 상관 탐지하고, 하나의 집약 인시던트로 묶는다. 운용자·탐지
과부하를 완화하고(경보 집약), 다축 상관 시 등급을 상향한다.

`SOC_Alert_Stream_CL`(S1~S11 개별 룰 출력의 통합 스트림)의 런타임 구현부에 해당하며,
집약 결과를 `to_aggregate_alert()` 로 S9 경보(`UAV-SWARM-SATURATION-009`)로 변환해
기존 6-에이전트 파이프라인에 그대로 투입할 수 있다.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime

from pydantic import BaseModel, Field

from core.models import Alert, Severity, Verdict

_S9_SCENARIO = "UAV-SWARM-SATURATION-009"
_S9_PLAYBOOK: dict[str, object] = {
    "id": "PB-SWARM-AGGREGATE-09",
    "actions": [
        "경보 집약 — 다축 클러스터를 단일 인시던트로 승급",
        "상위자산 lateral 에스컬레이션",
        "탐지 게이트 완화(과부하 시 우선순위 큐 운영)",
    ],
    "failover": "운용자 과부하 시 자동대응 우선순위 큐로 분산",
}


class CorrelatedIncident(BaseModel):
    """다수 경보를 집약한 상관 인시던트."""

    id: str
    pattern: str  # "alert_storm" | "multi_axis"
    count: int
    distinct_assets: int
    distinct_scenarios: int
    window_sec: float
    member_alert_ids: list[str] = Field(default_factory=list)
    member_scenarios: list[str] = Field(default_factory=list)


class AlertCorrelator:
    """경보 스트림을 슬라이딩 윈도우로 상관·집약한다.

    Args:
        window_sec: 상관 윈도우(초). 이 안의 경보를 한 묶음으로 본다.
        storm_count: 윈도우 내 경보 수가 이 값 이상이면 경보 폭주.
        multi_axis_assets: 윈도우 내 서로 다른 자산 수가 이 값 이상이면 다축 동시침해.
    """

    def __init__(
        self,
        window_sec: float = 300.0,
        storm_count: int = 5,
        multi_axis_assets: int = 3,
    ) -> None:
        self._window_sec = window_sec
        self._storm_count = storm_count
        self._multi_axis_assets = multi_axis_assets
        self._window: deque[tuple[datetime, Alert]] = deque()
        self._fired = False

    def observe(self, alert: Alert, now: datetime) -> CorrelatedIncident | None:
        """경보 한 건을 윈도우에 넣고, 상관 패턴이 새로 확정되면 인시던트 반환.

        Args:
            alert: 입력 경보.
            now: 관측 시각.

        Returns:
            폭주/다축 패턴이 새로 확정되면 `CorrelatedIncident`, 아니면 None
            (임계 미만이면 재무장).
        """
        self._window.append((now, alert))
        while (
            self._window
            and (now - self._window[0][0]).total_seconds() > self._window_sec
        ):
            self._window.popleft()

        members = [a for _, a in self._window]
        assets = {a.asset_id for a in members}
        scenarios = {a.scenario_id for a in members}
        multi = len(assets) >= self._multi_axis_assets
        storm = len(members) >= self._storm_count

        if not (multi or storm):
            self._fired = False  # 임계 아래로 떨어지면 재무장(다음 군집 탐지)
            return None
        if self._fired:
            return None  # 동일 군집 중복 발화 억제
        self._fired = True
        return CorrelatedIncident(
            id=f"CORR-{_S9_SCENARIO}-{len(members)}",
            pattern="multi_axis" if multi else "alert_storm",
            count=len(members),
            distinct_assets=len(assets),
            distinct_scenarios=len(scenarios),
            window_sec=self._window_sec,
            member_alert_ids=[a.id for a in members],
            member_scenarios=sorted(scenarios),
        )

    def to_aggregate_alert(self, incident: CorrelatedIncident) -> Alert:
        """집약 인시던트를 S9 경보로 변환(파이프라인 투입용).

        다축 동시침해는 조율된 공격이므로 baseline h + lateral_correlation 으로
        등급 상향을 유도한다.

        Args:
            incident: 집약 인시던트.

        Returns:
            S9(`UAV-SWARM-SATURATION-009`) 경보.
        """
        return Alert(
            id=incident.id,
            scenario_id=_S9_SCENARIO,
            title="군집 포화 — 다축 동시침해 및 SOC 과부하(집약)",
            asset_id="AI_SOC",
            asset_tier="T0-AISOC",
            mission_phase="on-station",
            severity_baseline=Severity.HIGH,
            signals=[
                f"경보 {incident.count}건 {incident.window_sec:.0f}초 내 집약",
                f"다축 {incident.distinct_assets}자산 동시침해",
                f"시나리오 {', '.join(incident.member_scenarios)}",
            ],
            mitre={"attack_ics": ["T0814", "T0855"]},
            expected_detection={"sigma_rule": "swarm_saturation_alertstorm.yml"},
            defense_playbook=_S9_PLAYBOOK,
            ground_truth=Verdict.TRUE_POSITIVE,
            lateral_correlation=incident.pattern == "multi_axis",
        )

    def reset(self) -> None:
        """윈도우·발화 상태 초기화."""
        self._window.clear()
        self._fired = False
