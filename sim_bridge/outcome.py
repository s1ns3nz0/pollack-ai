"""OutcomeProbe — 대응 후 시뮬 텔레메트리로 환경검증 라벨을 산정한다.

본선은 사람 개입이 없어(HITL 불가) 자가발전이 필수다. OutcomeProbe 는 사람 서명
대신 *시뮬 환경의 실제 결과*를 신뢰 심판으로 삼는다. 경보 텍스트는 적이 조작할 수
있어도 기체에 벌어진 물리적 결과(EKF 잔차/GPS 품질의 지속·회복)는 조작할 수 없다.

비대칭 설계:
- 물리 효과가 관측되면 `CONFIRMED_TP`(탐지 학습 — 안전).
- 충분히 긴 윈도우 내내 효과가 없으면 `CONFIRMED_FP`(억제 학습 — 위험하므로 보수적).
- 애매하면 `INCONCLUSIVE`(메모리에 적지 않음 — 적이 노리는 회색지대 배제).

`core/dynamics.py` 의 원칙("`no_effect_sustained` 는 효과 관측이 필요해 시간만으로
자동 도출하지 않는다")을 어기지 않고 충족한다 — 시간이 아니라 실제 효과 관측으로
판정한다. → docs/adr/0002-autonomous-self-improving-blue-soc.md
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, Field

from core.models import EnvVerdict
from sim_bridge.detector import EKF_GPS_GLITCHING
from sim_bridge.models import TelemetryRecord
from utils.logging import get_logger


class OutcomeAssessment(BaseModel):
    """OutcomeProbe 판정 결과(감사/KPI 용 근거 포함).

    Attributes:
        env_verdict: 환경검증 라벨.
        sustained_effect_records: 위협 신호가 연속 지속된 최대 레코드 수.
        observations: 관측 윈도우 길이(레코드 수).
        rationale: 사람이 읽을 판정 근거(감사용 — 메모리 적립 대상 아님).
    """

    env_verdict: EnvVerdict
    sustained_effect_records: int
    observations: int
    rationale: list[str] = Field(default_factory=list)


class OutcomeProbe:
    """대응 후 텔레메트리 윈도우를 관측해 환경검증 라벨을 산정한다(결정론).

    Args:
        effect_min: 물리 효과로 인정할 위협신호 연속 지속 레코드 수(트랜지언트 배제).
        min_observations: `CONFIRMED_FP`(무효과 확정)를 허용할 최소 윈도우 길이.
        pos_var_threshold: EKF 잔차(PosHoriz/Velocity Variance) 위협 임계.
        min_satellites: 위성수 하한(미만이면 GPS 열화 = 위협 지속).
    """

    def __init__(
        self,
        effect_min: int = 5,
        min_observations: int = 30,
        pos_var_threshold: float = 0.8,
        min_satellites: int = 7,
    ) -> None:
        self._effect_min = effect_min
        self._min_observations = min_observations
        self._pos_var_threshold = pos_var_threshold
        self._min_satellites = min_satellites
        self._logger = get_logger("OutcomeProbe")

    def assess(self, records: Sequence[TelemetryRecord]) -> OutcomeAssessment:
        """대응 후 텔레메트리 윈도우로 환경검증 라벨을 산정한다.

        판정 규칙(비대칭):
          1. 위협신호가 `effect_min` 이상 연속 지속 → `CONFIRMED_TP`(물리 효과 관측).
          2. (1) 아님 + 윈도우 길이 ≥ `min_observations` + 위협신호 전무 →
             `CONFIRMED_FP`(무효과 확정).
          3. 그 외(짧은 윈도우 / 단발 트랜지언트) → `INCONCLUSIVE`(적립 보류).

        TP 는 윈도우 길이와 무관하게 인정한다(탐지 학습은 안전 방향). 반면 FP 는
        `min_observations` 이상일 때만 허용한다(억제 학습은 위험 방향 — 보수적).

        Args:
            records: 대응 직후 관측된 텔레메트리 레코드(시간순).

        Returns:
            환경검증 라벨과 근거를 담은 `OutcomeAssessment`.
        """
        observations = len(records)
        max_run = 0
        current = 0
        for record in records:
            if self._threat_present(record):
                current += 1
                max_run = max(max_run, current)
            else:
                current = 0

        rationale = [f"관측 {observations}레코드, 위협신호 최대연속 {max_run}"]
        if max_run >= self._effect_min:
            rationale.append(
                f"물리 효과 관측(연속 {max_run}≥{self._effect_min}) → 정탐 확정"
            )
            verdict = EnvVerdict.CONFIRMED_TP
        elif observations < self._min_observations:
            rationale.append(
                f"윈도우 부족({observations}<{self._min_observations}) → 판정 보류"
            )
            verdict = EnvVerdict.INCONCLUSIVE
        elif max_run == 0:
            rationale.append("충분한 윈도우 내 위협신호 전무 → 오탐 확정")
            verdict = EnvVerdict.CONFIRMED_FP
        else:
            rationale.append(
                f"단발 트랜지언트(연속 {max_run}<{self._effect_min}) → 판정 보류"
            )
            verdict = EnvVerdict.INCONCLUSIVE

        self._logger.info(
            "outcome: verdict=%s max_run=%d obs=%d", verdict, max_run, observations
        )
        return OutcomeAssessment(
            env_verdict=verdict,
            sustained_effect_records=max_run,
            observations=observations,
            rationale=rationale,
        )

    def _threat_present(self, record: TelemetryRecord) -> bool:
        """레코드 한 건이 위협 지속 신호를 보이는지(결정론) 판정한다.

        Args:
            record: 텔레메트리 레코드.

        Returns:
            EKF 글리치 플래그 / 잔차 급증 / 위성 급감 중 하나라도 있으면 True.
        """
        flags = record.ekf_flags
        if flags is not None and flags & EKF_GPS_GLITCHING:
            return True
        phv = record.pos_horiz_variance
        if phv is not None and phv >= self._pos_var_threshold:
            return True
        vv = record.velocity_variance
        if vv is not None and vv >= self._pos_var_threshold:
            return True
        sats = record.satellites_visible
        if sats is not None and sats < self._min_satellites:
            return True
        return False
