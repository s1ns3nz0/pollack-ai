"""OutcomeProbe — 시뮬 관측 → env_verdict + effect 결정론 매트릭스(spec A-1).

`ObservationSource` Protocol + `ProbeEngine` 결정론 룰. 시뮬 결합 분리 — 호출자가
ObservationSource 구현체 주입. 본 모듈은 *결정 엔진*만.

Spec: docs/superpowers/specs/2026-06-30-outcome-probe-design.md
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from core.models import EnvVerdict, JudgeFeatures, Severity, Verdict


class Observation(BaseModel):
    """시뮬 후속 관측 한 건(spec A-1).

    호출자가 alert 원본 메타(signals/severity/verdict/asset)를 채워야 exp/actors
    적립이 가능하다. 일부 누락 시 해당 gate 만 skip (전체 처리는 계속).
    """

    alert_id: str
    scenario_id: str
    actor_id: str | None = None
    playbook_id: str | None = None
    window_min: int = Field(default=0, ge=0)
    mission_effect_observed: bool = False
    no_effect_sustained: bool = False
    reoccurred: bool = False
    # 검증 폐루프: 이 관측 이전에 RecoveryPlan(축출/복구)이 실행됐는지.
    # True + reoccurred → 축출 실패(공격자 잔존) 판정(RecoveryVerifier).
    recovery_applied: bool = False
    dwelling_min: int = 0
    ts: str
    # exp/actors 적립용 알림 원본 메타.
    alert_signals: list[str] = Field(default_factory=list)
    alert_severity: Severity | None = None
    alert_verdict: Verdict | None = None
    alert_iocs: list[str] = Field(default_factory=list)
    alert_mitre: dict[str, object] = Field(default_factory=dict)
    asset_id: str = ""
    asset_tier: str = ""
    judge_features: JudgeFeatures | None = None


class ProbeDecision(BaseModel):
    """ProbeEngine 결과."""

    env_verdict: EnvVerdict
    effect: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


@runtime_checkable
class ObservationSource(Protocol):
    """시뮬 관측 소스 — 호출자 구현(sim_bridge 어댑터 등)."""

    async def apoll(self) -> list[Observation]:
        """현재 처리 대기 중인 관측 목록을 반환한다."""
        ...


class InMemoryObservationSource:
    """테스트/MVP 용 in-memory queue."""

    def __init__(self) -> None:
        self._queue: list[Observation] = []

    def push(self, obs: Observation) -> None:
        self._queue.append(obs)

    async def apoll(self) -> list[Observation]:
        out = self._queue[:]
        self._queue.clear()
        return out


class ProbeEngine:
    """관측 → ProbeDecision 결정론 매트릭스.

    Args:
        min_window_for_fp: CONFIRMED_FP 판정 최소 윈도우(분). 디폴트 5.
    """

    def __init__(self, min_window_for_fp: int = 5) -> None:
        self._min_window_fp = min_window_for_fp

    def decide(self, obs: Observation) -> ProbeDecision:
        """관측 → (env_verdict, effect)."""
        if obs.mission_effect_observed:
            if obs.reoccurred:
                return ProbeDecision(
                    env_verdict=EnvVerdict.CONFIRMED_TP,
                    effect=0.0,
                    rationale="mission_effect + reoccurred → PB 완전 실패",
                )
            return ProbeDecision(
                env_verdict=EnvVerdict.CONFIRMED_TP,
                effect=0.3,
                rationale="mission_effect 단발 → PB 부분 효과",
            )
        if obs.no_effect_sustained and obs.window_min >= self._min_window_fp:
            return ProbeDecision(
                env_verdict=EnvVerdict.CONFIRMED_FP,
                effect=1.0,
                rationale=(
                    f"no_effect_sustained + window>={self._min_window_fp}분 "
                    "→ 차단 완료/오탐"
                ),
            )
        return ProbeDecision(
            env_verdict=EnvVerdict.INCONCLUSIVE,
            effect=0.5,
            rationale="관측 불충분 — 보류",
        )
