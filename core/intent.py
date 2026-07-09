"""임무형 지휘 — Commander's Intent 필터(결정론·읽기전용·자문).

지휘관이 사전 선언한 의도(commander-intent.yaml)로 SOC 산출물을 우선순위화하고
'지휘관 결심 필요' vs '통상 SOC 가시성'을 자문 판정한다. **비대칭 게이팅**이 핵심:
surface 는 provisional∪authoritative 둘 다 발동(가시성 fail-safe), delegate 는
authoritative 확정에만 — 위조 신호로 지휘관 시야에서 은폐하는 것을 차단한다.

verdict/severity/CAT 을 바꾸지 않는다. decision_class 는 표현 메타데이터일 뿐 억제
권한이 아니다(모든 항목은 리포트·감사에 항상 존재). 정책 로드/검증 실패 시
degraded — 전부 surfaced(delegate 비활성, fail-safe).

Spec: docs/superpowers/specs/2026-07-09-commander-intent-filter-design.md
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from core.exceptions import PolicyError
from core.models import Alert, IncidentCase, IntentAssessment
from core.policy_loader import load_policy_mapping
from utils.logging import get_logger

_logger = get_logger("intent")

_POLICY = Path(__file__).resolve().parent / "policy" / "commander-intent.yaml"
# 시스템이 산출하는 CAT 어휘(core/incident.py·commander.py). 미지 CAT 은 정책 오류.
_KNOWN_CATS = frozenset({"CAT1", "CAT2", "CAT3", "CAT4", "CAT6", "CAT7", "CAT8"})
# 필수 상승 CAT — 치명/연방보고(CISA CAT1/4/7)는 정책 오타로도 위임·은폐 불가.
_MANDATORY_SURFACE = frozenset({"CAT1", "CAT4", "CAT7"})


class CommanderIntent(BaseModel):
    """지휘관 사전 선언 의도(정적 교리 입력). 로드 시 엄격 검증.

    Attributes:
        main_effort_assets: 주력 자산 — 항상 지휘관 상승.
        protected_scenarios: 보호 시나리오 id(scenario_id 매칭).
        protected_mission_phases: 보호 임무단계(mission_phase 매칭).
        risk_tolerance: 위험 감내(low|medium|high — 참고·rationale).
        surface_cats: 지휘관 결심 상승 CAT 집합(치명 CAT1/4/7 필수 포함).
        delegate_cats: authoritative 확정 시 통상 SOC 처리 CAT 집합.
    """

    main_effort_assets: list[str] = Field(default_factory=list)
    protected_scenarios: list[str] = Field(default_factory=list)
    protected_mission_phases: list[str] = Field(default_factory=list)
    risk_tolerance: Literal["low", "medium", "high"] = "medium"
    surface_cats: list[str] = Field(default_factory=list)
    delegate_cats: list[str] = Field(default_factory=list)

    @field_validator("surface_cats", "delegate_cats")
    @classmethod
    def _known_cats(cls, v: list[str]) -> list[str]:
        """CAT 어휘 검증 — 미지 CAT 은 오류(오타로 게이팅 무력화 차단)."""
        unknown = [c for c in v if c not in _KNOWN_CATS]
        if unknown:
            raise ValueError(f"미지 CAT: {unknown}")
        return v

    @model_validator(mode="after")
    def _consistent_gating(self) -> CommanderIntent:
        """게이팅 정합성 — 상호배타 + 치명 CAT 필수 상승(부분/오타 정책 거부).

        surface_cats ⊇ {CAT1,CAT4,CAT7}: 절단·오타 정책(예: surface 누락 +
        delegate 오기)이 치명 사건을 routine_soc 로 은폐하는 것을 원천 차단.
        빈/부분 정책은 이 조건 미달 → ValidationError → degraded(전부 surfaced).
        """
        overlap = set(self.surface_cats) & set(self.delegate_cats)
        if overlap:
            raise ValueError(f"surface/delegate CAT 겹침: {sorted(overlap)}")
        missing = _MANDATORY_SURFACE - set(self.surface_cats)
        if missing:
            raise ValueError(
                f"surface_cats 에 치명 CAT 누락(필수 상승): {sorted(missing)}"
            )
        return self


class IntentFilter:
    """지휘관 의도 기반 우선순위·결심필요 판정기(결정론·읽기전용).

    Args:
        intent: 검증된 지휘관 의도. None 이면 degraded(전부 surfaced).
    """

    def __init__(self, intent: CommanderIntent | None) -> None:
        self._intent = intent

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> IntentFilter:
        """commander-intent.yaml 을 적재·검증한다(fail-safe degrade).

        파일/파싱/스키마(미지 CAT·CAT 겹침·risk 오류) 실패는 예외를 던지지 않고
        degraded 필터(intent=None)로 반환한다 — 깨진 의도 정책이 파이프라인·지휘관
        가시성을 절대 막지 못하게 한다(security fail-safe). 실패는 warning 로 관측.

        Returns:
            검증 통과 시 활성 필터, 실패 시 degraded 필터.
        """
        try:
            raw = load_policy_mapping(path, _POLICY, label="지휘관 의도")
            intent = CommanderIntent.model_validate(raw)
        except (PolicyError, ValidationError) as exc:
            _logger.warning("지휘관 의도 로드 실패, degraded(전부 surfaced): %s", exc)
            return cls(None)
        return cls(intent)

    def assess(self, alert: Alert, case: IncidentCase | None) -> IntentAssessment:
        """의도 기반 우선순위 + decision_class 를 산정한다(비대칭 게이팅).

        Args:
            alert: 대상 알람(asset_id/scenario_id/mission_phase 매칭 키).
            case: 봉합 사건(cat/provisional — 상승/위임 게이팅). 없으면 CAT 게이팅 생략.

        Returns:
            우선순위·결심필요 판정. 억제 권한 아님(표현 메타데이터).
        """
        if self._intent is None:
            return IntentAssessment(
                priority="routine", decision_class="surfaced", intent_available=False
            )
        it = self._intent
        matched: list[str] = []
        if alert.asset_id and alert.asset_id in it.main_effort_assets:
            matched.append(f"main_effort:{alert.asset_id}")
        if alert.scenario_id and alert.scenario_id in it.protected_scenarios:
            matched.append(f"protected_scenario:{alert.scenario_id}")
        if alert.mission_phase and alert.mission_phase in it.protected_mission_phases:
            matched.append(f"protected_phase:{alert.mission_phase}")
        priority: Literal["main_effort", "routine"] = (
            "main_effort" if matched else "routine"
        )

        # decision_class — 우선순위 순(main_effort 상승이 CAT 게이팅보다 우선).
        decision_class: Literal["commander_decision", "routine_soc", "surfaced"]
        if priority == "main_effort":
            decision_class = "commander_decision"
        elif case is not None and case.cat in it.surface_cats:
            # 위조 가능한 provisional 로도 상승 — 지휘관 시야에서 은폐 차단(fail-safe).
            decision_class = "commander_decision"
            matched.append(f"surface_cat:{case.cat}")
        elif case is not None and case.cat in it.delegate_cats and not case.provisional:
            # authoritative 확정에만 통상 처리 — provisional 은 routine_soc 안 됨.
            decision_class = "routine_soc"
            matched.append(f"delegate_cat:{case.cat}")
        else:
            decision_class = "surfaced"

        return IntentAssessment(
            priority=priority,
            decision_class=decision_class,
            matched=matched,
            intent_available=True,
        )
