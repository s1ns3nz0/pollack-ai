"""사이버 교전피해평가(BDA) — 교전 후 기능피해·복구권고 판정(JP 3-60 사이버판).

방어 효과(`ProbeDecision.effect`: 1=완전차단, 0=완전실패)의 역을 **기능피해**로
환산하고, 복구 성공 여부(recovery_applied·reoccurred)와 임무 지속성
(MissionContinuity)을 결합해 재교전(복구) 필요성과 평가 확신도를 산출한다.
outcome([[outcome-probe]]) 가 *효과 관측* 이라면 BDA 는 그 효과의 *피해 판정·조치 권고*.

전 과정 결정론. LLM 무관.

Spec: docs/superpowers/specs/2026-07-08-cyber-bda-design.md
"""

from __future__ import annotations

from core.models import BdaReport, MissionContinuity
from core.outcome import Observation

# 방어 효과(effect) 구간 → 기능피해 등급. effect 높을수록 피해 작음.
_NONE_AT = 0.8
_LIGHT_AT = 0.5
_MODERATE_AT = 0.2
# 확신도 판정 최소 관측 윈도우(분).
_MIN_WINDOW_HIGH = 5


def _damage_level(effect: float) -> str:
    """방어 효과 → 기능피해 등급(effect 역방향)."""
    if effect >= _NONE_AT:
        return "none"
    if effect >= _LIGHT_AT:
        return "light"
    if effect >= _MODERATE_AT:
        return "moderate"
    return "severe"


class BdaAssessor:
    """효과 + 관측 + 임무지속성 → BdaReport(결정론)."""

    def assess(
        self,
        effect: float,
        obs: Observation,
        continuity: MissionContinuity | None = None,
    ) -> BdaReport:
        """교전 후 기능피해·복구권고를 산정한다.

        Args:
            effect: 방어 효과(ProbeDecision.effect, 0~1).
            obs: 후속 관측(복구 적용/재발/윈도우).
            continuity: 임무 지속성 판정(선택) — 임무영향 서술 연계.

        Returns:
            피해등급·복구권고·확신도를 담은 BdaReport.
        """
        eff = max(0.0, min(1.0, effect))
        level = _damage_level(eff)

        # 복구 성공 = 복구 적용 + 미재발. 미완/잔존 + 유의미 피해 → 재교전 권고.
        recovery_ok = obs.recovery_applied and not obs.reoccurred
        significant = level in ("moderate", "severe")
        restore = significant and not recovery_ok

        # 확신도 — 충분한 관측 윈도우 + 효과/무효과 지속 관측.
        observed = obs.mission_effect_observed or obs.no_effect_sustained
        confidence = (
            "high" if (obs.window_min >= _MIN_WINDOW_HIGH and observed) else "low"
        )

        mission_impact = self._mission_impact(continuity, level)
        rationale = [
            f"effect={eff:.2f} → 기능피해 {level}",
            f"복구성공={recovery_ok}(적용={obs.recovery_applied},재발={obs.reoccurred})",
            f"확신도={confidence}(window={obs.window_min}m)",
        ]
        if restore:
            rationale.append("복구/재교전 권고 — 잔존 위협 또는 미복구")
        return BdaReport(
            damage_level=level,
            effect=eff,
            mission_impact=mission_impact,
            restore_recommended=restore,
            confidence=confidence,
            rationale=rationale,
        )

    @staticmethod
    def _mission_impact(continuity: MissionContinuity | None, level: str) -> str:
        """임무영향 서술 — MissionContinuity 우선, 없으면 피해등급 기반."""
        if continuity is not None:
            return f"{continuity.level}: {continuity.capability_lost}".strip(": ")
        return {
            "none": "임무영향 없음",
            "light": "경미 — 임무 지속 가능",
            "moderate": "중간 — 능력 저하",
            "severe": "심각 — 임무 재평가 필요",
        }.get(level, "")
