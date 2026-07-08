"""사이버 교전피해평가(BDA) — 효과→피해 + 복구권고 + 확신도(결정론)."""

from core.bda import BdaAssessor
from core.models import MissionContinuity
from core.outcome import Observation


def _obs(
    *,
    recovery_applied: bool = False,
    reoccurred: bool = False,
    window: int = 10,
    effect_observed: bool = True,
) -> Observation:
    return Observation.model_validate(
        {
            "alert_id": "a1",
            "scenario_id": "S1",
            "ts": "t",
            "recovery_applied": recovery_applied,
            "reoccurred": reoccurred,
            "window_min": window,
            "mission_effect_observed": effect_observed,
        }
    )


class TestDamageLevel:
    """방어 효과 역방향 → 기능피해."""

    def test_high_effect_no_damage(self) -> None:
        r = BdaAssessor().assess(0.9, _obs())
        assert r.damage_level == "none" and not r.restore_recommended

    def test_zero_effect_severe(self) -> None:
        r = BdaAssessor().assess(0.0, _obs())
        assert r.damage_level == "severe"

    def test_mid_effect_moderate(self) -> None:
        r = BdaAssessor().assess(0.3, _obs())
        assert r.damage_level == "moderate"

    def test_effect_clamped(self) -> None:
        """범위 밖 effect → clamp(크래시 없음)."""
        assert BdaAssessor().assess(2.5, _obs()).damage_level == "none"
        assert BdaAssessor().assess(-1.0, _obs()).damage_level == "severe"


class TestRestoreRecommendation:
    """복구 성공 여부 → 재교전 권고."""

    def test_significant_damage_no_recovery_recommends(self) -> None:
        """유의미 피해 + 복구 미적용 → 복구 권고."""
        r = BdaAssessor().assess(0.1, _obs(recovery_applied=False))
        assert r.restore_recommended is True

    def test_recovered_no_reoccur_no_restore(self) -> None:
        """복구 적용 + 미재발 → 권고 없음."""
        r = BdaAssessor().assess(0.1, _obs(recovery_applied=True, reoccurred=False))
        assert r.restore_recommended is False

    def test_recovered_but_reoccur_recommends(self) -> None:
        """복구 적용했으나 재발(잔존) → 재교전 권고."""
        r = BdaAssessor().assess(0.1, _obs(recovery_applied=True, reoccurred=True))
        assert r.restore_recommended is True

    def test_light_damage_no_restore(self) -> None:
        """경미 피해 → 복구 권고 안 함."""
        r = BdaAssessor().assess(0.6, _obs(recovery_applied=False))
        assert r.damage_level == "light" and r.restore_recommended is False


class TestConfidenceAndImpact:
    """확신도 + 임무영향."""

    def test_low_confidence_short_window(self) -> None:
        r = BdaAssessor().assess(0.3, _obs(window=2))
        assert r.confidence == "low"

    def test_high_confidence(self) -> None:
        r = BdaAssessor().assess(0.3, _obs(window=10, effect_observed=True))
        assert r.confidence == "high"

    def test_mission_impact_from_continuity(self) -> None:
        cont = MissionContinuity(
            asset_id="GNSS", level="ABORT", capability_lost="항법 상실"
        )
        r = BdaAssessor().assess(0.1, _obs(), continuity=cont)
        assert "ABORT" in r.mission_impact and "항법" in r.mission_impact
