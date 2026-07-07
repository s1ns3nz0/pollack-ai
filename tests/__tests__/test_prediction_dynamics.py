"""prediction_match dynamics 규칙 단위 테스트 — 예측 적중 시 정책 격상."""

from core.models import Alert, Severity
from core.severity import SeverityEngine


def _alert(*, prediction_match: bool) -> Alert:
    return Alert(
        id="a1",
        scenario_id="S2",
        title="test",
        asset_tier="T2-Important",
        severity_baseline=Severity.MEDIUM,
        signals=["sig"],
        prediction_match=prediction_match,
    )


class TestPredictionMatchDynamics:
    """정책 엔진 prediction_match 격상 테스트 (기본 정책 yaml 기준)."""

    def test_match_escalates_one_step(self) -> None:
        """적중 시 미적중 대비 한 단계 격상 + rationale 기록."""
        engine = SeverityEngine()

        base_level, _ = engine.compute(_alert(prediction_match=False))
        hit_level, rationale = engine.compute(_alert(prediction_match=True))

        order = {"i": 0, "l": 1, "m": 2, "h": 3}
        assert order[str(hit_level)] == order[str(base_level)] + 1
        assert any("prediction_match" in r for r in rationale)

    def test_no_match_no_effect(self) -> None:
        """미적중이면 rationale 에 prediction_match 없음."""
        engine = SeverityEngine()

        _, rationale = engine.compute(_alert(prediction_match=False))

        assert not any("prediction_match" in r for r in rationale)

    def test_match_clamped_at_high(self) -> None:
        """이미 h 면 클램프 상한 유지(격상 초과 없음)."""
        engine = SeverityEngine()
        alert = Alert(
            id="a1",
            scenario_id="S1",
            title="test",
            asset_tier="T1-Critical",
            severity_baseline=Severity.HIGH,
            signals=["sig"],
            prediction_match=True,
        )

        level, _ = engine.compute(alert)

        assert level == Severity.HIGH
