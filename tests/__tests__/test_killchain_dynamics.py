"""kill_chain_advanced dynamics 규칙 테스트 — 후반단계 도달 시 정책 격상."""

from core.models import Alert, Severity
from core.severity import SeverityEngine


def _alert(*, advanced: bool) -> Alert:
    return Alert(
        id="a1",
        scenario_id="S2",
        title="t",
        asset_tier="T2-Important",
        severity_baseline=Severity.MEDIUM,
        signals=["sig"],
        kill_chain_advanced=advanced,
    )


class TestKillChainDynamics:
    """정책 엔진 kill_chain_advanced 격상."""

    def test_advanced_escalates_one_step(self) -> None:
        """후반 단계 도달 시 한 단계 격상 + rationale 기록."""
        engine = SeverityEngine()

        base, _ = engine.compute(_alert(advanced=False))
        adv, rationale = engine.compute(_alert(advanced=True))

        order = {"i": 0, "l": 1, "m": 2, "h": 3}
        assert order[str(adv)] == order[str(base)] + 1
        assert any("kill_chain" in r for r in rationale)

    def test_not_advanced_no_effect(self) -> None:
        """미도달이면 rationale 에 kill_chain 없음."""
        engine = SeverityEngine()

        _, rationale = engine.compute(_alert(advanced=False))

        assert not any("kill_chain" in r for r in rationale)
