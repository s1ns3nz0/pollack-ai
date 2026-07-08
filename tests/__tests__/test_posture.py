"""CPCON 사이버방어태세 사다리 — 전역 태세 → alert.posture 하한 스탬프."""

import pytest

from core.exceptions import PolicyError
from core.models import Alert, Severity
from core.posture import PostureLadder, PostureProvider


def _alert(posture: str = "normal") -> Alert:
    return Alert(
        id="a1",
        scenario_id="S1",
        title="t",
        severity_baseline=Severity.MEDIUM,
        signals=["sig"],
        posture=posture,
    )


class TestPostureLadder:
    """CPCON 사다리 로딩·매핑."""

    def test_maps_cpcon_to_posture(self) -> None:
        """CPCON 5→normal, 3→elevated, 1→high."""
        ladder = PostureLadder.from_yaml()
        assert ladder.posture_for(5) == "normal"
        assert ladder.posture_for(3) == "elevated"
        assert ladder.posture_for(1) == "high"

    def test_level_names(self) -> None:
        """국정원 표기 매핑."""
        ladder = PostureLadder.from_yaml()
        assert ladder.level(1) is not None and ladder.level(1).name == "심각"

    def test_empty_raises(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """빈 사다리 → PolicyError."""
        p = tmp_path / "e.yaml"
        p.write_text("cpcon: []\n", encoding="utf-8")
        with pytest.raises(PolicyError):
            PostureLadder.from_yaml(p)


class TestPostureProvider:
    """전역 태세 하한 스탬프."""

    @pytest.mark.asyncio
    async def test_raises_low_posture_to_floor(self) -> None:
        """전역 CPCON 1(high) → normal alert 을 high 로 상향."""
        prov = PostureProvider(PostureLadder.from_yaml(), cpcon_level=1)
        out = await prov.enrich(_alert("normal"))
        assert out.posture == "high"

    @pytest.mark.asyncio
    async def test_keeps_higher_scenario_posture(self) -> None:
        """시나리오 posture(high)가 전역(elevated)보다 높으면 유지(floor 의미)."""
        prov = PostureProvider(PostureLadder.from_yaml(), cpcon_level=3)
        out = await prov.enrich(_alert("high"))
        assert out.posture == "high"

    @pytest.mark.asyncio
    async def test_normal_cpcon_no_change(self) -> None:
        """전역 CPCON 5(정상) → normal alert 무변(읽기전용, 원본 반환)."""
        prov = PostureProvider(PostureLadder.from_yaml(), cpcon_level=5)
        alert = _alert("normal")
        out = await prov.enrich(alert)
        assert out.posture == "normal"

    def test_condition_exposed(self) -> None:
        """현재 CPCON 단계 정의 노출."""
        prov = PostureProvider(PostureLadder.from_yaml(), cpcon_level=2)
        assert prov.cpcon_level == 2
        assert prov.condition is not None and prov.condition.name == "경계"


class TestPostureEscalatesSeverity:
    """전역 태세 상향이 severity 격상으로 전파(통합)."""

    def test_high_posture_escalates(self) -> None:
        """posture=high 스탬프 → severity posture_modifier 격상 확인."""
        from core.severity import SeverityEngine

        eng = SeverityEngine()
        base_level, _ = eng.compute(_alert("normal"))
        high_level, rationale = eng.compute(_alert("high"))
        assert eng.ordinal[str(high_level)] >= eng.ordinal[str(base_level)]
        assert any("posture[high]" in r for r in rationale)
