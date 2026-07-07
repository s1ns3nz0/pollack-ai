"""StrideClassifier 테스트 — alert → STRIDE 분류 + BAS 연계 커버리지."""

from core.models import Alert, Severity, StrideThreat
from core.stride import StrideClassifier, StrideModel


class TestStrideModel:
    """stride-model.yaml 로더."""

    def test_loads_six_categories(self) -> None:
        sm = StrideModel.from_yaml()
        assert sm.category_count == 6

    def test_category_has_mitigation(self) -> None:
        sm = StrideModel.from_yaml()

        cat = sm.category("D")

        assert cat is not None
        assert cat.name == "Denial of Service"
        assert cat.mitigation
        assert "InhibitResponseFunction" in cat.tactics


def _alert(tactics: list[str], stride: list[str] | None = None) -> Alert:
    mitre: dict[str, object] = {"tactics": tactics}
    if stride is not None:
        mitre["stride"] = stride
    return Alert(
        id="a1",
        scenario_id="S2",
        title="t",
        severity_baseline=Severity.HIGH,
        signals=["sig"],
        mitre=mitre,
    )


class TestStrideClassifier:
    """alert tactic/stride → STRIDE 위협 분류."""

    def _clf(self) -> StrideClassifier:
        return StrideClassifier(StrideModel.from_yaml())

    def test_explicit_stride_tag_used(self) -> None:
        """alert.mitre.stride 명시 태그 우선."""
        threats = self._clf().classify(_alert(["Impact"], stride=["T", "E"]))

        codes = {t.code for t in threats}
        assert codes == {"T", "E"}
        assert all(isinstance(t, StrideThreat) for t in threats)

    def test_tactic_inferred_when_no_tag(self) -> None:
        """stride 태그 없으면 tactic 으로 STRIDE 추론."""
        # InhibitResponseFunction → D(DoS)
        threats = self._clf().classify(_alert(["InhibitResponseFunction"]))

        assert any(t.code == "D" for t in threats)

    def test_threat_carries_mitigation(self) -> None:
        """분류된 위협은 완화책을 담는다."""
        threats = self._clf().classify(_alert(["Impact"], stride=["T"]))

        t = next(t for t in threats if t.code == "T")
        assert t.name == "Tampering"
        assert t.mitigation

    def test_unmapped_empty(self) -> None:
        """분류 불가(미매핑 tactic, 태그 없음)면 빈 리스트."""
        threats = self._clf().classify(_alert(["Reconnaissance"]))

        assert threats == []


class TestStrideCoverage:
    """BAS by_stride 연계 — STRIDE 유형별 방어 커버리지."""

    def test_coverage_from_bas(self) -> None:
        """BAS 검증 결과로 STRIDE 커버리지 산출 — I 축에 갭."""
        from core.bas import BASRunner

        bas = BASRunner.from_yaml().run()
        cov = StrideClassifier(StrideModel.from_yaml()).coverage(bas)

        assert "I" in cov
        # I(Info Disclosure): S12 미탐 → 1.0 미만
        assert cov["I"] < 1.0
        assert cov["D"] == 1.0
