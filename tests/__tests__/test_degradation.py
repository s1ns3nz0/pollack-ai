"""DegradationAssessor 테스트 — 자산 손상 → 임무 지속성 등급 + 대체경로."""

from core.degradation import DegradationAssessor, DegradationMatrix
from core.models import Alert, Severity, Verdict


class TestDegradationMatrix:
    """degradation-matrix.yaml 로더."""

    def test_loads_from_yaml(self) -> None:
        dm = DegradationMatrix.from_yaml()
        assert dm.assess_asset("GNSS") is not None

    def test_gnss_sustained_with_fallback(self) -> None:
        """GNSS 손상 → SUSTAINED + INS fallback."""
        dm = DegradationMatrix.from_yaml()

        mc = dm.assess_asset("GNSS")

        assert mc is not None
        assert mc.level == "SUSTAINED"
        assert mc.sustains is True
        assert "INS" in mc.fallback
        assert mc.capability_lost

    def test_autopilot_abort(self) -> None:
        """AUTOPILOT 손상 → ABORT(비행제어 상실, 임무 불가)."""
        dm = DegradationMatrix.from_yaml()

        mc = dm.assess_asset("AUTOPILOT")

        assert mc is not None
        assert mc.level == "ABORT"
        assert mc.sustains is False

    def test_unknown_asset_none(self) -> None:
        dm = DegradationMatrix.from_yaml()
        assert dm.assess_asset("BOGUS") is None


def _alert(asset_id: str) -> Alert:
    return Alert(
        id="a1",
        scenario_id="S1",
        title="t",
        asset_id=asset_id,
        severity_baseline=Severity.HIGH,
        signals=["sig"],
    )


class TestDegradationAssessor:
    """정탐 alert asset → MissionContinuity."""

    def _assessor(self) -> DegradationAssessor:
        return DegradationAssessor(DegradationMatrix.from_yaml())

    def test_tp_asset_assessed(self) -> None:
        """정탐 + 손상 자산 → 지속성 판정."""
        mc = self._assessor().assess(_alert("C2_LINK"), Verdict.TRUE_POSITIVE)

        assert mc is not None
        assert mc.asset_id == "C2_LINK"
        assert mc.level == "MINIMAL"

    def test_fp_no_assessment(self) -> None:
        """오탐은 손상 아님 — None."""
        mc = self._assessor().assess(_alert("C2_LINK"), Verdict.FALSE_POSITIVE)

        assert mc is None

    def test_no_asset_none(self) -> None:
        """자산 미상 알람은 None."""
        mc = self._assessor().assess(_alert(""), Verdict.TRUE_POSITIVE)

        assert mc is None
