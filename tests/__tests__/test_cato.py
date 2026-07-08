"""cATO — 방어 검증 신호 → POA&M + 지속 인가 판정(결정론)."""

import pytest

from core.bas import BASReport
from core.cato import CatoAssessor, CatoControls
from core.exceptions import PolicyError
from core.models import SbomFinding
from core.monitoring import SloBreach


def _assessor() -> CatoAssessor:
    return CatoAssessor(CatoControls.from_yaml())


class TestCatoControls:
    """정책 로딩."""

    def test_loads_default(self) -> None:
        c = CatoControls.from_yaml()
        assert c.count == 3 and c.bas_detection_floor == 0.8
        assert c.by_source("bas") is not None

    def test_empty_raises(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        p = tmp_path / "e.yaml"
        p.write_text("cato:\n  controls: []\n", encoding="utf-8")
        with pytest.raises(PolicyError):
            CatoControls.from_yaml(p)

    def test_malformed_floor_raises(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        p = tmp_path / "f.yaml"
        p.write_text(
            "cato:\n  bas_detection_floor: xyz\n  controls:\n    - id: CA-8\n"
            "      source: bas\n",
            encoding="utf-8",
        )
        with pytest.raises(PolicyError):
            CatoControls.from_yaml(p)

    def test_missing_id_raises(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """id 누락 통제 → PolicyError(조용한 부분로딩 은폐 차단, Codex M-3)."""
        p = tmp_path / "n.yaml"
        p.write_text("cato:\n  controls:\n    - source: bas\n", encoding="utf-8")
        with pytest.raises(PolicyError):
            CatoControls.from_yaml(p)

    def test_controls_not_list_raises(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """controls 가 리스트 아님 → PolicyError(TypeError 아님, Codex H-1)."""
        p = tmp_path / "c.yaml"
        p.write_text("cato:\n  controls: 5\n", encoding="utf-8")
        with pytest.raises(PolicyError):
            CatoControls.from_yaml(p)


class TestCatoAssess:
    """신호 → POA&M + 인가태세."""

    def test_all_clean_authorized(self) -> None:
        """커버리지 충분·위반/취약 없음 → authorized(POA&M 0)."""
        bas = BASReport(total=10, detected=10)
        status = _assessor().assess(bas=bas, slo_breaches=[], sbom_findings=[])
        assert status.authorization == "authorized" and not status.poam

    def test_bas_below_floor_at_risk(self) -> None:
        """탐지 커버리지 하한 미달 → CA-8 high POA&M → at_risk."""
        bas = BASReport(total=10, detected=5, gaps=["g1", "g2"])
        status = _assessor().assess(bas=bas)
        assert status.authorization == "at_risk"
        assert any(p.control_id == "CA-8" and p.severity == "high" for p in status.poam)

    def test_slo_breach_conditional(self) -> None:
        """중간 SLO 위반만 → SI-4 medium POA&M → conditional."""
        breach = SloBreach(
            metric="mttr", actual=9.0, threshold=5.0, severity="medium", message="느림"
        )
        status = _assessor().assess(
            bas=BASReport(total=1, detected=1), slo_breaches=[breach]
        )
        assert status.authorization == "conditional"
        assert any(p.control_id == "SI-4" for p in status.poam)

    def test_sbom_tampered_high(self) -> None:
        """SBOM 변조 → SR-4 high POA&M → at_risk."""
        f = SbomFinding(component="fw.bin", issue="tampered", detail="해시 불일치")
        status = _assessor().assess(sbom_findings=[f])
        item = next(p for p in status.poam if p.source == "sbom")
        assert item.severity == "high" and status.authorization == "at_risk"

    def test_sbom_unregistered_medium(self) -> None:
        """미등록 컴포넌트 → medium → conditional."""
        f = SbomFinding(component="lib.so", issue="unregistered")
        status = _assessor().assess(sbom_findings=[f])
        assert status.authorization == "conditional"

    def test_unknown_slo_severity_fails_safe_high(self) -> None:
        """미인식 SLO severity(critical) → high 로 상향(강등 우회 차단, Codex H-2)."""
        breach = SloBreach(
            metric="m", actual=1, threshold=0, severity="critical", message="치명"
        )
        status = _assessor().assess(slo_breaches=[breach])
        item = next(p for p in status.poam if p.source == "slo")
        assert item.severity == "high" and status.authorization == "at_risk"

    def test_worst_severity_drives_authorization(self) -> None:
        """혼합 갭 — 최고 심각도(high)가 인가태세 지배."""
        status = _assessor().assess(
            bas=BASReport(total=10, detected=4),  # high
            slo_breaches=[
                SloBreach(
                    metric="m", actual=1, threshold=0, severity="low", message="x"
                )
            ],
        )
        assert status.authorization == "at_risk"
        assert status.controls_evaluated == 3
