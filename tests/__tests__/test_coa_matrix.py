"""CoaMatrix 로더 + technique→tactic 역인덱스 테스트."""

from core.coa import CoaMatrix
from tools.coverage import CoverageMatrix


class TestTacticOf:
    """CoverageMatrix technique→tactic 역인덱스."""

    def test_known_technique_returns_tactic(self) -> None:
        """실 coverage.yaml — technique 이 소속 tactic 반환."""
        matrix = CoverageMatrix.from_yaml()

        # T1590(Gather Victim Network Info)은 Reconnaissance 소속
        assert matrix.tactic_of("T1590") == "Reconnaissance"

    def test_unknown_technique_none(self) -> None:
        """매트릭스에 없는 technique 은 None."""
        matrix = CoverageMatrix.from_yaml()

        assert matrix.tactic_of("T9999") is None


class TestCoaMatrix:
    """COA 매트릭스 정책 로더."""

    def test_loads_from_yaml(self) -> None:
        """기본 coa-matrix.yaml 자동 적재."""
        coa = CoaMatrix.from_yaml()

        assert coa.defenses  # 7D 축 정의됨

    def test_defenses_are_7d(self) -> None:
        """7D 방어 축 순서 유지."""
        coa = CoaMatrix.from_yaml()

        assert coa.defenses == [
            "Discover",
            "Detect",
            "Deny",
            "Disrupt",
            "Degrade",
            "Deceive",
            "Destroy",
        ]

    def test_options_for_tactic_available_and_gap(self) -> None:
        """tactic COA 조회 — 정의된 셀 available + 미정의 gap, 7D 전부 포함."""
        coa = CoaMatrix.from_yaml()

        options = coa.options_for("CommandAndControl")

        # 7D 전부 노출
        assert [o.defense for o in options] == coa.defenses
        by_def = {o.defense: o for o in options}
        # C2 는 Detect/Deny/Disrupt/Deceive 정의됨
        assert by_def["Detect"].status == "available"
        assert by_def["Detect"].d3fend_id
        assert by_def["Detect"].action
        # Discover/Degrade/Destroy 는 gap
        assert by_def["Discover"].status == "gap"
        assert by_def["Discover"].action == ""

    def test_unknown_tactic_all_gap(self) -> None:
        """매트릭스에 없는 tactic 은 7D 전부 gap."""
        coa = CoaMatrix.from_yaml()

        options = coa.options_for("UnknownTactic")

        assert all(o.status == "gap" for o in options)
        assert len(options) == 7
