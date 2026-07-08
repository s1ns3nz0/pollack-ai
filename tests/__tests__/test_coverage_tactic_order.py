"""CoverageMatrix tactic→order 역인덱스 테스트 — kill chain 진행도 산정 기반."""

from tools.coverage import CoverageMatrix


class TestTacticOrder:
    """tactic 이름 → kill-chain order 조회."""

    def test_known_tactic_returns_order(self) -> None:
        """실 coverage.yaml — Reconnaissance=1(초기), Impact=15(후반)."""
        matrix = CoverageMatrix.from_yaml()

        assert matrix.tactic_order("Reconnaissance") == 1
        assert matrix.tactic_order("Impact") == 15

    def test_later_tactic_higher_order(self) -> None:
        """후반 tactic 이 초기보다 큰 order."""
        matrix = CoverageMatrix.from_yaml()

        collection = matrix.tactic_order("Collection")
        initial = matrix.tactic_order("InitialAccess")
        assert collection is not None and initial is not None
        assert collection > initial

    def test_unknown_tactic_none(self) -> None:
        """매핑 없는 tactic(예: ATLAS MLAttackStaging)은 None."""
        matrix = CoverageMatrix.from_yaml()

        assert matrix.tactic_order("MLAttackStaging") is None

    def test_max_order_of_tactics(self) -> None:
        """여러 tactic 중 최고 order 반환(actor 누적 진행도용). 미매핑은 무시."""
        matrix = CoverageMatrix.from_yaml()

        result = matrix.max_tactic_order(
            ["InitialAccess", "Collection", "MLAttackStaging"]
        )

        assert result == matrix.tactic_order("Collection")

    def test_max_order_all_unknown_returns_zero(self) -> None:
        """전부 미매핑이면 0(진행도 없음)."""
        matrix = CoverageMatrix.from_yaml()

        assert matrix.max_tactic_order(["MLAttackStaging", "Bogus"]) == 0

    def test_max_order_empty_returns_zero(self) -> None:
        """빈 목록은 0."""
        matrix = CoverageMatrix.from_yaml()

        assert matrix.max_tactic_order([]) == 0
