"""BASRunner 테스트 — 공격 세트 방어 검증 → 커버리지/갭/STRIDE 집계."""

from core.bas import BASRunner


class TestBASRunner:
    """방어 상시 검증 — 탐지룰 보유 = 탐지, 미보유 = 갭."""

    def test_loads_and_runs(self) -> None:
        """기본 bas-scenarios.yaml 로 검증 실행."""
        report = BASRunner.from_yaml().run()

        assert report.total > 0
        assert 0.0 <= report.detection_ratio <= 1.0

    def test_detected_and_gaps(self) -> None:
        """탐지룰 보유 시나리오 detected, 미보유(S12) gap."""
        report = BASRunner.from_yaml().run()

        assert report.detected >= 11  # S1~S11 탐지룰 보유
        assert "S12-COVERT-EXFIL" in report.gaps

    def test_detection_ratio(self) -> None:
        """detection_ratio = detected / total."""
        report = BASRunner.from_yaml().run()

        assert report.detection_ratio == round(report.detected / report.total, 3)

    def test_by_stride_coverage(self) -> None:
        """STRIDE 카테고리별 탐지/총 집계 — I(Info)는 S12 갭 포함."""
        report = BASRunner.from_yaml().run()

        assert "I" in report.by_stride
        i_stat = report.by_stride["I"]
        # I 카테고리: S3, S8, S12 → S12 는 미탐
        assert i_stat.total >= 3
        assert i_stat.detected < i_stat.total  # S12 갭

    def test_by_tactic_present(self) -> None:
        """tactic 별 집계 존재."""
        report = BASRunner.from_yaml().run()

        assert "CommandAndControl" in report.by_tactic

    def test_gap_only_missing_rule(self) -> None:
        """탐지룰 있는 시나리오는 gap 아님."""
        report = BASRunner.from_yaml().run()

        assert "S1-GNSS-SPOOF" not in report.gaps
