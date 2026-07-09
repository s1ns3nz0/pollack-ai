"""BASRunner 테스트 — 공격 세트 방어 검증 → 커버리지/갭/STRIDE 집계."""

from core.bas import BASRunner, BASScenario


class TestBASRunner:
    """방어 상시 검증 — 탐지룰 보유 = 탐지, 미보유 = 갭."""

    def test_loads_and_runs(self) -> None:
        """기본 bas-scenarios.yaml 로 검증 실행."""
        report = BASRunner.from_yaml().run()

        assert report.total > 0
        assert 0.0 <= report.detection_ratio <= 1.0

    def test_detected_and_gaps(self) -> None:
        """S1~S126 재정렬 + 신규 S127~S131/C34 저작(2026-07) — 전부 실배포 → gap 0.

        총계는 하한만 고정 — gen_bas_scenarios.py 재실행으로 룰이 늘 때마다
        깨지지 않도록(exact 하드코딩 금지).
        """
        report = BASRunner.from_yaml().run()

        assert report.total >= 131
        assert report.detected == report.total
        assert report.gaps == []

    def test_detection_ratio(self) -> None:
        """detection_ratio = detected / total."""
        report = BASRunner.from_yaml().run()

        assert report.detection_ratio == round(report.detected / report.total, 3)

    def test_by_stride_coverage(self) -> None:
        """STRIDE 카테고리별 탐지/총 집계 — 전면 재정렬 이후 gap 없음(전부 실배포)."""
        report = BASRunner.from_yaml().run()

        assert "I" in report.by_stride
        i_stat = report.by_stride["I"]
        assert i_stat.total >= 3
        assert i_stat.detected == i_stat.total  # gap 없음

    def test_by_tactic_present(self) -> None:
        """tactic 별 집계 존재."""
        report = BASRunner.from_yaml().run()

        assert "CommandAndControl" in report.by_tactic

    def test_gap_only_missing_rule(self) -> None:
        """탐지룰 있는 시나리오는 gap 아님."""
        report = BASRunner.from_yaml().run()

        assert "S1-GNSS-SPOOFING" not in report.gaps

    def test_missing_detection_rule_counts_as_gap(self) -> None:
        """detection_rule 빈 시나리오 → 미탐 갭으로 집계(합성 케이스)."""
        report = BASRunner(
            [
                BASScenario(id="SX-COVERED", signals=["sig"], detection_rule="x.json"),
                BASScenario(id="SX-GAP", signals=["sig"], detection_rule=""),
            ]
        ).run()

        assert report.total == 2
        assert report.detected == 1
        assert report.gaps == ["SX-GAP"]

    def test_non_deployed_status_counts_as_gap(self) -> None:
        """planned/deprecated 룰은 실배포 아님 → 탐지 커버리지로 집계 금지."""
        report = BASRunner(
            [
                BASScenario(
                    id="SX-PLANNED",
                    status="planned",
                    signals=["sig"],
                    detection_rule="x.json",
                ),
                BASScenario(
                    id="SX-DEPRECATED",
                    status="deprecated",
                    signals=["sig"],
                    detection_rule="y.json",
                ),
            ]
        ).run()

        assert report.detected == 0
        assert sorted(report.gaps) == ["SX-DEPRECATED", "SX-PLANNED"]
