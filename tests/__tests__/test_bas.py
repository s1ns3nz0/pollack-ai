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
        깨지지 않도록(exact 하드코딩 금지). 단, detected 는 "룰 존재" 지표이고
        native readiness 와 동일하지 않다.
        """
        report = BASRunner.from_yaml().run()

        assert report.total >= 131
        assert report.detected == report.total
        assert report.gaps == []
        assert report.native_detected < report.detected
        assert report.proxy_detected > 0
        assert 0.0 < report.readiness_ratio < report.detection_ratio

    def test_detection_ratio(self) -> None:
        """detection_ratio = detected / total."""
        report = BASRunner.from_yaml().run()

        assert report.detection_ratio == round(report.detected / report.total, 3)
        assert report.readiness_ratio == round(report.native_detected / report.total, 3)

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

    def test_policy_marks_proxy_language_as_non_native(self) -> None:
        """proxy/계측공백 표현이 있는 시나리오는 native 로 숨길 수 없다."""
        suspicious = (
            "proxy",
            "Proxy",
            "근사",
            "최선근사",
            "계측 공백",
            "설계상 사각지대",
            "제안 스키마",
            "미배포",
            "존재하지 않음",
            "관례",
        )
        scenarios = BASRunner.from_yaml()._scenarios
        mislabeled = [
            scenario.id
            for scenario in scenarios
            if scenario.instrumentation_status == "native"
            and any(token in " ".join(scenario.signals) for token in suspicious)
        ]

        assert mislabeled == []

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
        assert report.native_detected == 1
        assert report.gaps == ["SX-GAP"]

    def test_proxy_rule_is_detected_but_not_native_ready(self) -> None:
        """proxy 계측은 룰 존재로는 탐지되지만 native readiness 로 집계하지 않는다."""
        report = BASRunner(
            [
                BASScenario(
                    id="SX-PROXY",
                    signals=["sig"],
                    detection_rule="x.json",
                    instrumentation_status="proxy",
                )
            ]
        ).run()

        assert report.detected == 1
        assert report.native_detected == 0
        assert report.proxy_detected == 1
        assert report.detection_ratio == 1.0
        assert report.readiness_ratio == 0.0

    def test_quality_gaps_are_grouped_as_remediation_backlog(self) -> None:
        """비-native 탐지는 계측 보완 백로그로 그룹화해 우선순위를 줄 수 있다."""
        report = BASRunner.from_yaml().run()

        assert report.remediation_backlog
        top = report.remediation_backlog[0]
        assert top.status in {"proxy", "reconstructed"}
        assert top.scenario_count >= report.remediation_backlog[-1].scenario_count
        assert sum(item.scenario_count for item in report.remediation_backlog) == sum(
            len(ids) for ids in report.quality_gaps.values()
        )

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
