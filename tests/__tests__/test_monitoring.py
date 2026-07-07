"""SLOMonitor 테스트 — 지표 스냅샷 → SLO 위반 감지(continuous monitoring)."""

from core.monitoring import SLOMonitor


class TestSLOMonitor:
    """지표 임계 대조 → 위반 목록."""

    def test_loads_from_yaml(self) -> None:
        mon = SLOMonitor.from_yaml()
        assert mon.rule_count > 0

    def test_lt_breach_when_below(self) -> None:
        """lt 규칙 — 값이 임계 미만이면 위반."""
        mon = SLOMonitor.from_yaml()

        breaches = mon.evaluate({"bas_detection_ratio": 0.7})

        assert any(b.metric == "bas_detection_ratio" for b in breaches)

    def test_lt_no_breach_when_above(self) -> None:
        """lt 규칙 — 임계 이상이면 위반 아님."""
        mon = SLOMonitor.from_yaml()

        breaches = mon.evaluate({"bas_detection_ratio": 0.95})

        assert not any(b.metric == "bas_detection_ratio" for b in breaches)

    def test_gt_breach_when_above(self) -> None:
        """gt 규칙 — 값이 임계 초과면 위반(축출 실패 발생)."""
        mon = SLOMonitor.from_yaml()

        breaches = mon.evaluate({"eviction_failed_total": 2})

        b = next(b for b in breaches if b.metric == "eviction_failed_total")
        assert b.severity == "critical"
        assert b.message

    def test_gt_no_breach_at_threshold(self) -> None:
        """gt 규칙 — 임계 이하면 위반 아님(0 == threshold)."""
        mon = SLOMonitor.from_yaml()

        breaches = mon.evaluate({"eviction_failed_total": 0})

        assert not any(b.metric == "eviction_failed_total" for b in breaches)

    def test_missing_metric_skipped(self) -> None:
        """스냅샷에 없는 지표는 평가 생략(no breach)."""
        mon = SLOMonitor.from_yaml()

        breaches = mon.evaluate({})

        assert breaches == []

    def test_breach_carries_actual_and_threshold(self) -> None:
        """위반은 실제값·임계·severity 를 담는다."""
        mon = SLOMonitor.from_yaml()

        breaches = mon.evaluate({"mission_abort_total": 1})

        b = next(b for b in breaches if b.metric == "mission_abort_total")
        assert b.actual == 1
        assert b.severity == "critical"
