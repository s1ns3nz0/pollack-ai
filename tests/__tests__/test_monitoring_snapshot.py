"""지표 스냅샷 수집 테스트 — 런타임 카운터 + coverage + BAS 통합."""

from core.monitoring import collect_snapshot


class TestCollectSnapshot:
    """현재 방어 지표를 SLO 평가용 스냅샷으로 수집."""

    def test_includes_bas_and_coverage(self) -> None:
        """BAS 탐지율·커버리지가 스냅샷에 포함(정책 파일 기반, 상시 계산)."""
        snap = collect_snapshot()

        assert "bas_detection_ratio" in snap
        assert "attack_coverage_ratio" in snap

    def test_includes_runtime_counters(self) -> None:
        """런타임 카운터(축출 실패·임무 중단·경보수)가 포함."""
        snap = collect_snapshot()

        assert "eviction_failed_total" in snap
        assert "mission_abort_total" in snap
        assert "alerts_total" in snap

    def test_values_are_numeric(self) -> None:
        """모든 값이 수치."""
        snap = collect_snapshot()

        assert all(isinstance(v, (int, float)) for v in snap.values())
