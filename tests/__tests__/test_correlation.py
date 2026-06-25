"""AlertCorrelator — 다중경보 상관·집약(S9) 검증."""

from datetime import datetime, timedelta

from core.correlation import AlertCorrelator
from core.models import Alert, Severity
from core.severity import SeverityEngine

_T0 = datetime(2026, 1, 1, 12, 0, 0)


def _alert(asset: str, scenario: str = "S?", idx: int = 0) -> Alert:
    return Alert(
        id=f"A-{asset}-{idx}",
        scenario_id=scenario,
        title=f"{asset} 경보",
        asset_id=asset,
        asset_tier="T1-Critical",
        mission_phase="on-station",
        severity_baseline=Severity.MEDIUM,
    )


class TestAlertStorm:
    """경보 폭주(같은/소수 자산에 다수 경보)."""

    def test_storm_fires_on_threshold(self) -> None:
        """윈도우 내 5건 이상 → alert_storm 집약."""
        corr = AlertCorrelator(window_sec=300, storm_count=5, multi_axis_assets=99)
        incident = None
        for i in range(5):
            incident = corr.observe(
                _alert("GNSS", "S1", i), _T0 + timedelta(seconds=i * 10)
            )
        assert incident is not None
        assert incident.pattern == "alert_storm"
        assert incident.count == 5

    def test_sparse_no_incident(self) -> None:
        """윈도우 밖으로 흩어진 경보는 집약 안 됨."""
        corr = AlertCorrelator(window_sec=60, storm_count=3, multi_axis_assets=99)
        results = [
            corr.observe(_alert("GNSS", "S1", i), _T0 + timedelta(seconds=i * 120))
            for i in range(4)
        ]
        assert all(r is None for r in results)


class TestMultiAxis:
    """다축 동시침해(서로 다른 자산 동시 경보)."""

    def test_multi_axis_fires_and_escalates(self) -> None:
        """3개 자산 동시 경보 → multi_axis 집약 → S9 경보가 등급 상향."""
        corr = AlertCorrelator(window_sec=300, storm_count=99, multi_axis_assets=3)
        corr.observe(_alert("GNSS", "S1"), _T0)
        corr.observe(_alert("C2_LINK", "S2"), _T0 + timedelta(seconds=5))
        incident = corr.observe(_alert("GCS", "S6"), _T0 + timedelta(seconds=10))
        assert incident is not None
        assert incident.pattern == "multi_axis"
        assert incident.distinct_assets == 3

        agg = corr.to_aggregate_alert(incident)
        assert agg.scenario_id == "UAV-SWARM-SATURATION-009"
        assert agg.lateral_correlation is True
        level, _ = SeverityEngine().compute(agg)
        assert level == Severity.HIGH  # baseline h + T0/lateral → h 유지·상향


class TestSuppressionRearm:
    """중복 발화 억제 + 군집 종료 후 재무장."""

    def test_duplicate_suppressed_then_rearm(self) -> None:
        """동일 군집 1회만 발화, 윈도우 비워지면 재무장."""
        corr = AlertCorrelator(window_sec=30, storm_count=3, multi_axis_assets=99)
        first = None
        for i in range(3):
            first = corr.observe(_alert("GNSS", "S1", i), _T0 + timedelta(seconds=i))
        dup = corr.observe(_alert("GNSS", "S1", 3), _T0 + timedelta(seconds=4))
        assert first is not None
        assert dup is None  # 동일 군집 억제
        # 윈도우(30s) 비워진 뒤 새 군집
        base = _T0 + timedelta(seconds=120)
        again = None
        for i in range(3):
            again = corr.observe(
                _alert("GNSS", "S1", 10 + i), base + timedelta(seconds=i)
            )
        assert again is not None  # 재무장 후 재발화
