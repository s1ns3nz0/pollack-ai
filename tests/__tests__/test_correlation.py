"""AlertCorrelator — 다중경보 상관·집약(S9) 검증."""

from datetime import datetime, timedelta

from core.correlation import AlertCorrelator
from core.models import Alert, Severity
from core.severity import SeverityEngine
from core.terrain import KeyTerrainMap

_T0 = datetime(2026, 1, 1, 12, 0, 0)
_HASH = "a" * 64  # 유효 sha256 형태(shape 산열 통과)


def _alert(
    asset: str, scenario: str = "S?", idx: int = 0, iocs: list[str] | None = None
) -> Alert:
    return Alert(
        id=f"A-{asset}-{idx}",
        scenario_id=scenario,
        title=f"{asset} 경보",
        asset_id=asset,
        asset_tier="T1-Critical",
        mission_phase="on-station",
        severity_baseline=Severity.MEDIUM,
        iocs=iocs or [],
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


def _quiet(**over: object) -> AlertCorrelator:
    """storm/multi_axis 비활성(임계 99)한 correlator — 클러스터만 격리 검증."""
    kw: dict[str, object] = {
        "window_sec": 300,
        "storm_count": 99,
        "multi_axis_assets": 99,
    }
    kw.update(over)
    return AlertCorrelator(**kw)  # type: ignore[arg-type]


class TestSharedIocCluster:
    """공유 IOC 의미 상관 클러스터."""

    def test_shared_ioc_forms_cluster(self) -> None:
        """공통 IOC + 서로 다른 2자산 ≥ cluster_min → correlated_cluster."""
        corr = _quiet(cluster_min=2)
        corr.observe(_alert("GNSS", "S1", 0, iocs=[_HASH]), _T0)
        inc = corr.observe(
            _alert("C2_LINK", "S2", 1, iocs=[_HASH]), _T0 + timedelta(seconds=5)
        )
        assert inc is not None
        assert inc.pattern == "correlated_cluster"
        assert "shared_ioc" in inc.edge_kinds
        assert inc.distinct_assets == 2

    def test_malformed_ioc_no_edge(self) -> None:
        """사설 IP IOC 는 산열 드롭 → 공유 엣지 없음 → 클러스터 아님."""
        corr = _quiet(cluster_min=2)
        corr.observe(_alert("GNSS", "S1", 0, iocs=["192.168.0.1"]), _T0)
        inc = corr.observe(
            _alert("C2_LINK", "S2", 1, iocs=["192.168.0.1"]),
            _T0 + timedelta(seconds=5),
        )
        assert inc is None

    def test_single_asset_repeat_no_cluster(self) -> None:
        """공유 IOC 여도 동일 자산 반복(distinct<2) → 클러스터 아님."""
        corr = _quiet(cluster_min=2)
        corr.observe(_alert("GNSS", "S1", 0, iocs=[_HASH]), _T0)
        inc = corr.observe(
            _alert("GNSS", "S1", 1, iocs=[_HASH]), _T0 + timedelta(seconds=5)
        )
        assert inc is None

    def test_cluster_min_threshold(self) -> None:
        """연결요소 크기가 cluster_min 미만 → 미발화."""
        corr = _quiet(cluster_min=3)
        corr.observe(_alert("GNSS", "S1", 0, iocs=[_HASH]), _T0)
        inc = corr.observe(
            _alert("C2_LINK", "S2", 1, iocs=[_HASH]), _T0 + timedelta(seconds=5)
        )
        assert inc is None  # 크기 2 < 3


class TestDependencyCluster:
    """자산 의존(depends_on) 엣지 클러스터 — 정책그래프(포이즌 저항)."""

    def test_dependency_edge_forms_cluster(self) -> None:
        """AUTOPILOT depends_on GNSS·C2_LINK → 의존 엣지로 3자산 클러스터."""
        corr = _quiet(terrain=KeyTerrainMap.from_yaml(), cluster_min=3)
        corr.observe(_alert("AUTOPILOT", "S1", 0), _T0)
        corr.observe(_alert("GNSS", "S2", 1), _T0 + timedelta(seconds=5))
        inc = corr.observe(_alert("C2_LINK", "S3", 2), _T0 + timedelta(seconds=10))
        assert inc is not None
        assert inc.pattern == "correlated_cluster"
        assert "dependency" in inc.edge_kinds
        assert inc.distinct_assets == 3

    def test_forged_unregistered_asset_no_dependency(self) -> None:
        """미등록(위조) asset_id → 의존 엣지 0 → 클러스터 아님."""
        corr = _quiet(terrain=KeyTerrainMap.from_yaml(), cluster_min=3)
        inc = None
        for i, a in enumerate(["FAKE-1", "FAKE-2", "FAKE-3"]):
            inc = corr.observe(_alert(a, f"S{i}", i), _T0 + timedelta(seconds=i))
        assert inc is None

    def test_no_terrain_ioc_only(self) -> None:
        """terrain=None → 의존 엣지 스킵(등록 의존자산이라도 IOC 없으면 미발화)."""
        corr = _quiet(terrain=None, cluster_min=2)
        corr.observe(_alert("AUTOPILOT", "S1", 0), _T0)
        inc = corr.observe(_alert("GNSS", "S2", 1), _T0 + timedelta(seconds=5))
        assert inc is None


class TestClusterPrecedenceAndDedup:
    """우선순위 + 패턴별 arm/disarm 상태머신."""

    def test_precedence_cluster_over_storm(self) -> None:
        """같은 observe 서 클러스터+storm 동시 확정 → correlated_cluster(최고 우선)."""
        corr = AlertCorrelator(
            window_sec=300, storm_count=2, multi_axis_assets=99, cluster_min=2
        )
        corr.observe(_alert("GNSS", "S1", 0, iocs=[_HASH]), _T0)
        # 2번째에서 cluster(2자산 공유IOC)·storm(2건) 동시 최초 확정 → precedence
        inc = corr.observe(
            _alert("C2_LINK", "S2", 1, iocs=[_HASH]), _T0 + timedelta(seconds=2)
        )
        assert inc is not None
        assert inc.pattern == "correlated_cluster"

    def test_cluster_dedup_no_refire(self) -> None:
        """동일 클러스터가 성장해도 재발화 없음."""
        corr = _quiet(cluster_min=2)
        corr.observe(_alert("GNSS", "S1", 0, iocs=[_HASH]), _T0)
        first = corr.observe(
            _alert("C2_LINK", "S2", 1, iocs=[_HASH]), _T0 + timedelta(seconds=2)
        )
        second = corr.observe(
            _alert("GCS", "S3", 2, iocs=[_HASH]), _T0 + timedelta(seconds=4)
        )
        assert first is not None and first.pattern == "correlated_cluster"
        assert second is None

    def test_cluster_fired_does_not_starve_storm(self) -> None:
        """클러스터 발화 후에도 별개 storm 조건 충족 시 storm 발화(패턴별 arm)."""
        corr = AlertCorrelator(
            window_sec=300, storm_count=4, multi_axis_assets=99, cluster_min=2
        )
        corr.observe(_alert("GNSS", "S1", 0, iocs=[_HASH]), _T0)
        c = corr.observe(
            _alert("C2_LINK", "S2", 1, iocs=[_HASH]), _T0 + timedelta(seconds=2)
        )
        assert c is not None and c.pattern == "correlated_cluster"
        corr.observe(_alert("GNSS", "S1", 2), _T0 + timedelta(seconds=3))
        s = corr.observe(_alert("GNSS", "S1", 3), _T0 + timedelta(seconds=4))
        assert s is not None
        assert s.pattern == "alert_storm"

    def test_precedence_cluster_over_multi_axis(self) -> None:
        """cluster + multi_axis 동시 충족 → correlated_cluster 반환(우선순위)."""
        corr = AlertCorrelator(
            window_sec=300, storm_count=99, multi_axis_assets=3, cluster_min=3
        )
        corr.observe(_alert("GNSS", "S1", 0, iocs=[_HASH]), _T0)
        corr.observe(
            _alert("C2_LINK", "S2", 1, iocs=[_HASH]), _T0 + timedelta(seconds=1)
        )
        c = corr.observe(
            _alert("SATCOM", "S3", 2, iocs=[_HASH]), _T0 + timedelta(seconds=2)
        )
        # 3자산 공유IOC → cluster + 3 distinct → multi_axis, precedence 는 cluster
        assert c is not None and c.pattern == "correlated_cluster"

    def test_cluster_fired_does_not_starve_multi_axis(self) -> None:
        """cluster 발화 후 multi_axis 새로 충족 시 multi_axis 발화(패턴별 arm)."""
        corr = AlertCorrelator(
            window_sec=300, storm_count=99, multi_axis_assets=3, cluster_min=2
        )
        corr.observe(_alert("GNSS", "S1", 0, iocs=[_HASH]), _T0)
        c = corr.observe(
            _alert("C2_LINK", "S2", 1, iocs=[_HASH]), _T0 + timedelta(seconds=1)
        )
        assert c is not None and c.pattern == "correlated_cluster"  # 2자산, multi 아직
        # 3번째 자산(IOC 없음 → cluster 미편입) → 3 distinct → multi_axis 신규 충족
        m = corr.observe(_alert("SATCOM", "S3", 2), _T0 + timedelta(seconds=2))
        assert m is not None and m.pattern == "multi_axis"


class TestWindowCap:
    """윈도우 하드 상한(DoS 방지)."""

    def test_window_max_alerts_cap(self) -> None:
        """위조 고속 스트림 → 윈도우 ≤ max_alerts."""
        corr = AlertCorrelator(
            window_sec=100000,
            storm_count=99999,
            multi_axis_assets=99999,
            cluster_min=99999,
            max_alerts=10,
        )
        for i in range(50):
            corr.observe(_alert(f"forge-{i}", "S1", i), _T0 + timedelta(seconds=i))
        assert len(corr._window) <= 10
