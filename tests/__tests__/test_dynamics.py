"""DynamicsTracker — 체류시간/횡적상관 신호 산정 + 등급 동적조정 검증."""

from datetime import datetime, timedelta

from core.dynamics import DynamicsTracker
from core.models import Alert, Severity
from core.severity import SeverityEngine

_T0 = datetime(2026, 1, 1, 12, 0, 0)


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "id": "A",
        "scenario_id": "S1",
        "title": "테스트 경보",
        "asset_id": "GNSS",
        "asset_tier": "T2-Important",
        "mission_phase": "on-station",
        "posture": "normal",
        "severity_baseline": Severity.MEDIUM,
    }
    base.update(overrides)
    return Alert.model_validate(base)


class TestDwellingTime:
    """체류시간(dwelling_min) 산정 + 임계 초과 시 등급 상향."""

    def test_first_observation_is_zero(self) -> None:
        """최초 관측은 체류 0분."""
        tracker = DynamicsTracker()
        enriched = tracker.enrich(_alert(), _T0)
        assert enriched.dwelling_min == 0

    def test_dwell_grows_and_escalates(self) -> None:
        """동일 위협 31분 지속 → 체류 31분 → 정책 dwelling_time_exceeds(+1) 발동."""
        tracker = DynamicsTracker()
        engine = SeverityEngine()
        alert = _alert()
        tracker.enrich(alert, _T0)  # 최초 관측
        later = tracker.enrich(alert, _T0 + timedelta(minutes=31))
        assert later.dwelling_min == 31
        base_level, _ = engine.compute(alert)  # dwell 0
        dwell_level, rationale = engine.compute(later)  # dwell 31
        assert base_level == Severity.MEDIUM
        assert dwell_level == Severity.HIGH  # m +1(dwell) = h
        assert any("dwelling" in r for r in rationale)


class TestLateralCorrelation:
    """상위자산(GCS/C2) 침해 시 의존 기체 횡적상관."""

    def test_upstream_compromise_marks_dependent(self) -> None:
        """GCS 침해 활성 중 의존 기체 경보 → lateral_correlation → 등급 하한 m."""
        tracker = DynamicsTracker()
        engine = SeverityEngine()
        tracker.enrich(_alert(asset_id="GCS-01", scenario_id="S6"), _T0)
        dependent = tracker.enrich(
            _alert(asset_id="GNSS", severity_baseline=Severity.LOW),
            _T0 + timedelta(minutes=5),
        )
        assert dependent.lateral_correlation is True
        level, rationale = engine.compute(dependent)
        assert level == Severity.MEDIUM  # l → lateral floor m
        assert any("lateral" in r for r in rationale)

    def test_no_lateral_without_upstream(self) -> None:
        """상위자산 침해 없으면 횡적상관 없음."""
        tracker = DynamicsTracker()
        enriched = tracker.enrich(_alert(asset_id="GNSS"), _T0)
        assert enriched.lateral_correlation is False

    def test_upstream_window_expires(self) -> None:
        """상위자산 침해가 활성창(60분)을 지나면 횡적상관 해제."""
        tracker = DynamicsTracker(upstream_active_min=60)
        tracker.enrich(_alert(asset_id="C2-LINK", scenario_id="S2"), _T0)
        stale = tracker.enrich(_alert(asset_id="GNSS"), _T0 + timedelta(minutes=61))
        assert stale.lateral_correlation is False


class TestRegistryUpstream:
    """레지스트리 기반 upstream 판정(substring 사칭 차단)."""

    def test_registered_upstream_triggers_lateral(self) -> None:
        """등록 upstream(C2_LINK) 침해 활성 중 하류 경보 → lateral."""
        tracker = DynamicsTracker(upstream_assets=frozenset({"C2_LINK"}))
        tracker.enrich(_alert(asset_id="C2_LINK", scenario_id="S2"), _T0)
        dep = tracker.enrich(
            _alert(asset_id="GNSS", severity_baseline=Severity.LOW),
            _T0 + timedelta(minutes=5),
        )
        assert dep.lateral_correlation is True

    def test_forged_unregistered_upstream_no_lateral(self) -> None:
        """레지스트리 모드: 'GCS-fake'(미등록)는 substring 이어도 upstream 아님."""
        tracker = DynamicsTracker(upstream_assets=frozenset({"C2_LINK"}))
        tracker.enrich(_alert(asset_id="GCS-fake", scenario_id="S6"), _T0)
        dep = tracker.enrich(_alert(asset_id="GNSS"), _T0 + timedelta(minutes=5))
        assert dep.lateral_correlation is False


class TestEvictionAndCap:
    """비활성 eviction(활성 dwell 보존) + cardinality 상한."""

    def test_active_incident_dwell_preserved(self) -> None:
        """retention 내 재관측 지속 → 활성 → first_seen 보존 → dwell 유지."""
        tracker = DynamicsTracker(retention_min=60)
        alert = _alert()
        tracker.enrich(alert, _T0)
        tracker.enrich(alert, _T0 + timedelta(minutes=40))  # 활성 재관측
        later = tracker.enrich(alert, _T0 + timedelta(minutes=70))  # gap 30 < 60
        assert later.dwelling_min == 70  # 리셋 안 됨

    def test_inactive_entry_evicted(self) -> None:
        """retention 초과 무활동 → eviction → 재등장 dwell 0."""
        tracker = DynamicsTracker(retention_min=60)
        alert = _alert()
        tracker.enrich(alert, _T0)
        later = tracker.enrich(alert, _T0 + timedelta(minutes=90))  # gap 90 > 60
        assert later.dwelling_min == 0

    def test_max_entries_cap_bounds_history(self) -> None:
        """위조 asset_id 스트림 → 이력 dict 상한 이내로 bounded."""
        tracker = DynamicsTracker(max_entries=10)
        for i in range(50):
            tracker.enrich(
                _alert(asset_id=f"forge-{i}", scenario_id="S1"),
                _T0 + timedelta(seconds=i),
            )
        assert len(tracker._first_seen) <= 10


class TestInjectableClock:
    """클록 주입 — now 미지정 시 내부 clock 사용."""

    def test_clock_drives_dwell(self) -> None:
        """clock 주입 + enrich(now 생략) → clock 시각으로 dwell 산정."""
        cur = [_T0]
        tracker = DynamicsTracker(clock=lambda: cur[0])
        first = tracker.enrich(_alert())
        assert first.dwelling_min == 0
        cur[0] = _T0 + timedelta(minutes=31)
        later = tracker.enrich(_alert())
        assert later.dwelling_min == 31
