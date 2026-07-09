"""DynamicsTracker 배선 — graph 주입(죽은 severity 룰 활성) + hotpath 지속 싱글톤.

DynamicsTracker core 로직은 test_dynamics.py 커버. 여기선 배선만:
(1) build_soc_graph(dynamics=) 가 dwelling/lateral 을 triage severity 에 반영,
(2) 미주입 시 현행 severity 불변(회귀), (3) hotpath 지속 싱글톤·리셋·비활성.
Spec: docs/superpowers/specs/2026-07-09-dynamics-tracker-wiring-design.md
"""

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from agents.graph import build_soc_graph
from app import hotpath
from core.dynamics import DynamicsTracker
from core.models import Alert, Severity, Verdict
from core.settings import Settings

_FIXED = datetime(2026, 7, 9, 12, 0, 0, tzinfo=UTC)


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "id": "A",
        "scenario_id": "S1",
        "title": "t",
        "asset_id": "GNSS",
        "asset_tier": "T2-Important",
        "mission_phase": "pre-flight",
        "posture": "normal",
        "severity_baseline": Severity.LOW,
        "signals": ["sig"],
        "defense_playbook": {"id": "PB", "actions": []},
        "ground_truth": Verdict.TRUE_POSITIVE,
    }
    base.update(overrides)
    return Alert.model_validate(base)


class TestGraphDynamicsInjection:
    @pytest.mark.asyncio
    async def test_lateral_escalates_via_injected_dynamics(self) -> None:
        """등록 upstream 침해 후 하류 경보 → dynamics lateral → severity 격상."""
        tracker = DynamicsTracker(
            upstream_assets=frozenset({"C2_LINK"}), clock=lambda: _FIXED
        )
        graph = build_soc_graph(retriever=None, dynamics=tracker)
        # 상위자산(C2_LINK) 침해 관측 → upstream 활성.
        await graph.ainvoke({"alert": _alert(asset_id="C2_LINK", scenario_id="S2")})
        # 하류 경보(GNSS, baseline l) → lateral → severity 하한 m.
        out = await graph.ainvoke({"alert": _alert(asset_id="GNSS")})
        assert out["severity"] == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_no_dynamics_severity_unchanged(self) -> None:
        """dynamics 미주입 → dwelling/lateral 없음 → 현행 severity(l) 불변(회귀)."""
        graph = build_soc_graph(retriever=None)
        await graph.ainvoke({"alert": _alert(asset_id="C2_LINK", scenario_id="S2")})
        out = await graph.ainvoke({"alert": _alert(asset_id="GNSS")})
        assert out["severity"] == Severity.LOW


class TestHotpathDynamicsSingleton:
    @pytest.fixture(autouse=True)
    def _reset(self) -> Iterator[None]:
        hotpath.reset_dynamics()
        yield
        hotpath.reset_dynamics()

    def test_persists_same_instance(self) -> None:
        """지연 구성 후 동일 인스턴스 재사용(이력 지속)."""
        s = Settings(dynamics_enabled=True)
        first = hotpath._get_dynamics(s)
        second = hotpath._get_dynamics(s)
        assert first is second
        assert isinstance(first, DynamicsTracker)

    def test_disabled_yields_none(self) -> None:
        """dynamics_enabled=False → None(현행 severity 보존)."""
        assert hotpath._get_dynamics(Settings(dynamics_enabled=False)) is None

    def test_reset_rebuilds(self) -> None:
        """reset 후 재구성 → 새 인스턴스."""
        s = Settings(dynamics_enabled=True)
        first = hotpath._get_dynamics(s)
        hotpath.reset_dynamics()
        assert hotpath._get_dynamics(s) is not first
