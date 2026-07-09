"""hotpath 크로스-alert 상관 배선 — S9 집약 재투입·실패격리·분리계량·재귀방지.

AlertCorrelator 자체 로직은 test_correlation.py 가 커버. 여기선 hotpath 배선만
스텁 그래프로 격리 검증(전체 파이프라인 무관, 결정론). 시간은 _now monkeypatch 제어.
Spec: docs/superpowers/specs/2026-07-09-alert-correlation-ingest-design.md
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from app import hotpath
from app.metrics import metrics
from core.models import Severity, Verdict
from core.settings import Settings

_FIXED = datetime(2026, 7, 9, 12, 0, 0, tzinfo=UTC)
_S9 = "UAV-SWARM-SATURATION-009"


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch) -> Any:
    """correlator 리셋 + 시간 고정(윈도우 미소멸)."""
    hotpath.reset_correlator()
    monkeypatch.setattr(hotpath, "_now", lambda: _FIXED)
    yield
    hotpath.reset_correlator()


class _StubGraph:
    """파이프라인 스텁 — 상관 배선만 격리. S9 실패 주입 옵션."""

    def __init__(self, fail_on_s9: bool = False) -> None:
        self._fail_on_s9 = fail_on_s9

    async def ainvoke(self, inp: dict[str, Any]) -> dict[str, Any]:
        alert = inp["alert"]
        if self._fail_on_s9 and alert.scenario_id == _S9:
            raise RuntimeError("집약 처리 실패")
        return {
            "report": SimpleNamespace(
                verdict=Verdict.TRUE_POSITIVE, decoy_placements=[]
            ),
            "severity": Severity.HIGH,
            "node_timings": [],
        }


def _use_stub(monkeypatch: pytest.MonkeyPatch, *, fail_on_s9: bool = False) -> None:
    stub = _StubGraph(fail_on_s9=fail_on_s9)
    monkeypatch.setattr(hotpath, "build_soc_graph", lambda **_kw: stub)


def _payload(i: int, asset: str) -> dict[str, object]:
    return {
        "id": f"A{i}",
        "scenario_id": "S1",
        "title": "t",
        "asset_id": asset,
        "severity_baseline": "m",
    }


class TestCorrelationWiring:
    @pytest.mark.asyncio
    async def test_storm_fires_aggregate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """동일 자산 5건(storm_count) → alert_storm 집약 + S9 판정."""
        _use_stub(monkeypatch)
        res: dict[str, object] = {}
        for i in range(5):
            res = await hotpath._run_alert(_payload(i, "GNSS"))
        corr = res["correlation"]
        assert isinstance(corr, dict)
        assert corr["pattern"] == "alert_storm"
        assert corr["aggregate_verdict"] == str(Verdict.TRUE_POSITIVE)
        assert str(corr["aggregate_id"]).startswith("CORR-")

    @pytest.mark.asyncio
    async def test_multi_axis_fires_aggregate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """서로 다른 자산 3건(multi_axis_assets) → multi_axis 집약."""
        _use_stub(monkeypatch)
        res: dict[str, object] = {}
        for i, asset in enumerate(["GNSS", "C2_LINK", "GCS"]):
            res = await hotpath._run_alert(_payload(i, asset))
        corr = res["correlation"]
        assert isinstance(corr, dict)
        assert corr["pattern"] == "multi_axis"

    @pytest.mark.asyncio
    async def test_single_alert_no_correlation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """1건 → correlation 키 없음."""
        _use_stub(monkeypatch)
        res = await hotpath._run_alert(_payload(0, "GNSS"))
        assert "correlation" not in res

    @pytest.mark.asyncio
    async def test_disabled_no_correlation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """correlation_enabled=False → correlator None, 무발화."""
        _use_stub(monkeypatch)
        monkeypatch.setattr(
            hotpath, "get_settings", lambda: Settings(correlation_enabled=False)
        )
        hotpath.reset_correlator()
        res: dict[str, object] = {}
        for i in range(6):
            res = await hotpath._run_alert(_payload(i, "GNSS"))
        assert "correlation" not in res

    @pytest.mark.asyncio
    async def test_aggregate_not_re_observed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codex I2 — S9 집약 alert 는 correlator 윈도우에 재관측 안 됨(피드백 방지)."""
        _use_stub(monkeypatch)
        for i in range(5):
            await hotpath._run_alert(_payload(i, "GNSS"))
        assert hotpath._correlator is not None
        member_ids = [a.id for _, a in hotpath._correlator._window]
        assert not any(mid.startswith("CORR-") for mid in member_ids)

    @pytest.mark.asyncio
    async def test_aggregate_failure_isolated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codex I6-2 — 집약 예외 → inbound 판정 유지 + correlation.error."""
        _use_stub(monkeypatch, fail_on_s9=True)
        res: dict[str, object] = {}
        for i in range(5):
            res = await hotpath._run_alert(_payload(i, "GNSS"))
        # inbound 판정은 온전
        assert res["verdict"] == str(Verdict.TRUE_POSITIVE)
        corr = res["correlation"]
        assert isinstance(corr, dict)
        assert "error" in corr
        assert corr["pattern"] == "alert_storm"
        assert "aggregate_verdict" not in corr

    @pytest.mark.asyncio
    async def test_metrics_no_double_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codex I5 — inbound(alerts_total)·집약(aggregate) 분리 계량."""
        _use_stub(monkeypatch)
        m = metrics()
        before_inbound = m.alerts_total
        before_agg = m.aggregate_alerts_total
        before_fired = m.correlation_fired_total.get("alert_storm", 0)
        for i in range(5):
            await hotpath._run_alert(_payload(i, "GNSS"))
        assert m.alerts_total == before_inbound + 5  # inbound 만 (집약 미포함)
        assert m.aggregate_alerts_total == before_agg + 1
        assert m.correlation_fired_total.get("alert_storm", 0) == before_fired + 1

    @pytest.mark.asyncio
    async def test_failure_metric_recorded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """집약 실패 시 correlation_error 계량 + aggregate 미증가."""
        _use_stub(monkeypatch, fail_on_s9=True)
        m = metrics()
        before_err = m.correlation_error_total
        before_agg = m.aggregate_alerts_total
        for i in range(5):
            await hotpath._run_alert(_payload(i, "GNSS"))
        assert m.correlation_error_total == before_err + 1
        assert m.aggregate_alerts_total == before_agg  # 실패라 집약 계량 안 함
