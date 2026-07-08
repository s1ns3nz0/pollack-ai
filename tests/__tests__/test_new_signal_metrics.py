"""신규 격상신호 관측성 — decoy_hit/key_terrain/bda_restore 메트릭(killchain 동형)."""

import pytest

from app.metrics import _Counters, render_text


@pytest.fixture(autouse=True)
def _isolate_global_counters():  # type: ignore[no-untyped-def]
    """전역 _METRICS 신규 카운터를 테스트마다 스냅샷·복원(교차오염 방지, Codex Low)."""
    from app import metrics as m

    fields = ("decoy_hit_total", "key_terrain_total", "bda_restore_total")
    saved = {f: getattr(m._METRICS, f) for f in fields}
    yield
    for f, v in saved.items():
        setattr(m._METRICS, f, v)


class TestCounters:
    """카운터 누적 + 렌더."""

    def test_decoy_and_key_terrain_counters(self) -> None:
        c = _Counters()
        c.record_decoy_hit()
        c.record_key_terrain()
        c.record_key_terrain()
        assert c.decoy_hit_total == 1
        assert c.key_terrain_total == 2

    def test_bda_restore_counter(self) -> None:
        c = _Counters()
        c.record_bda_restore(3)
        assert c.bda_restore_total == 3

    def test_render_emits_when_nonzero(self) -> None:
        from app import metrics as m

        m._METRICS.record_decoy_hit()
        m._METRICS.record_key_terrain()
        m._METRICS.record_bda_restore()
        text = render_text()
        assert "soc_decoy_hit_total" in text
        assert "soc_key_terrain_total" in text
        assert "soc_bda_restore_total" in text


class TestReportNodeCounts:
    """report 노드가 decoy_hit/key_terrain 격상을 계측(killchain 동형)."""

    @pytest.mark.asyncio
    async def test_report_counts_key_terrain(self) -> None:
        from agents.graph import build_soc_graph
        from app import metrics as m
        from core.models import Alert, Severity

        before = m._METRICS.key_terrain_total
        graph = build_soc_graph()
        # GNSS + ingress = 핵심지형(내부 enricher 가 key_terrain 세팅)
        alert = Alert(
            id="kt1",
            scenario_id="S1",
            title="t",
            asset_id="GNSS",
            mission_phase="ingress",
            severity_baseline=Severity.MEDIUM,
            signals=["sig"],
            mitre={"tactics": ["c2"], "techniques": ["T1071"]},
        )
        await graph.ainvoke({"alert": alert})
        assert m._METRICS.key_terrain_total == before + 1
