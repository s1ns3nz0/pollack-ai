"""Prometheus 메트릭 렌더 — 런타임 카운터 + 커버리지 KPI exposition."""

from app.metrics import _Counters, render_text


class TestRuntimeCounters:
    def test_record_alert_and_verdict(self) -> None:
        c = _Counters()
        c.record_alert("true_positive")
        c.record_alert("true_positive")
        c.record_alert("false_positive")
        assert c.alerts_total == 3
        assert c.verdict_total["true_positive"] == 2
        assert c.verdict_total["false_positive"] == 1

    def test_node_avg(self) -> None:
        c = _Counters()
        c.observe_node("triage", 10.0)
        c.observe_node("triage", 20.0)
        assert c.node_avg_ms()["triage"] == 15.0


class TestRenderText:
    def test_includes_runtime_and_coverage_metrics(self) -> None:
        body = render_text()
        # 런타임 카운터
        assert "# TYPE soc_alerts_total counter" in body
        assert "soc_alerts_total " in body
        # 커버리지 KPI 게이지(실 데이터 존재)
        assert "soc_attack_coverage_ratio" in body
        assert "soc_attack_quality_adjusted_ratio" in body
        assert "soc_attack_addressable_ratio" in body
        assert "soc_bas_readiness_ratio" in body
        assert "soc_runbook_readiness_ratio" in body
        assert 'soc_runbook_total{detail_level="generated"}' in body
        assert "soc_bas_quality_gap_total" in body
        assert 'soc_attack_technique_quality_total{quality="proxy"}' in body
        assert 'soc_attack_technique_total{status="covered"}' in body

    def test_archetype_and_tactic_labels(self) -> None:
        body = render_text()
        assert 'soc_attack_gap_total{archetype="A_pre_compromise"}' in body
        assert 'soc_attack_tactic_uncovered{tactic="Collection"}' in body

    def test_valid_exposition_lines(self) -> None:
        # 주석 외 라인은 'name value' 또는 'name{labels} value' 형식.
        for line in render_text().splitlines():
            if not line or line.startswith("#"):
                continue
            assert len(line.rsplit(" ", 1)) == 2
            float(line.rsplit(" ", 1)[1])  # 값은 숫자
