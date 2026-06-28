"""모니터링 매니페스트 — ServiceMonitor·Grafana 대시보드(유효 JSON)·메트릭 일관성."""

import json
from pathlib import Path

import yaml

from app.metrics import render_text

_MON = Path(__file__).resolve().parents[2] / "deploy" / "monitoring"


def _docs() -> list[dict]:
    out: list[dict] = []
    for f in sorted(_MON.glob("*.yaml")):
        for d in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if isinstance(d, dict):
                out.append(d)
    return out


class TestServiceMonitor:
    def test_present_and_scrapes_metrics(self) -> None:
        sm = next(d for d in _docs() if d.get("kind") == "ServiceMonitor")
        assert sm["spec"]["selector"]["matchLabels"]["monitoring"] == "enabled"
        ep = sm["spec"]["endpoints"][0]
        assert ep["port"] == "http"
        assert ep["path"] == "/metrics"


class TestGrafanaDashboard:
    def _dashboard(self) -> dict:
        cm = next(
            d
            for d in _docs()
            if d.get("kind") == "ConfigMap"
            and d["metadata"]["labels"].get("grafana_dashboard") == "1"
        )
        raw = next(iter(cm["data"].values()))
        return json.loads(raw)  # 유효 JSON 이어야 함

    def test_dashboard_json_valid(self) -> None:
        dash = self._dashboard()
        assert dash["uid"] == "uav-soc-kpi"
        assert len(dash["panels"]) >= 4

    def test_panel_metrics_are_exported(self) -> None:
        # 대시보드가 참조하는 메트릭이 실제 /metrics 에 노출되는지 교차검증.
        exposed = render_text()
        exprs = " ".join(
            t["expr"] for p in self._dashboard()["panels"] for t in p.get("targets", [])
        )
        for metric in (
            "soc_attack_coverage_ratio",
            "soc_attack_gap_total",
            "soc_alerts_total",
            "soc_node_latency_avg_ms",
        ):
            assert metric in exprs  # 대시보드에 있고
            assert metric in exposed  # 노출기에도 있음
