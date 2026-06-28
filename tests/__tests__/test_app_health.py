"""헬스 라우팅 — liveness/readiness/metrics/404(소켓 없이 순수 함수 검증)."""

from app.health import content_type_for, route


class TestRoute:
    def test_healthz_ok(self) -> None:
        assert route("/healthz") == (200, "ok")

    def test_readyz_ready(self) -> None:
        assert route("/readyz", ready=True) == (200, "ok")

    def test_readyz_not_ready_503(self) -> None:
        status, _ = route("/readyz", ready=False)
        assert status == 503

    def test_metrics_returns_prometheus_text(self) -> None:
        status, body = route("/metrics")
        assert status == 200
        assert "soc_alerts_total" in body  # Prometheus exposition

    def test_metrics_content_type(self) -> None:
        assert content_type_for("/metrics").startswith("text/plain; version=0.0.4")

    def test_unknown_404(self) -> None:
        assert route("/nope")[0] == 404
