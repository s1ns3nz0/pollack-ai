"""헬스 라우팅 — liveness/readiness/metrics/404(소켓 없이 순수 함수 검증)."""

import json

from app.health import route


class TestRoute:
    def test_healthz_ok(self) -> None:
        assert route("/healthz") == (200, "ok")

    def test_readyz_ready(self) -> None:
        assert route("/readyz", ready=True) == (200, "ok")

    def test_readyz_not_ready_503(self) -> None:
        status, _ = route("/readyz", ready=False)
        assert status == 503

    def test_metrics_returns_json(self) -> None:
        status, body = route("/metrics")
        assert status == 200
        json.loads(body)  # 유효 JSON(커버리지 스냅샷 또는 {})

    def test_unknown_404(self) -> None:
        assert route("/nope")[0] == 404
