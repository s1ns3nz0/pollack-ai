"""공통 헬스 엔드포인트 — K8s liveness/readiness 프로브 백엔드(표준 라이브러리).

웹 프레임워크 의존 없이 `http.server` 로 가벼운 `/healthz`(liveness)·`/readyz`
(readiness)·`/metrics`(커버리지 KPI 스냅샷)를 제공한다. 라우팅은 순수 함수
`route()` 로 분리해 소켓 없이 단위 테스트한다.
"""

from __future__ import annotations

from threading import Thread

_OK = "ok"


def route(path: str, ready: bool = True) -> tuple[int, str]:
    """경로를 (HTTP 상태, 본문)으로 매핑한다(순수 — 테스트 가능).

    `/metrics` 는 Prometheus 텍스트(런타임 카운터 + 커버리지 KPI)를 반환한다.

    Args:
        path: 요청 경로.
        ready: readiness 상태(False 면 `/readyz` 503).

    Returns:
        (상태코드, 응답 본문) 튜플.
    """
    if path.startswith("/healthz"):
        return (200, _OK)
    if path.startswith("/readyz"):
        return (200, _OK) if ready else (503, "not ready")
    if path.startswith("/metrics"):
        from app.metrics import render_text

        return (200, render_text())
    return (404, "not found")


def content_type_for(path: str) -> str:
    """경로별 응답 Content-Type(메트릭은 Prometheus 형식)."""
    if path.startswith("/metrics"):
        from app.metrics import content_type

        return content_type()
    return "text/plain; charset=utf-8"


def serve_in_background(port: int = 8080) -> Thread:
    """백그라운드 스레드로 헬스 서버를 띄운다(데몬). 스레드를 반환한다."""
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http.server 규약
            status, body = route(self.path)
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type_for(self.path))
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args: object) -> None:
            return  # 기본 stderr 로깅 억제

    server = HTTPServer(("0.0.0.0", port), _Handler)  # noqa: S104 - 컨테이너 내부
    thread = Thread(target=server.serve_forever, daemon=True, name="health")
    thread.start()
    return thread
