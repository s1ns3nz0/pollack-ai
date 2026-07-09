"""Deployment A — SOC 핫패스(지연민감, single-replica).

경보를 수신해 LangGraph 파이프라인(Triage→Investigation→Validation→Response/
RuleUpdate→Report)을 1건씩 실행한다. 상태 보유 컴포넌트(AlertCorrelator 등)로 인해
단일 레플리카로 운용한다(ADR 0002 D6). 헬스 서버는 K8s 프로브용.

표준 라이브러리 HTTP 서버로 `POST /alert`(JSON Alert)을 받아 그래프를 실행하고
판정 요약을 반환한다. 외부 의존(RAGFlow/LLM)은 그래프 내부에서 graceful degrade.
"""

from __future__ import annotations

import asyncio
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

from agents.graph import build_soc_graph
from app.health import content_type_for, route
from app.metrics import metrics
from core.models import UntrustedAlertPayload, has_forged_internal_fields
from core.settings import get_settings
from utils.logging import get_logger

_logger = get_logger("hotpath")


async def _run_alert(payload: dict[str, object]) -> dict[str, object]:
    """경보 1건을 파이프라인에 태워 판정 요약을 반환한다(+ 메트릭 계측).

    구조적 신뢰경계: untrusted HTTP 입력은 `UntrustedAlertPayload`(whitelist wire
    모델)로만 파싱한다. 파이프라인 내부/게이트 산출 필드(actor_id·enrich 플래그·
    ground_truth·posture·defense_playbook 등 `_INTERNAL_ONLY_FIELDS`)는 wire 모델에
    없어 위조가 구조적으로 불가능하다. 위조 시도는 로깅해 telemetry 로 남긴다.
    """
    forged = has_forged_internal_fields(payload)
    if forged:
        _logger.warning("inbound alert 내부전용 필드 위조 시도 드롭: %s", forged)
    alert = UntrustedAlertPayload.model_validate(payload).to_alert()
    graph = build_soc_graph(settings=get_settings())
    state = await graph.ainvoke({"alert": alert})
    report = state["report"]
    verdict = str(report.verdict)
    metrics().record_alert(verdict)
    if report.decoy_placements:
        metrics().record_decoy_placed(len(report.decoy_placements))
    for timing in state.get("node_timings", []):
        node = timing.get("node")
        elapsed = timing.get("elapsed_ms")
        if isinstance(node, str) and isinstance(elapsed, (int, float)):
            metrics().observe_node(node, float(elapsed))
    return {
        "alert_id": alert.id,
        "verdict": verdict,
        "severity": str(state.get("severity", "")),
    }


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        status, body = route(self.path)
        self._send(status, body, content_type_for(self.path))

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.startswith("/alert"):
            self._send(404, "not found")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            result = asyncio.run(_run_alert(payload))
            self._send(200, json.dumps(result, ensure_ascii=False))
        except (ValueError, KeyError) as exc:
            self._send(400, json.dumps({"error": str(exc)}))

    def _send(
        self, status: int, body: str, content_type: str = "application/json"
    ) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args: object) -> None:
        return


def main(port: int = 8080) -> None:
    """핫패스 HTTP 서버를 기동한다(blocking)."""
    _logger.info("SOC 핫패스 기동: :%d", port)
    HTTPServer(("0.0.0.0", port), _Handler).serve_forever()  # noqa: S104


if __name__ == "__main__":
    main()
