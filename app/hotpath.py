"""Deployment A — SOC 핫패스(지연민감, single-replica).

경보를 수신해 LangGraph 파이프라인(Triage→Investigation→Validation→Response/
RuleUpdate→Report)을 1건씩 실행한다. 상태 보유 컴포넌트(AlertCorrelator 등)로 인해
단일 레플리카로 운용한다(ADR 0002 D6). 헬스 서버는 K8s 프로브용.

표준 라이브러리 HTTP 서버로 `POST /alert`(JSON Alert)을 받아 그래프를 실행하고
판정 요약을 반환한다. 외부 의존(RAGFlow/LLM)은 그래프 내부에서 graceful degrade.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
from typing import TYPE_CHECKING, cast

from agents.graph import build_soc_graph
from app.health import content_type_for, route
from app.metrics import metrics
from core.correlation import AlertCorrelator, CorrelatedIncident
from core.dynamics import DynamicsTracker
from core.exceptions import SOCPlatformError
from core.models import Alert, UntrustedAlertPayload, has_forged_internal_fields
from core.settings import Settings, get_settings
from core.terrain import KeyTerrainMap
from utils.logging import get_logger

if TYPE_CHECKING:
    from langgraph.graph.state import CompiledStateGraph

    from core.models import SOCState

_logger = get_logger("hotpath")

# 크로스-alert 상관: 지속(persistent) 모듈-전역 correlator. hotpath 는 단일레플리카·
# 비-threading HTTPServer(요청 직렬)라 공유 윈도우가 스레드-안전하나, 향후 threaded
# 전환 대비 correlator 뮤테이션(observe+to_aggregate)을 lock 으로 감싼다(Codex I1).
_correlator: AlertCorrelator | None = None
_correlator_ready = False
_corr_lock = threading.Lock()


def _now() -> datetime:
    """수신시각(UTC). 테스트가 monkeypatch 로 윈도우 시간을 제어(Codex I4)."""
    return datetime.now(UTC)


def _build_correlator(settings: Settings) -> AlertCorrelator:
    """자산 의존 그래프(depends_on 엣지용)를 주입한 correlator 구성.

    KeyTerrainMap 로드 실패 시 terrain=None(공유-IOC 엣지만)으로 degrade.
    """
    terrain: KeyTerrainMap | None = None
    try:
        terrain = KeyTerrainMap.from_yaml()
    except SOCPlatformError as exc:
        _logger.warning("correlation 의존그래프 로드 실패, IOC 엣지만: %s", exc)
    return AlertCorrelator(
        window_sec=settings.correlation_window_sec,
        storm_count=settings.correlation_storm_count,
        multi_axis_assets=settings.correlation_multi_axis_assets,
        terrain=terrain,
        cluster_min=settings.correlation_cluster_min,
        max_alerts=settings.correlation_window_max_alerts,
    )


def _get_correlator(settings: Settings) -> AlertCorrelator | None:
    """지속 correlator 를 지연 구성(비활성이면 None). 최초 1회만.

    지연-init 도 lock 으로 감싼다(double-checked) — 향후 threaded 서버에서 최초
    동시 진입 시 이중 구성 방지(Codex diff Low).
    """
    global _correlator, _correlator_ready
    if not _correlator_ready:
        with _corr_lock:
            if not _correlator_ready:  # 재확인(threaded 최초진입 경합 대비)
                _correlator = (
                    _build_correlator(settings)
                    if settings.correlation_enabled
                    else None
                )
                _correlator_ready = True
    return _correlator


def reset_correlator() -> None:
    """테스트 격리용 — correlator 상태 리셋(autouse fixture 에서 호출)."""
    global _correlator, _correlator_ready
    with _corr_lock:
        _correlator = None
        _correlator_ready = False


# dynamics(체류시간·횡적상관): 지속 모듈-전역 tracker. correlator 와 동형 — 그래프는
# alert 마다 재빌드되나 같은 인스턴스를 주입해 이력을 지속한다(dwelling 산정 필수).
_dynamics: DynamicsTracker | None = None
_dynamics_ready = False
_dyn_lock = threading.Lock()


def _build_dynamics(settings: Settings) -> DynamicsTracker:
    """레지스트리 upstream(asset-tiers dependents)을 주입한 tracker 구성.

    KeyTerrainMap 로드 실패 시 upstream_assets=None(레거시 substring 판정)으로 degrade.
    """
    upstream: frozenset[str] | None = None
    try:
        upstream = KeyTerrainMap.from_yaml().upstream_assets()
    except SOCPlatformError as exc:
        _logger.warning("dynamics upstream 레지스트리 로드 실패, 레거시 판정: %s", exc)
    return DynamicsTracker(
        upstream_active_min=settings.dynamics_upstream_active_min,
        upstream_assets=upstream,
        retention_min=settings.dynamics_retention_min,
        max_entries=settings.dynamics_max_entries,
    )


def _get_dynamics(settings: Settings) -> DynamicsTracker | None:
    """지속 dynamics tracker 지연 구성(비활성이면 None). double-checked lock."""
    global _dynamics, _dynamics_ready
    if not _dynamics_ready:
        with _dyn_lock:
            if not _dynamics_ready:
                _dynamics = (
                    _build_dynamics(settings) if settings.dynamics_enabled else None
                )
                _dynamics_ready = True
    return _dynamics


def reset_dynamics() -> None:
    """테스트 격리용 — dynamics tracker 상태 리셋."""
    global _dynamics, _dynamics_ready
    with _dyn_lock:
        _dynamics = None
        _dynamics_ready = False


def _record_timings(state: SOCState, *, prefix: str = "") -> None:
    """상태의 node_timings 를 메트릭으로 계측(집약은 prefix 로 구분)."""
    for timing in state.get("node_timings", []):
        node = timing.get("node")
        elapsed = timing.get("elapsed_ms")
        if isinstance(node, str) and isinstance(elapsed, (int, float)):
            metrics().observe_node(f"{prefix}{node}", float(elapsed))


async def _run_alert(payload: dict[str, object]) -> dict[str, object]:
    """경보 1건을 파이프라인에 태워 판정 요약을 반환한다(+ 메트릭 계측).

    구조적 신뢰경계: untrusted HTTP 입력은 `UntrustedAlertPayload`(whitelist wire
    모델)로만 파싱한다. 파이프라인 내부/게이트 산출 필드(actor_id·enrich 플래그·
    ground_truth·posture·defense_playbook 등 `_INTERNAL_ONLY_FIELDS`)는 wire 모델에
    없어 위조가 구조적으로 불가능하다. 위조 시도는 로깅해 telemetry 로 남긴다.

    크로스-alert 상관: inbound 처리 후 지속 correlator 로 관측한다. 폭주/다축이
    확정되면 S9 집약 alert 를 동일 그래프에 재투입한다(상관 가설 — 권고전용, severity
    escalate-only). 집약 실패는 격리되어 inbound 판정을 무너뜨리지 않는다(Codex I6-2).
    """
    forged = has_forged_internal_fields(payload)
    if forged:
        _logger.warning("inbound alert 내부전용 필드 위조 시도 드롭: %s", forged)
    settings = get_settings()
    alert = UntrustedAlertPayload.model_validate(payload).to_alert()
    graph = build_soc_graph(settings=settings, dynamics=_get_dynamics(settings))
    state = await graph.ainvoke({"alert": alert})
    report = state["report"]
    verdict = str(report.verdict)
    metrics().record_alert(verdict)
    if report.decoy_placements:
        metrics().record_decoy_placed(len(report.decoy_placements))
    _record_timings(cast("SOCState", state))
    result: dict[str, object] = {
        "alert_id": alert.id,
        "verdict": verdict,
        "severity": str(state.get("severity", "")),
    }

    # 크로스-alert 상관: inbound alert 만 관측(집약 alert 는 재관측 금지 — 피드백 방지).
    corr = _get_correlator(settings)
    if corr is not None:
        with _corr_lock:
            incident = corr.observe(alert, _now())
            agg = corr.to_aggregate_alert(incident) if incident is not None else None
        if incident is not None and agg is not None:
            metrics().record_correlation_fired(incident.pattern)
            # 집약 재투입은 inbound POST 경로에서 동기 실행(발화 시 2× graph run).
            # 의도적(상관 판정을 한 응답에 반환) — 발화 드물어 지연 수용. 지연 우려 시
            # 배포에서 비동기 큐로 분리(Codex diff Medium — SLO 트레이드오프).
            result["correlation"] = await _process_aggregate(graph, incident, agg)
    return result


async def _process_aggregate(
    graph: CompiledStateGraph[SOCState],
    incident: CorrelatedIncident,
    agg: Alert,
) -> dict[str, object]:
    """S9 집약 alert 를 파이프라인에 재투입(실패 격리). 상관 요약 dict 반환.

    집약 처리 예외는 여기서 삼켜 inbound 판정을 보호한다(Codex I6-2). 집약은
    best-effort — 실패 시 correlation.error 로 정직히 표기하고 실패 메트릭 계량.
    """
    base: dict[str, object] = {
        "pattern": incident.pattern,
        "count": incident.count,
        "distinct_assets": incident.distinct_assets,
        "aggregate_id": agg.id,
    }
    try:
        agg_state = await graph.ainvoke({"alert": agg})
    except Exception as exc:  # noqa: BLE001 — 집약 실패 격리 경계(inbound 보호)
        metrics().record_correlation_error()
        _logger.warning("집약 재투입 실패(inbound 판정 유지): %s", exc)
        base["error"] = str(exc)
        return base
    metrics().record_aggregate_alert()
    _record_timings(cast("SOCState", agg_state), prefix="agg:")
    base["aggregate_verdict"] = str(agg_state["report"].verdict)
    base["aggregate_severity"] = str(agg_state.get("severity", ""))
    return base


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
