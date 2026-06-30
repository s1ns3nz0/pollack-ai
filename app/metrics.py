"""Prometheus 메트릭 노출 — 런타임 카운터 + 커버리지 KPI(표준 라이브러리만).

`prometheus_client` 의존 없이 텍스트 exposition(0.0.4)을 직접 렌더한다. 두 부류:

1. **런타임 카운터** — 핫패스가 갱신(처리 경보 수·판정별 수·노드 평균지연).
2. **커버리지 KPI** — `tools.coverage` 리포트를 게이지로(전체/대응가능 비율, 갭 수,
   전술별/archetype 별). 스크레이프 시점에 계산.

스레드 안전(카운터는 락 보호). `/metrics` 가 `render_text()` 를 반환한다.
"""

from __future__ import annotations

import threading

_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


class _Counters:
    """프로세스 내 런타임 카운터(스레드 안전)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.alerts_total = 0
        self.verdict_total: dict[str, int] = {}
        self._node_ms_sum: dict[str, float] = {}
        self._node_ms_count: dict[str, int] = {}
        # spec D1: RAGAS 누적
        self.ragas_evaluations_total = 0
        self._ragas_faith_sum = 0.0
        self._ragas_ans_rel_sum = 0.0
        self._ragas_ctx_rel_sum = 0.0

    def record_alert(self, verdict: str) -> None:
        """경보 1건 처리 + 판정 집계."""
        with self._lock:
            self.alerts_total += 1
            self.verdict_total[verdict] = self.verdict_total.get(verdict, 0) + 1

    def observe_node(self, node: str, elapsed_ms: float) -> None:
        """노드 실행 지연(ms) 관측 — 평균 산출용 합/카운트 누적."""
        with self._lock:
            self._node_ms_sum[node] = self._node_ms_sum.get(node, 0.0) + elapsed_ms
            self._node_ms_count[node] = self._node_ms_count.get(node, 0) + 1

    def node_avg_ms(self) -> dict[str, float]:
        """노드별 평균 지연(ms)."""
        with self._lock:
            return {
                n: round(self._node_ms_sum[n] / self._node_ms_count[n], 2)
                for n in self._node_ms_sum
                if self._node_ms_count.get(n)
            }

    def observe_ragas(self, faith: float, ans_rel: float, ctx_rel: float) -> None:
        """RAGAS 측정 1건 누적(spec D1)."""
        with self._lock:
            self.ragas_evaluations_total += 1
            self._ragas_faith_sum += faith
            self._ragas_ans_rel_sum += ans_rel
            self._ragas_ctx_rel_sum += ctx_rel

    def ragas_avgs(self) -> dict[str, float]:
        """RAGAS 메트릭 평균(spec D1). 측정 0건이면 빈 dict."""
        with self._lock:
            n = self.ragas_evaluations_total
            if n == 0:
                return {}
            return {
                "faithfulness": round(self._ragas_faith_sum / n, 3),
                "answer_relevancy": round(self._ragas_ans_rel_sum / n, 3),
                "context_relevancy": round(self._ragas_ctx_rel_sum / n, 3),
            }


_METRICS = _Counters()


def metrics() -> _Counters:
    """전역 런타임 카운터를 반환한다(핫패스가 갱신)."""
    return _METRICS


def content_type() -> str:
    """Prometheus exposition Content-Type."""
    return _CONTENT_TYPE


def _line(name: str, value: float, labels: str = "") -> str:
    return f"{name}{labels} {value}"


def render_text() -> str:
    """런타임 카운터 + 커버리지 KPI 를 Prometheus 텍스트로 렌더한다."""
    c = _METRICS
    out: list[str] = []

    out.append("# HELP soc_alerts_total 처리된 경보 수")
    out.append("# TYPE soc_alerts_total counter")
    out.append(_line("soc_alerts_total", c.alerts_total))

    out.append("# HELP soc_verdict_total 판정별 경보 수")
    out.append("# TYPE soc_verdict_total counter")
    for verdict, n in sorted(c.verdict_total.items()):
        out.append(_line("soc_verdict_total", n, f'{{verdict="{verdict}"}}'))

    out.append("# HELP soc_node_latency_avg_ms 파이프라인 노드 평균 지연(ms)")
    out.append("# TYPE soc_node_latency_avg_ms gauge")
    for node, avg in sorted(c.node_avg_ms().items()):
        out.append(_line("soc_node_latency_avg_ms", avg, f'{{node="{node}"}}'))

    # spec D1: RAGAS 게이지
    ragas_avg = c.ragas_avgs()
    if ragas_avg:
        out.append("# HELP soc_ragas_evaluations_total RAGAS 측정 누적")
        out.append("# TYPE soc_ragas_evaluations_total counter")
        out.append(_line("soc_ragas_evaluations_total", c.ragas_evaluations_total))
        for k in ("faithfulness", "answer_relevancy", "context_relevancy"):
            out.append(f"# HELP soc_ragas_{k}_avg RAGAS {k} 평균")
            out.append(f"# TYPE soc_ragas_{k}_avg gauge")
            out.append(_line(f"soc_ragas_{k}_avg", ragas_avg[k]))

    out.extend(_coverage_metrics())
    return "\n".join(out) + "\n"


def _coverage_metrics() -> list[str]:
    """커버리지 KPI 게이지(데이터 없으면 빈 목록)."""
    try:
        from tools.coverage import CoverageMatrix

        report = CoverageMatrix.from_yaml().report()
    except Exception:  # noqa: BLE001 - 메트릭 조회 실패가 스크레이프를 깨지 않게
        return []

    out: list[str] = [
        "# HELP soc_attack_coverage_ratio ATT&CK 커버리지 비율(covered/total)",
        "# TYPE soc_attack_coverage_ratio gauge",
        _line("soc_attack_coverage_ratio", report.coverage_pct),
        "# HELP soc_attack_addressable_ratio 대응가능 커버리지(pre-compromise 제외)",
        "# TYPE soc_attack_addressable_ratio gauge",
        _line("soc_attack_addressable_ratio", report.addressable_pct),
        "# HELP soc_attack_technique_total 상태별 기법 수",
        "# TYPE soc_attack_technique_total gauge",
        _line("soc_attack_technique_total", report.covered, '{status="covered"}'),
        _line("soc_attack_technique_total", report.planned, '{status="planned"}'),
        _line("soc_attack_technique_total", report.uncovered, '{status="uncovered"}'),
        "# HELP soc_attack_gap_total archetype 별 미탐지 기법 수",
        "# TYPE soc_attack_gap_total gauge",
    ]
    for archetype, n in sorted(report.by_archetype.items()):
        out.append(_line("soc_attack_gap_total", n, f'{{archetype="{archetype}"}}'))
    out.append("# HELP soc_attack_tactic_uncovered 전술별 미탐지 기법 수")
    out.append("# TYPE soc_attack_tactic_uncovered gauge")
    for tactic in report.tactics:
        out.append(
            _line(
                "soc_attack_tactic_uncovered",
                tactic.uncovered,
                f'{{tactic="{tactic.name}"}}',
            )
        )
    return out
