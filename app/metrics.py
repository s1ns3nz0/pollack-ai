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
        # 예측 폐루프: hit/miss 판정 누적(ActorWriteGate on_settle 훅이 갱신)
        self.prediction_hits = 0
        self.prediction_misses = 0
        # kill chain: 후반단계 도달 격상 누적(Report 노드가 갱신)
        self.killchain_advanced_total = 0
        # recovery: 축출 실패(축출 후 재발) 누적(RecoveryVerifier 가 갱신)
        self.eviction_failed_total = 0
        # graceful degradation: 임무 중단(ABORT) 판정 누적(Report 노드가 갱신)
        self.mission_abort_total = 0
        # deception: decoy 자산/canary 미끼 접촉 격상 누적(Report 노드가 갱신)
        self.decoy_hit_total = 0
        # MBCRA: 사이버 핵심지형(KT-C) 자산 침해 격상 누적(Report 노드가 갱신)
        self.key_terrain_total = 0
        # BDA: 교전피해평가 복구/재교전 권고 누적(OutcomeProbeAgent 가 갱신)
        self.bda_restore_total = 0
        self.prompt_injection_total = 0
        self.active_injection_total = 0
        self.aibom_violation_total = 0
        self.cisa_reportable_total = 0

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

    def record_killchain_advanced(self) -> None:
        """kill chain 후반단계 도달 격상 1건 누적."""
        with self._lock:
            self.killchain_advanced_total += 1

    def record_eviction_failed(self) -> None:
        """축출 실패(축출 후 재발) 1건 누적."""
        with self._lock:
            self.eviction_failed_total += 1

    def record_mission_abort(self) -> None:
        """임무 중단(ABORT) 판정 1건 누적."""
        with self._lock:
            self.mission_abort_total += 1

    def record_decoy_hit(self) -> None:
        """decoy/canary 미끼 접촉 격상 1건 누적."""
        with self._lock:
            self.decoy_hit_total += 1

    def record_key_terrain(self) -> None:
        """사이버 핵심지형(KT-C) 침해 격상 1건 누적."""
        with self._lock:
            self.key_terrain_total += 1

    def record_bda_restore(self, n: int = 1) -> None:
        """교전피해평가 복구/재교전 권고 n건 누적."""
        with self._lock:
            self.bda_restore_total += n

    def record_prompt_injection(self) -> None:
        """LLM 프롬프트 인젝션 의심/가드 강등 1건 누적(ATLAS AML.T0051)."""
        with self._lock:
            self.prompt_injection_total += 1

    def record_active_injection(self) -> None:
        """high-confidence active 인젝션(우리 시스템 직접 조작) 1건 누적."""
        with self._lock:
            self.active_injection_total += 1

    def record_aibom_violation(self, n: int = 1) -> None:
        """AIBOM 거버넌스 위반 n건 누적(AI 공급망·출처). 정적 posture — 로드 시 1회."""
        with self._lock:
            self.aibom_violation_total += n

    def record_cisa_reportable(self) -> None:
        """CIRCIA 연방(CISA) 72h 보고 대상 권위 case 1건 누적."""
        with self._lock:
            self.cisa_reportable_total += 1

    def record_prediction(self, *, hit: bool) -> None:
        """예측 판정 1건 누적(예측 폐루프)."""
        with self._lock:
            if hit:
                self.prediction_hits += 1
            else:
                self.prediction_misses += 1

    def prediction_stats(self) -> dict[str, float]:
        """예측 적중 통계. 판정 0건이면 빈 dict."""
        with self._lock:
            total = self.prediction_hits + self.prediction_misses
            if total == 0:
                return {}
            return {
                "hits": self.prediction_hits,
                "misses": self.prediction_misses,
                "hit_ratio": round(self.prediction_hits / total, 3),
            }

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

    # kill chain: 후반단계 도달 격상 카운터
    if c.killchain_advanced_total:
        out.append(
            "# HELP soc_killchain_advanced_total kill chain 후반단계 도달 격상 수"
        )
        out.append("# TYPE soc_killchain_advanced_total counter")
        out.append(_line("soc_killchain_advanced_total", c.killchain_advanced_total))

    # recovery: 축출 실패(축출 후 재발) 카운터
    if c.eviction_failed_total:
        out.append("# HELP soc_eviction_failed_total 축출 후 재발(축출 실패) 수")
        out.append("# TYPE soc_eviction_failed_total counter")
        out.append(_line("soc_eviction_failed_total", c.eviction_failed_total))

    # graceful degradation: 임무 중단(ABORT) 카운터
    if c.mission_abort_total:
        out.append("# HELP soc_mission_abort_total 임무 중단(ABORT) 판정 수")
        out.append("# TYPE soc_mission_abort_total counter")
        out.append(_line("soc_mission_abort_total", c.mission_abort_total))

    # deception/MBCRA/BDA: 신규 격상·조치 신호 카운터
    if c.decoy_hit_total:
        out.append("# HELP soc_decoy_hit_total decoy/canary 미끼 접촉 격상 수")
        out.append("# TYPE soc_decoy_hit_total counter")
        out.append(_line("soc_decoy_hit_total", c.decoy_hit_total))
    if c.key_terrain_total:
        out.append("# HELP soc_key_terrain_total 사이버 핵심지형(KT-C) 침해 격상 수")
        out.append("# TYPE soc_key_terrain_total counter")
        out.append(_line("soc_key_terrain_total", c.key_terrain_total))
    if c.bda_restore_total:
        out.append("# HELP soc_bda_restore_total 교전피해평가 복구/재교전 권고 수")
        out.append("# TYPE soc_bda_restore_total counter")
        out.append(_line("soc_bda_restore_total", c.bda_restore_total))
    if c.prompt_injection_total:
        out.append(
            "# HELP soc_prompt_injection_total 프롬프트 인젝션 의심/가드 강등 수"
        )
        out.append("# TYPE soc_prompt_injection_total counter")
        out.append(_line("soc_prompt_injection_total", c.prompt_injection_total))
    if c.active_injection_total:
        out.append("# HELP soc_active_injection_total high-confidence active 인젝션 수")
        out.append("# TYPE soc_active_injection_total counter")
        out.append(_line("soc_active_injection_total", c.active_injection_total))
    if c.aibom_violation_total:
        out.append("# HELP soc_aibom_violation_total AIBOM 거버넌스 위반 수(AI 공급망)")
        out.append("# TYPE soc_aibom_violation_total counter")
        out.append(_line("soc_aibom_violation_total", c.aibom_violation_total))
    if c.cisa_reportable_total:
        out.append(
            "# HELP soc_cisa_reportable_total CIRCIA 연방 72h 보고 대상 권위 case 수"
        )
        out.append("# TYPE soc_cisa_reportable_total counter")
        out.append(_line("soc_cisa_reportable_total", c.cisa_reportable_total))

    # 예측 폐루프: hit/miss 카운터 + 적중률 게이지
    pred = c.prediction_stats()
    if pred:
        out.append("# HELP soc_prediction_hit_total 예측 판정 누적(hit/miss)")
        out.append("# TYPE soc_prediction_hit_total counter")
        out.append(_line("soc_prediction_hit_total", pred["hits"], '{result="hit"}'))
        out.append(_line("soc_prediction_hit_total", pred["misses"], '{result="miss"}'))
        out.append("# HELP soc_prediction_hit_ratio 예측 적중률")
        out.append("# TYPE soc_prediction_hit_ratio gauge")
        out.append(_line("soc_prediction_hit_ratio", pred["hit_ratio"]))

    out.extend(_coverage_metrics())
    out.extend(_bas_metrics())
    out.extend(_cato_metrics())
    return "\n".join(out) + "\n"


_CATO_AUTH_CODE = {"authorized": 0, "conditional": 1, "at_risk": 2}


def _cato_metrics() -> list[str]:
    """cATO 지속 인가 게이지 — BAS 커버리지 + SLO 위반 합성(정책 없으면 빈 목록)."""
    try:
        from core.bas import BASRunner
        from core.cato import CatoAssessor, CatoControls
        from core.monitoring import SLOMonitor, collect_snapshot

        bas = BASRunner.from_yaml().run()
        breaches = SLOMonitor.from_yaml().evaluate(collect_snapshot())
        status = CatoAssessor(CatoControls.from_yaml()).assess(
            bas=bas, slo_breaches=breaches
        )
    except Exception:  # noqa: BLE001 - 메트릭 조회 실패가 스크레이프를 깨지 않게
        return []
    return [
        "# HELP soc_cato_authorization cATO 인가(0=auth/1=cond/2=at_risk)",
        "# TYPE soc_cato_authorization gauge",
        _line("soc_cato_authorization", _CATO_AUTH_CODE.get(status.authorization, 1)),
        "# HELP soc_cato_poam_total 미충족 통제(POA&M) 수",
        "# TYPE soc_cato_poam_total gauge",
        _line("soc_cato_poam_total", len(status.poam)),
    ]


def _bas_metrics() -> list[str]:
    """BAS 방어 검증 게이지(시나리오 없으면 빈 목록)."""
    try:
        from core.bas import BASRunner

        report = BASRunner.from_yaml().run()
    except Exception:  # noqa: BLE001 - 메트릭 조회 실패가 스크레이프를 깨지 않게
        return []
    out: list[str] = [
        "# HELP soc_bas_detection_ratio BAS 방어 검증 탐지 비율(detected/total)",
        "# TYPE soc_bas_detection_ratio gauge",
        _line("soc_bas_detection_ratio", report.detection_ratio),
        "# HELP soc_bas_gap_total BAS 미탐(방어 공백) 시나리오 수",
        "# TYPE soc_bas_gap_total gauge",
        _line("soc_bas_gap_total", len(report.gaps)),
        "# HELP soc_bas_stride_detection_ratio STRIDE 카테고리별 탐지 비율",
        "# TYPE soc_bas_stride_detection_ratio gauge",
    ]
    for cat, stat in sorted(report.by_stride.items()):
        out.append(
            _line("soc_bas_stride_detection_ratio", stat.ratio, f'{{stride="{cat}"}}')
        )
    return out


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
