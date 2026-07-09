# AlertCorrelator 인제스트 배선 — 크로스-alert 상관(S9 집약) (design)

**날짜**: 2026-07-09
**작성**: 황준식 (analysis lane)
**상태**: design (Codex 교차검증 대기)

## 1. 목적 / intent

`core/correlation.py AlertCorrelator`(슬라이딩 윈도우 alert-storm/multi-axis 상관기)는
**구현 존재하나 미배선** — `app/hotpath.py` docstring 이 "상태보유 컴포넌트
(AlertCorrelator 등)로 단일레플리카"라 주장하나 실제 인스턴스화·지속 없음. 매 alert
그래프를 새로 빌드해 **단일-alert 고립분석**만 한다. 이 기능이 hotpath 에 지속
correlator 를 배치해 크로스-alert 상관(캠페인/과부하)을 살린다.

## 2. 결정된 설계 (grill 확정)

| 포크 | 결정 |
|---|---|
| 스코프 | **AlertCorrelator 인제스트 배선만**. IoAGraph(report-viz)는 별도 후속 |
| 집약 처리 | 발화 시 `to_aggregate_alert(S9)` → **동일 파이프라인 재투입**(inbound+집약 둘 다 판정 반환), **실패 격리** |
| 트러스트 | **관측적·provisional 수용** — S9 는 상관 가설. 안전=escalate-only(severity 만)+**권고전용**(actuator 아님)+surface. env-verdict 자동보장 주장 안 함(Codex High#1) |

### 2.1 아키텍처 근거
- hotpath = single-replica(ADR 0002 D6) + `HTTPServer`(비-threading) → 요청 **직렬**.
  따라서 **모듈-전역 persistent `AlertCorrelator`** 의 공유 deque 는 스레드-안전(단일
  스레드). correlator 는 그래프 밖(그래프는 alert마다 재빌드, correlator 는 지속).
- `observe(alert, now)` 의 `now` = 수신시각 `datetime.now(UTC)`(app 코드, 워크플로 아님).

## 3. 변경 상세

### 3.1 Settings (`core/settings.py`)
- `correlation_enabled: bool = True`(내부 상관 — egress 없음, 저위험 고가치 → 기본 on).
- `correlation_window_sec: float = 300.0`(gt 0).
- `correlation_storm_count: int = 5`(gt 0).
- `correlation_multi_axis_assets: int = 3`(gt 0).
- 하드코딩 금지 준수 — 임계 외부화(운용 튜닝).

### 3.2 app/hotpath.py
- 모듈-전역 지속 correlator + **module lock**(Codex I1 — 향후 threaded 서버 대비) +
  **injectable clock**(Codex I4 — 테스트 시간 제어) + 테스트 리셋:
```
import threading
_correlator: AlertCorrelator | None = None
_correlator_ready = False
_corr_lock = threading.Lock()

def _now() -> datetime:            # 테스트가 monkeypatch 로 시간 제어
    return datetime.now(UTC)

def _get_correlator(settings) -> AlertCorrelator | None:
    global _correlator, _correlator_ready
    if not _correlator_ready:
        _correlator = AlertCorrelator(...) if settings.correlation_enabled else None
        _correlator_ready = True
    return _correlator

def reset_correlator() -> None:    # 테스트 격리(autouse fixture)
    global _correlator, _correlator_ready
    with _corr_lock:
        _correlator = None; _correlator_ready = False
```
- `_run_alert` 흐름(집약 **실패 격리** — Codex I6-2):
```
graph = build_soc_graph(settings=settings)
state = await graph.ainvoke({"alert": alert})     # inbound(현행)
result = {alert_id, verdict, severity}
metrics().record_alert(inbound_verdict)           # inbound 만 소비(현행)
... inbound node_timings 계측(현행) ...
corr = _get_correlator(settings)
if corr is not None:
    with _corr_lock:                              # 윈도우 뮤테이션 직렬화
        incident = corr.observe(alert, _now())    # inbound 만 observe(agg 재귀 금지)
        agg = corr.to_aggregate_alert(incident) if incident else None
    if incident is not None and agg is not None:
        metrics().record_correlation_fired(incident.pattern)
        try:
            agg_state = await graph.ainvoke({"alert": agg})   # S9 재투입(동일 그래프)
            metrics().record_aggregate_alert(str(agg_state["report"].verdict))
            _record_timings(agg_state, kind="aggregate")      # 집약 node 지연 계측
            result["correlation"] = {pattern,count,distinct_assets,aggregate_id,
                                     aggregate_verdict,aggregate_severity}
        except SOCPlatformError as exc:            # 집약 실패가 inbound 를 무너뜨리지 않음
            metrics().record_correlation_error()
            result["correlation"] = {"pattern": incident.pattern, "error": str(exc)}
            _logger.warning("집약 재투입 실패(inbound 유지): %s", exc)
```
- **agg 는 observe 에 안 넣음**(Codex I2 — storm 피드백 방지). observe 는 POST당 정확히
  1회, inbound alert 만.
- inbound 는 항상 완료·계량됨 → 집약 예외로 롤백 없음(Codex I6-2).
- lock 은 correlator 뮤테이션(observe+to_aggregate)만 감쌈. 무거운 graph.ainvoke 는
  lock 밖(직렬 hotpath 라 무방, 향후 threaded 시에도 윈도우 정합 유지).

### 3.3 app/metrics.py (Codex I5 — 이중계량 회피)
- `record_correlation_fired(pattern)` → `soc_correlation_fired_total{pattern=...}`.
- `record_aggregate_alert(verdict)` → `soc_aggregate_alerts_total`(inbound `soc_alerts_
  total` 과 **분리** — SLO 혼동 방지). record_alert 재호출 안 함.
- `record_correlation_error()` → `soc_correlation_error_total`(집약 실패 계량).
- 각 export 블록 `render_text()` 추가.

## 4. 트러스트 / 포이즈닝 분석 (Codex High#1/#2 반영)
- correlator 는 untrusted wire alert 관측(asset_id/scenario_id 위조가능).
- **storm(볼륨)**: 위조 플러드여도 실제 인제스트 부하 = 실 DoS 증상 → surface 타당.
- **multi_axis(distinct asset)**: 위조 다양 asset_id → 조율공격 신호 조작 가능.
- **정직한 안전 서사**(env-verdict 자동보장 주장 철회):
  - hotpath verdict 는 **설정된 judge** 를 따른다. 기본 `default_judge` 는
    `alert.ground_truth`(sim/oracle)를 신뢰 → **모든** inbound 및 S9 가 동일하게
    TP 판정된다(S9 특권 아님 — inbound 와 같은 경로). 운영 배포는 env-verdict-backed
    judge 로 교체. 즉 "env-verdict 가 진짜 판정"은 **배포 의존**이며 기본 그래프에선
    성립 안 함 → 이 서사에 안전을 기대지 않는다.
  - **실제 안전 근거**: (1) severity **escalate-only**(과표면=alert fatigue, 은폐 아님).
    (2) response 는 **권고전용**(ResponseResult=문자열 필드, actuator 호출 아님 —
    COA 교리). auto_response="활성"은 권고 라벨. (3) surfaced-not-suppressed.
  - (4) multi_axis 는 이미 **distinct asset 집합** 요구(동일 asset 플러드는 storm 만).
  - 결론: 위조 → **거짓 S9 과표면**(권고), 억제/자율행동 아님. 로그(correlation-fired,
    member/asset 수)로 위조 감시.
- **hitl(Codex High#2)**: 기본 hotpath `hitl=False` 는 correlation 무관한 hotpath-wide
  속성(모든 HIGH inbound 동일). 이 기능은 신규 자율행동 표면 추가 안 함(권고전용).
  HITL 강제는 `build_soc_graph(hitl=True)` 배포 선택 — 스코프 밖.
- correlator·to_aggregate_alert 는 **신뢰 인프라**(내부 로직) — 집약 alert 의
  `lateral_correlation=True`(내부필드)는 correlator 가 채우는 게 정당(wire 아님).

## 5. 테스트 (`tests/__tests__/test_hotpath_correlation.py`)
- `test_storm_fires_aggregate`: window 내 storm_count 이상 → correlation 블록 + S9 판정.
- `test_multi_axis_fires_aggregate`: distinct asset multi_axis_assets 이상 → multi_axis.
- `test_single_alert_no_correlation`: 1건 → correlation 키 없음.
- `test_correlator_persists_across_calls`: 연속 `_run_alert` 가 윈도우 누적(모듈 지속).
- `test_disabled_no_correlation`: `correlation_enabled=False` → correlator None, 무발화.
- `test_correlation_metric_recorded`: 발화 시 correlation_fired + aggregate_alert 계량,
  `soc_alerts_total` 은 inbound 만(이중계량 없음).
- `test_observe_called_once_never_with_aggregate`(Codex I2): POST당 observe 1회,
  agg.id 로 재관측 안 됨(피드백 없음).
- `test_aggregate_failure_isolated`(Codex I6-2): 집약 graph 예외 → inbound 판정 유지 +
  `correlation.error` + error 메트릭(POST 200).
- 각 테스트 `reset_correlator()` autouse fixture 격리 + `_now` monkeypatch 로 시간 제어.
  (AlertCorrelator 자체 로직은 기존 `test_correlation.py` 커버 — 여기선 배선만.)

## 6. 미결 / 후속
- IoAGraph report-viz 배선(SOCReport.ioa_graph + report_agent) — 별 PR.
- correlator 상태 지속성: 현재 in-memory(재시작 시 윈도우 소실 — 슬라이딩이라 수용).
  다중 레플리카 확장 시 공유 스토어 필요(현 단일레플리카 전제).
- 게이트: 스펙→Codex 설계리뷰→반영→구현→black/ruff/mypy/pytest→clean-worktree→
  Codex diff 리뷰→커밋/PR/머지.
