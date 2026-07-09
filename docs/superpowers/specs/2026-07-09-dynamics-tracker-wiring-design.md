# DynamicsTracker 배선 — 죽은 severity dwelling/lateral 룰 활성 (design)

**날짜**: 2026-07-09
**작성**: 황준식 (analysis lane)
**상태**: design (Codex 교차검증 대기)

## 1. 목적 / intent

`SeverityEngine` 에 `dwelling_time_exceeds`(+1)·`lateral_correlation`(min m) 격상 룰이
있으나, 정규 inbound 흐름에서 그 입력(`dwelling_min`·`lateral_correlation`)을
**아무도 안 채운다**(correlation.py 만 S9 에 lateral 세팅). `core/dynamics.py
DynamicsTracker`(이력 기반 산정기)는 구현 존재하나 **완전 dormant**(agents/app 미참조).
이 기능이 DynamicsTracker 를 배선해 죽은 severity 룰을 살린다.

## 2. 결정된 설계 (grill 확정)

| 포크 | 결정 |
|---|---|
| 배치 | build_soc_graph `dynamics` param 주입 — hotpath 지속 인스턴스(그래프 재빌드에도 이력 지속) |
| eviction | **TTL** — retention 창 넘은 이력 드롭(settings 외부화, 무한증가 방지) |
| upstream 판정 | **레지스트리 기반**(asset-tiers dependents 보유 자산) — substring 대체. 잔여 위조는 escalate-only |

## 3. 변경 상세

### 3.1 core/dynamics.py
- **레지스트리 upstream**: `_is_upstream` substring 매칭 제거 → 생성자에
  `upstream_assets: frozenset[str]`(**다른 자산이 depends_on 하는 = dependents 보유**
  자산 집합) 주입. `alert.asset_id in upstream_assets` 로 판정. 임의 'GCS-fake' 차단 +
  정상자산 오탐 제거. 배선 시 KeyTerrainMap 에서 도출.
  - **⚠ 예시 정정(Codex H)**: asset-tiers 상 upstream(=dependents 보유)은 **C2_LINK,
    GNSS, SATCOM, AUTOPILOT** 이다. GCS 는 `depends_on:[C2_LINK]` 라 dependents 없음 →
    upstream 아님(소비자). "손상전파원=고가치 upstream" 정의에 부합(C2_LINK 침해 →
    AUTOPILOT/GCS/UGV 영향). 잔여위조 예시는 GCS 아닌 **C2_LINK**.
- **eviction = 비활성(last_seen) 기준(Codex H — 이력소실 방지)**: first_seen 나이가
  아니라 **last_seen 무활동** 기준으로 드롭. `enrich` 마다 해당 키 `_last_seen[key]=now`
  갱신, `now - last_seen > retention` 인 항목만 evict. → 진행 중(활성) 인시던트는
  first_seen 보존 → dwell 유지(다음 경보가 dwell=0 로 리셋돼 +1 격상 사라지는 버그
  방지). first_seen 은 dwell 산정 유지, last_seen 은 eviction 전용.
- **cardinality cap(Codex M)**: TTL 은 나이만 bound → 고속 위조 asset_id 스트림이
  retention 창 내 dict 폭증 가능. `max_entries` 상한(초과 시 가장 오래된 last_seen
  축출, settings 외부화)으로 개수도 bound.
- **injectable clock**: 생성자 `clock: Callable[[], datetime]=lambda: datetime.now(UTC)`.
  `enrich(alert, now=None)` → `now = now or self._clock()`(하위호환 — 기존 test_dynamics.py
  의 positional now 인자 유지). graph 노드는 `dynamics.enrich(alert)`, 테스트 fake clock.
- 병합은 escalate-only 유지(`max(dwell,...)`, `lateral or ...`).
- **동시성(Codex M)**: 지속 인스턴스라 hotpath 는 직렬이나, 향후 threaded 대비 내부
  뮤테이션 lock 또는 hotpath `_get_dynamics` 를 correlator 와 동일 lock 패턴으로.

### 3.2 agents/graph.py — ⚠ changed flag 정합(Codex M, 핵심 배선 버그)
- `build_soc_graph` 에 `dynamics: DynamicsTracker | None = None` param 추가.
- `_triage_with_match` enrich 체인에 슬롯: **posture 다음, matcher 앞**(dwelling/lateral
  이 triage 내부 severity compute 전에 세팅돼야). `if dynamics is not None: alert =
  dynamics.enrich(alert)`(sync — 순수 계산).
- **필수**: `_triage_with_match` 는 `changed` 참일 때만 enriched alert 를 state 에 씀.
  기존 enricher 는 특정 플래그(prediction_match 등)로 changed 세팅 → dwelling/lateral 은
  그 플래그가 아니므로 **누락 위험**. dynamics enrich 후 `changed = changed or
  new_alert != alert`(또는 dynamics 결과가 원본과 다르면 changed=True) 로 반드시
  state["alert"] 갱신 → 아니면 triage 가 옛 alert 로 severity 계산해 룰이 계속 dormant.
- 내부 `_default_dynamics` **없음** — 상태보유라 그래프 재빌드마다 fresh 면 이력 소실.
  반드시 지속 인스턴스 주입(hotpath). 미주입(테스트/sim) → None → 현행 보존.
- **참고(Codex)**: `sim_bridge/bridge.py` 는 이미 자체 지속 DynamicsTracker 를 그래프
  전(前) enrich 로 사용 → DynamicsTracker 는 sim 경로엔 배선됨, **hotpath 만 dormant**.
  이 기능은 hotpath 배선. sim 은 무영향(별 인스턴스).

### 3.3 app/hotpath.py
- 지속 모듈-전역 `_get_dynamics()`(correlator 와 동형 — lock double-checked init +
  `reset_dynamics()` 테스트 훅). upstream_assets 는 `KeyTerrainMap.from_yaml()` 에서
  dependents 보유 자산 도출(실패 시 None → 비활성). `build_soc_graph(..., dynamics=
  _get_dynamics(settings))` 전달.
- `dynamics_enabled=False` → None(현행 severity 보존).
- 클록: hotpath 지속 인스턴스는 실 clock. (correlator `_now` 와 별개 — dynamics 는 자체
  clock 보유.)

### 3.4 core/settings.py
- `dynamics_enabled: bool = True`(내부 로직·egress 없음 → 기본 on).
- `dynamics_retention_min: int = 180`(gt 0 — 무활동 eviction 창; dwelling 지평 > 30분).
- `dynamics_upstream_active_min: int = 60`(gt 0 — 기존 기본, 외부화).
- `dynamics_max_entries: int = 4096`(gt 0 — 이력 dict cardinality 상한, 위조 폭증 방지).

## 4. 트러스트 / 포이즈닝 분석
- `dwelling_min`·`lateral_correlation` = `_INTERNAL_ONLY_FIELDS`(wire 위조 불가). 채움
  주체가 DynamicsTracker(신뢰 인프라). 입력은 이력(first_seen 타임스탬프) — 내부 파생.
- **dwelling**: 실 경과시간 기반(now=수신시각). 위조 불가(공격자가 시간 못 조작) — 높은
  dwell 은 실제 지속 위협. escalate-only(+1).
- **lateral(레지스트리 후)**: 등록 upstream 자산(dependents 보유) 침해 활성 중 하류 경보
  상관. 위조 표면 축소 — 임의 문자열 upstream 사칭 불가. 잔여: 공격자가 **실제 등록
  upstream id**(예 C2_LINK — GCS 아님, §3.1 참조)를 wire 로 세팅 → lateral 유도 가능.
  단 severity **min m
  강등불가**(escalate-only, 과격상=alert fatigue) → 안전방향. telemetry 로 감시.
- **TTL**: 이력 dict bounded → 위조 asset_id 키 폭증 메모리 고갈 방지.
- severity 권한 불변 — DynamicsTracker 는 severity 가 **이미 정의한** 룰의 입력만 채움
  (신규 격상 경로 아님). 최종 verdict 는 판정 판단(현행).

## 5. 테스트 (`tests/__tests__/test_dynamics_wiring.py` + core 로직)
- `test_dwelling_accumulates_over_retention`: fake clock 로 동일 자산 시퀀스 → dwell 증가.
- `test_active_incident_dwell_preserved`(Codex H): retention 내 재관측 지속 → last_seen
  갱신으로 evict 안 됨, dwell 유지(리셋 안 됨 — +1 격상 보존).
- `test_inactive_entry_evicted`: retention 초과 무활동 → 항목 드롭(다음 재등장 dwell 0).
- `test_max_entries_cap`(Codex M): max_entries 초과 위조 asset_id 스트림 → dict bounded.
- `test_registered_upstream_triggers_lateral`: 등록 upstream(dependents 보유) 침해 후
  하류 경보 → lateral=True.
- `test_forged_unregistered_upstream_no_lateral`: 'GCS-fake'(미등록) → upstream 아님,
  lateral 안 뜸.
- `test_escalate_only_never_lowers`: 기존 dwell/lateral 있으면 낮추지 않음(병합).
- `test_graph_dynamics_injection`: build_soc_graph(dynamics=tracker) → dwelling/lateral 이
  severity 에 반영(격상). 미주입 → 현행 severity 불변(회귀).
- `test_hotpath_persists_dynamics`: 연속 _run_alert 가 이력 누적(지속 싱글톤).
- eviction/upstream/clock 은 core/dynamics.py 단위 + 배선은 graph/hotpath 통합.

## 6. 미결 / 후속
- retention_min(180) 초기값은 dwelling 임계(30분)·운용 튜닝 대상.
- 다중 레플리카 확장 시 이력 공유 스토어 필요(현 단일레플리카 전제 — correlator 와 동일).
- upstream_assets 도출을 KeyTerrainMap.dependents 역산 vs asset-tiers 직접 파싱 —
  구현 시 결정(KeyTerrainMap 에 upstream 헬퍼 추가 가능).
- 게이트: 스펙→Codex 설계리뷰→반영→구현→black/ruff/mypy/pytest→clean-worktree→
  Codex diff 리뷰→커밋/PR/머지.
