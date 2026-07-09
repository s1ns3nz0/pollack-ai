# METT-TC 가중 트리아지 → response 전달 (design)

**날짜**: 2026-07-09
**작성**: 황준식 (analysis lane)
**상태**: design (Codex 교차검증 대기)

## 1. 목적 / intent

triage 단계에서 METT-TC 임무위험(`MissionRiskAssessor.assess`)을 산출해
(1) 트리아지 **우선순위(priority)** 를 상승-전용으로 가중하고,
(2) `mission_risk` 객체를 SOCState 로 실어 **response_agent** 가 소비(HITL 상향 + 맥락).

오늘 상태: `MissionRiskAssessor` 는 `report_agent` 에서만 호출되어 `SOCReport.mission_risk`
표시용 죽은 산출물. score 가 아무 게이트도 먹이지 않음. 이 스펙이 triage→response
경로로 승격해 실제 결심에 반영한다.

## 2. 결정된 설계 (grill 확정 4포크)

| 포크 | 결정 |
|---|---|
| Q1 가중 | **상승-전용 modifier** (escalate-only, de-escalate 불가) |
| Q2 이중계산 | **delta-only**: severity 가 이미 안 쓰는 요소만 = `terrain_dependents` + `civil_geo` |
| Q3 트러스트 | 상승전용 + **cap = +1 우선순위 밴드** + 과상승 telemetry |
| Q4 response | `mission_risk` → **HITL 상향만** + `ResponseResult` 맥락 부착 |

### 2.1 핵심 정정 (grounding 중 발견 — Codex 확인 요망)

`severity-policy.yaml`: 레벨 `h` = `auto_response: 활성`(RTB/페일세이프 **자동** 허용).
따라서 METT-TC 가 **severity 레벨**을 m→h 로 올리면 고-민간블라스트 표적에
**자동 페일세이프를 켜는** 역효과 — Q4(인간 게이트 강제)와 정반대.

→ **METT-TC 가중은 severity 레벨을 건드리지 않는다.** 가중 대상 = **priority 축(1~4
큐 순위)** + **HITL 게이트**. severity 레벨은 순수 정책 엔진 권한으로 유지.
- severity 레벨 = 정책 엔진 권한(불변, 포이즈닝 표면 무증가).
- priority = 큐 긴급도(METT delta 상승전용 +1, 위조→과-우선순위=안전).
- HITL = 행동 게이트(mission_risk 상향만, 위조→과-게이트=안전).

세 축 모두 위조 시 **안전 방향**(과상승/과게이트 ≫ 은폐)이며 "정책 엔진이 severity
권한 보유" 교리와 충돌 없음.

## 3. 변경 상세

### 3.1 TriageAgent (`agents/triage_agent.py`)
- 생성자에 `mission_risk: MissionRiskAssessor | None = None`, `mett_policy` 주입.
- `run()`:
  1. 기존: `level, rationale = engine.compute(alert)`; `priority = _PRIORITY[level]`.
  2. `if self._mission_risk:` → `mr = self._mission_risk.assess(alert)`.
  3. **delta 계산**: `mett_delta = mr.factors["terrain_dependents"] + mr.factors["civil_geo"]`
     (severity 미중복 요소만; Q2).
  4. **상승-전용 + cap**: `if mett_delta >= priority_delta_min:` →
     `priority = max(1, priority - priority_delta_cap)` (cap=1, 큐에서 1단계 급상; Q3).
     priority 는 이미 explicit-actor 강등과 동일 축 — 최저 1 floor.
  5. **telemetry**: 상승 발생 시 `severity_rationale` 에 delta·전후 priority 기록 +
     `logger.info`(grep 가능한 과상승 관측). 전용 메트릭 카운터는 후속(Codex diff L —
     현재는 rationale/log 로 관측, guardrail_flags 는 가드레일 전용이라 미사용).
  6. `result["mission_risk"] = mr` 로 SOCState 에 부착.
- 순서: explicit-actor 강등과 METT 상승 **둘 다 priority -1** → 합산 시 cap 별도 관리
  (METT 는 최대 1, actor 는 최대 1, 독립). floor 1 로 클램프.

### 3.2 SOCState (`core/models.py`)
- `mission_risk: MissionRisk` 키 추가(TypedDict, total=False, **append-only** 끝에).

### 3.3 ApprovalAgent (`agents/approval_agent.py`) — HITL 게이트 **실제 강제** 위치
**Codex High 반영**: HITL 상향은 response 가 아니라 **approval 노드**가 강제해야 실효.
graph 는 hitl=True 시 모든 TP 를 validation→**approval**→response 로 태움(라우팅
불변). ApprovalAgent 가 인터럽트 여부만 결정 → 여기 조건을 넓힌다.
- 오늘: `if severity != Severity.HIGH: return auto-approve`. → 즉 h 만 인터럽트.
- 변경: `mission_risk = state.get("mission_risk")` 읽어 인터럽트 조건 확장:
  ```
  force = severity == Severity.HIGH or (
      mission_risk is not None and mission_risk.score >= hitl_force_threshold
  )
  if not force: return auto-approve
  ```
  → medium/low severity 라도 임무위험 高면 **실제 interrupt**(운용자 대기).
- `hitl_force_threshold` 는 정책(severity-policy.yaml `mett_tc`)에서 주입(생성자/settings).
- interrupt 메시지에 `mission_risk_score`·`rationale` 요약 포함(운용자 판단 근거).
- **상향만**: severity==HIGH 는 무조건 유지 → mission_risk 로 게이트를 **낮추지 못함**.

### 3.3b ResponseAgent (`agents/response_agent.py`) — 결과 반영 + 맥락
- `mission_risk = state.get("mission_risk")` 읽음(맥락 부착용).
- **HITL 강제는 하지 않음**(approval 노드가 이미 함). response 는 approval 결과를
  기존대로 반영: 승인 거부 → `auto_response="보류..."`(현행 유지).
- `ResponseResult` 에 `mission_risk` score/note 맥락 부착 → 아래 3.4.
- **hitl=False 그래프**(approval 노드 없음): 강제 게이트 없음. response 가 정직하게
  `mission_risk_note` 로 "임무위험 高 — 인간검토 권고" 표기만(권고전용, 은폐 없음).
- **위조 안전**: mission_risk.score 는 wire 필드(asset_tier/phase/lat) 파생 →
  위조 시 과-HITL(안전). 절대 HITL 제거 방향 없음.

### 3.4 ResponseResult (`core/models.py`)
- 옵션 필드 추가(append-only): `mission_risk_score: int | None = None`,
  `mission_risk_note: str | None = None` (report/감사 맥락). 전체 MissionRisk 객체는
  SOCReport.mission_risk 가 이미 보유하므로 중복 저장 회피 — score+note 만.

### 3.5 report_agent (`agents/report_agent.py`)
- **중복 계산 제거**: `state.get("mission_risk")` 있으면 재사용, 없으면(하위호환)
  기존 `self._mission_risk.assess(alert)`. triage 와 report 산출값 발산 방지.

### 3.6 graph 배선 (`agents/graph.py`)
- `MissionRiskAssessor` 인스턴스를 **TriageAgent 에도 주입**(ReportAgent 와 동일
  인스턴스 공유 — `KeyTerrainMap.from_yaml()` 1회).
- `ApprovalAgent(settings)` 생성 시 `hitl_force_threshold` 주입(정책 적재).
- 라우팅 **불변**(validation→approval→response). ApprovalAgent 인터럽트 조건만 확장.
- 사전-enrich 체인은 불변(KeyTerrainDetector 는 그대로 alert.key_terrain 스탬프).
- `mission_risk` 는 alert 필드가 아니라 **SOCState 산출물** → 사전-enrich(alert 변형)
  아닌 triage 노드 출력이 맞음(트러스트 경계: 내부 산출물, wire 아님).

### 3.7 정책 (`core/policy/severity-policy.yaml`)
신규 `mett_tc` 섹션(외부화 — 하드코딩 금지):
```yaml
mett_tc:
  # 트리아지 priority delta — severity 미중복 요소만(상승전용).
  priority_delta_factors: [terrain_dependents, civil_geo]
  priority_delta_min: 2        # delta 합 ≥ 2 → priority 1단계 급상
  priority_delta_cap: 1        # 최대 +1 밴드(위조 blast 반경 제한)
  # response HITL 강제 임계(상향만; 하향 불가).
  hitl_force_threshold: 6      # mission_risk.score ≥ 임계 → HITL 필수
```
- score 범위: terrain_key(0/2)+terrain_dependents(0-3)+troops_tier(0-4)+
  enemy_advanced(0/2)+time_dwelling(0/1)+civil_geo(0/1) = 0~13. 임계 6 = 중상.
- `policy_loader` 로 적재, 파일 부재/형식 오류 → `PolicyError`.

## 4. 트러스트 / 포이즈닝 분석

| 입력 | 출처 | 위조 시 방향 | 안전? |
|---|---|---|---|
| `terrain_dependents` | asset_id(wire)→policy dependents | 과-우선순위(+1 cap) | ✅ 상승전용 |
| `civil_geo` | lat(wire) | 과-우선순위(+1 cap) | ✅ 상승전용 |
| `mission_risk.score` (HITL, approval 노드) | tier/phase/lat(wire)+kill_chain/dwelling(내부) | 과-HITL(운용자 대기) | ✅ 상향만 |
| severity 레벨 | 정책 엔진 | **불변**(METT 미접촉) | ✅ 권한 분리 |

- 위조로 인한 유일 벡터 = **과상승/과게이트**(alert fatigue) — 은폐 불가.
- cap +1 로 위조 blast 반경 제한(i→최상위 점프 불가; 큐 1단계만).
- `MissionRiskAssessor.assess` 가 `is_key_terrain` 을 asset_id/phase(wire)에서
  재계산 → `KeyTerrainDetector` 처럼 정책 재파생 아님. 단 결과는 상승전용이라
  위조 이득 없음(과상승만). terrain_key 요소는 priority delta 에서 제외(Q2,
  severity 가 이미 key_terrain dynamics 로 소비) → priority 이중 위조 표면 없음.
- **HITL full-score overlap(Codex Medium)**: HITL 임계는 `mission_risk.score` 전체
  사용(terrain_key/troops_tier/enemy/dwelling 포함, severity 와 신호 겹침). 이는
  **의도적** — HITL 은 severity/priority 와 **다른 축**(행동 게이트)이고 임무 전체상
  (블라스트+민간+적 진행)을 봐야 함. 겹침 = 보수적 격상(상향만)이지 이중계산 아님
  (severity/priority 값에 더해지지 않음). priority delta 만 엄격히 비중복.

## 5. 테스트 (`tests/__tests__/`)
- `test_triage_mett_escalates_priority`: dependents+civil 있는 alert → priority -1.
- `test_triage_mett_cap_plus_one`: 큰 delta 여도 priority 최대 1단계만 상승.
- `test_triage_mett_never_deescalates`: delta 0/저-mission 위조 → priority 불변.
- `test_triage_no_double_count`: severity 레벨은 METT 로 **불변**(정책 엔진값 그대로).
- (구현: `tests/__tests__/test_mett_tc_triage.py`)
- `TestMettHitlEnforceable`: severity=m 이지만 score≥임계 → 그래프 interrupt(핵심).
- `test_low_mission_below_high_auto_approves`·`test_no_mission_risk_below_high...`:
  score<임계·부재 → 자동승인(무인터럽트).
- severity==h 항상 interrupt(상향 불변)는 기존 `test_soc_agents::TestHitlInterrupt`
  가 커버(중복 회피).
- `test_high_mission_attaches_note`·`test_low_mission_score_only_no_note`: ResponseResult
  score/note 부착. `test_mett_does_not_lower_hitl`: hitl 하향 없음.
- `TestReportReuse::test_reuses_state_mission_risk`: triage 산출 재사용(sentinel 검증).
- `TestMettTcConfigParse`: 음수 cap/min → 0 클램프(escalate-only 코드 강제).
- severity 레벨 불변: `test_severity_level_untouched`(METT 는 priority/HITL만).

## 6. 미결 / 후속 (open questions)
- ~~approval-node 라우팅~~ **해결(Codex High 반영)**: ApprovalAgent 인터럽트 조건에
  `mission_risk.score >= hitl_force_threshold` 추가 → 게이트 실효. §3.3 참조.
- **hitl=False 그래프**: approval 노드 부재 → 강제 게이트 없음. response 가 권고표기만
  (설계상 hitl=False 는 무인 자동모드 — mission_risk 표기로 정직 반영, 은폐 없음).
- **MissionRisk 가변성(Codex Low)**: SOCState 공유 객체 → response/report 는 **읽기만**
  (mutator 금지 규율). 현재 mutator 없음. 필요 시 후속에서 frozen 전환 검토.
- `priority_delta_min`/`hitl_force_threshold` 초기값은 정책 튜닝 대상(validation 피드백).
- 게이트 정합: 스펙 → Codex 설계리뷰 → 반영 → 구현 → black/ruff/mypy/pytest →
  clean-worktree 검증(#51 교훈) → Codex diff 리뷰 → 커밋/PR/머지.
