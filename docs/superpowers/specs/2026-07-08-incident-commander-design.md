# Incident Commander — 인시던트 생명주기 오케스트레이션(DoD SOC)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (Codex 설계검증 5건 반영 → 구현) |
| 작성자 | s1ns3nz0 |
| 근거 | DoD SOC Incident Commander(에스컬레이션·티어 태스킹·HITL 조율). NIST 800-61 조정 |
| 선행 | Incident Case 전 생명주기(#29~#34): state·CAT·severity_peak·reopen_count·report_due_at |
| base | `feat/incident-cat7-sbom`(스택 최상단) |

## 1. 배경 & 동기
DoD SOC 매핑의 마지막 공백 — **Incident Commander**(사건 조정 역할). Case 생명주기는
갖췄으나 그 위에서 "에스컬레이션 할까 / 어느 티어에 태스킹 / HITL 필요 / 보고 초과" 를
결정하는 **조율 계층**이 없다. Case 상태·CAT·재범·보고시한을 읽어 결정론 **지시
(directive)** 를 산출한다. COA 처럼 *자문·운영자 메뉴* — 자동 실행·외향 행동 없음.

## 2. 목표 / 비목표 (Codex 5건 반영)
### 목표
- `IncidentDirective`(escalation·hitl_required·report_overdue·assigned_tier·
  recommended_action·**provisional**·rationale). provisional 미러 필드로 지시 신뢰도 명시.
- `IncidentCommander.direct(case, now_iso="")` — Case 신호 → 결정론 지시. **순수·무 I/O·total** 매핑(예외 불가).
- **2모드 계약(F2)**: 같은 순수함수가 provisional case(report-time, CAT6/8)엔 bounded 지시를,
  권위 case(CONFIRMED_TP 후 CAT1/4/7)엔 full-high 지시를 산출. report 노드는 provisional 공급,
  권위 지시는 후속 모니터링 패스 몫(현재 표면 없음 — 비목표).
- **에스컬레이션 rank(F5)**: 0=low/1=medium/2=high. base=CAT(고위험{CAT1,CAT4,CAT7}→2,
  {CAT2}→1, 그 외→0). 소프트범프 +1: reopen_count>0(재범), severity_peak==HIGH.
  최종 rank=min(base+범프, 2). **provisional severity 범프는 rationale 에 "baseline-derived
  (미확증)" 라벨(F1)** — 절대 tier3/HITL 하드게이트 아님.
- **HITL(F1) — 권위 게이트만**: `(not provisional and cat in 고위험)` ∨ `reopen_count>0`(재범은
  권위 CONFIRMED_TP 재확정 산). provisional severity 단독은 HITL 강제 못함(포이즈닝 봉인).
- **티어**: `tier3 if hitl_required else tier2`(hitl 이 이미 권위게이트 — 이중정의 제거).
- **recommended_action total table(F3)** — 전 IncidentState:
  NEW→트리아지, ANALYSIS→Tier2 조사, CONTAINMENT→격리, ERADICATION→축출, RECOVERY→복구,
  CLOSED→교훈. **reopened override 는 CONTAINMENT 만**(reopen 이 state 를 CONTAINMENT 로 리셋
  → `reopen_count>0 and state==CONTAINMENT`→재교전; RECOVERY/CLOSED 영구 override 금지).
- report_overdue: `is_case_overdue(case, now_iso)`.
### 비목표
- 자동 에스컬레이션/통보 발송·태스킹 실행(외향 — 운영자·별 모니터링).
- 다중 case 스토어 스캔 오케스트레이션(후속 — store 열거 필요).
- **정책 YAML(F4 제거)**: 고위험 CAT 집합·rank 는 교리상수(incident.py `_DOS_MARKERS` 패턴).
  I/O 없음 → from_yaml/graceful 표면 자체 소멸.

## 3. 설계
- `core/commander.py`: IncidentDirective(BaseModel) + IncidentCommander(무상태 클래스).
- `direct(case, now_iso)` 순수 결정론·total — 부작용 없음, 예외 던지지 않음(제시만).
- 교리상수: `_HIGH_CAT={"CAT1","CAT4","CAT7"}`, `_MED_CAT={"CAT2"}`, `_ACTION` 매핑(모듈 상수).
- report 노드: incident_case 있으면 `direct(case)` → SOCReport.incident_directive(now="" → overdue=False).

## 4. 트러스트/견고성
- 결정론·읽기전용·total — Case 상태 변이·응답 실행·예외 없음(COA·hunt 와 동일 자문 원칙).
- **트러스트 경계(F1)**: HITL/tier3 는 권위 신호(provisional=False 고위험 CAT ∨ reopen)에만.
  provisional severity(baseline-derived, 위조가능)는 escalation 소프트범프+라벨까지 — 하드게이트 불가.
- **graceful(F4)**: 정책 I/O 없음 + total 매핑 → direct() 는 어떤 case 로도 크래시 불가.
  now 미가용/파싱실패 → report_overdue=False(is_case_overdue 기존 graceful).

## 5. 테스트 (`tests/__tests__/test_commander.py`)
- 권위 CAT1/7(provisional=False) → escalation high + hitl + tier3.
- **provisional CAT7(F1/F2)** → HITL 강제 안됨, tier2, escalation bounded(재범/severity 없으면 low).
- provisional CAT8 → low + tier2 + hitl False.
- reopen_count>0 → hitl True + tier3(재범 권위신호).
- **provisional + severity_peak HIGH(F1)** → escalation 범프되나 HITL False·tier2(하드게이트 아님) + 라벨.
- rank cap: 고위험+reopen+HIGH → high 에서 포화(overflow 없음).
- recommended_action: 전 IncidentState 매핑 + reopened CONTAINMENT→재교전, RECOVERY 는 미override.
- report_overdue: 초과 case+now → True / now="" → False.

## 6. 롤아웃
1. IncidentDirective + IncidentCommander(교리상수, 정책 YAML 없음).
2. report 배선(SOCReport.incident_directive).
3. Codex 검증(설계→diff) → 게이트.
4. 브랜치 `feat/incident-commander`, 커밋 `feat(incident): Incident Commander — 생명주기 오케스트레이션(에스컬레이션·티어·HITL)`.
