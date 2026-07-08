# Incident 캡스톤 — CLOSED 재개방(재범) + CAT4(DoS) 권위분류

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (Codex 설계검증 → 구현) |
| 작성자 | s1ns3nz0 |
| 근거 | NIST 800-61 인시던트 재개방, CJCSM 6510 CAT4(DoS). [[coldcase-reopener]] 개념 정합 |
| 선행 | Incident 생명주기(#29/#30), observe_outcome 신뢰관측 채널 |
| base | `feat/tier3-threat-hunt`(스택 최상단) |

## 1. 배경 & 동기
#30 이 CLOSED 까지 생명주기를 돌렸으나 **재범(recidivism)** — CLOSED 된 사건의 동일
actor 재확정 —과 **CAT4(DoS) 권위분류**가 미완. 이 캡스톤으로 Case 루프를 닫는다.

## 2. 목표 / 비목표
### 목표
- **CLOSED 재개방**: `observe_outcome` 에서 `state==CLOSED ∧ CONFIRMED_TP` → **CONTAINMENT
  재개방** + `reopen_count++`. 단조성의 *명시적 예외*(재범만 후퇴 허용, 로깅).
- **CAT4(DoS)**: scenario_id 의 DoS 마커(SWARM/SATURATION/DISABLE/FLOOD/DOS) → CONFIRMED_TP
  권위 CAT4. 순서표 갱신: FP→CAT3 / DoS→CAT4 / order≥11→CAT1 / >2→CAT2 / 1~2→CAT6 / else CAT2.
- `IncidentCase.reopen_count: int` 추가.
### 비목표(후속)
- CAT7(SBOM tamper) — Observation 에 확정 SbomFinding 없음(plumbing 필요) → 유보.
- Incident Commander, 보고시한 SLA.

## 3. 설계
- 재개방(observe_outcome): 정상 스텝와이즈 전진 *전에* CLOSED+CONFIRMED_TP 검사 →
  CONTAINMENT 로 재개방 + reopen_count++ + provisional=False + 권위 CAT 재산정. 이후
  일반 전이 로직은 건너뜀(이미 재개방 처리). CLOSED 아니면 기존 스텝와이즈.
- `_authoritative_cat(env_verdict, kill_chain_stage, is_dos)`: DoS 분기 추가(precedence
  FP > DoS > 단계). `is_dos` = scenario_id 대문자에 DoS 마커 포함.
- DoS 마커: `_DOS_MARKERS` frozenset(정책 아닌 상수 — 시나리오 명명 규약).

## 4. 트러스트/견고성
- 재개방·권위 CAT 는 **신뢰관측(CONFIRMED_TP) 한정**(report 자기확증 격상 불가 유지).
- is_dos 는 scenario_id(탐지소스 필드) 기반 — 자문적 분류일 뿐, 대응 실행 비구동.
- 재개방은 단조성 유일 예외이나 CONFIRMED_TP 게이트 + reopen_count 추적으로 명시적.

## 5. 테스트 (`tests/__tests__/test_incident_recidivism.py`)
- CLOSED + CONFIRMED_TP → CONTAINMENT 재개방 + reopen_count=1. 재재범 → reopen_count=2.
- CLOSED + INCONCLUSIVE/FP → 재개방 안 함.
- CAT4: DoS scenario(SWARM-SATURATION) CONFIRMED_TP → CAT4. 비-DoS → 기존 CAT1/2.
- DoS 마커 무관 시나리오 → CAT4 아님.

## 5.1 Codex 설계검증 반영
- **HIGH reopen 미바운드**: reopen_count 는 추적일 뿐 → **새 alert.id 게이트(같은 관측 재개방 금지)
  + _MAX_REOPEN(100) 하드캡**으로 무한 reopen/close 순환 봉인.
- Medium(DoS marker untrusted scenario_id): CONFIRMED_TP 게이트 + CAT 자문(대응 비구동) → 수용.
  CAT 이 SLA/라우팅 구동하게 되면 신뢰 scenario 태그로 이전(후속).
- Low(marker brittle): eval 명명 규약(의미적 DoS 탐지기 아님) 명시. 향후 exact 태그 선호.
- INFO: 트러스트 분리(EnvVerdict 게이트)·report CLOSED→CONTAINMENT edge 없음·reconciliation 정합 확인.

## 5.2 Codex diff 재검증
HIGH/MEDIUM 0, 원 HIGH 수정 확인(reopen_count<_MAX_REOPEN 이 실제 게이트). 체크리스트 6/6 PASS.
LOW(member cap 축출 후 old alert.id replay 재트리거 가능): **수용** — 진짜 바운드는
_MAX_REOPEN(100) 하드캡이고 총 reopen 이 그로 제한됨. member-window 는 2차 dedup 일 뿐.

## 6. 롤아웃
1. IncidentCase.reopen_count + _authoritative_cat DoS + observe_outcome 재개방.
2. Codex 검증(설계→diff) → 게이트.
3. 브랜치 `feat/incident-recidivism-cat`, 커밋 `feat(incident): CLOSED 재개방(재범) + CAT4(DoS) 권위분류`.
