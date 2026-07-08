# Incident Case 후반 생명주기 — 신뢰관측 채널(CONTAINMENT→CLOSED + 권위 CAT)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (Codex 설계검증 → 구현) |
| 작성자 | s1ns3nz0 |
| 근거 | NIST 800-61 인시던트 생명주기 후반, CJCSM 6510 권위 CAT |
| 선행 | Incident Case MVP(#29), OutcomeProbe(신뢰관측), recovery/BDA |
| base | `feat/incident-case-lifecycle`(스택 최상단) |

## 1. 배경 & 동기
#29 MVP 는 report 노드에서 **PROVISIONAL(NEW→ANALYSIS)** 까지만. 의미있는 후반 상태
(CONTAINMENT→ERADICATION→RECOVERY→CLOSED)와 권위 CAT(1/2/7)은 report verdict 가
자기확증 가능(default_judge ground_truth)이라 유보했다. 이를 **신뢰관측 채널
(OutcomeProbe CONFIRMED_TP/관측)** 으로 완성한다 — actor 적립·engage 전진과 동일 경계.

## 2. 목표 / 비목표 (Codex 설계검증 반영)
### 목표
- `CaseManager.observe_outcome(alert, env_verdict, obs)` — **INCONCLUSIVE 는 절대 전진
  안 함**(Codex M1). CONFIRMED_TP/FP + 신뢰 Observation 신호만:
  - `<CONTAINMENT` + `CONFIRMED_TP` → CONTAINMENT (provisional=False, 권위 CAT)
  - CONTAINMENT + `CONFIRMED_TP ∧ recovery_applied` → ERADICATION
  - ERADICATION + `CONFIRMED_TP ∧ recovery_applied ∧ ¬reoccurred` → RECOVERY
  - RECOVERY + `(CONFIRMED_FP ∨ no_effect_sustained)` → CLOSED
  - 스텝와이즈 단조(관측 1 = 전진 최대 1).
- **봉합 reconciliation(Codex H2)**: explicit case(`case:<actor_id>`) 로 봉합하되, 같은
  alert 의 **fingerprint case(`case:fp:…`)가 존재하면 explicit case 로 병합**(members·
  최고 state 흡수 + fp-case 삭제) — report 잠정 fp-case 와 outcome explicit-case 분리 봉합.
- **권위 CAT 순서표(Codex H4, 첫 매치·무중첩)**: order≥11→CAT1 / order≥3→CAT2 /
  order 1~2→CAT6 / order 0→CAT2. CONFIRMED_FP→CAT3. (CAT4 DoS·CAT7 SBOM 은 소스
  명확화 필요 → 후속.)
- OutcomeProbe `_submit_case` try/except 격리(Codex M6, BDA 패턴).
### 비목표(후속)
- CAT4(DoS)/CAT7(SBOM tamper) 권위분류(확정 SbomFinding·DoS 시나리오 taxonomy 필요).
- CLOSED 재개방(재범), incident 메트릭, Incident Commander, 보고시한 SLA.

## 3. 설계
- `observe_outcome` — 봉합 `resolve_actor_id`(obs.actor_id 있으니 explicit). 스텝와이즈
  단조(한 관측 = 한 전진, 상태 스킵 금지). CONFIRMED_TP 도달 시 `provisional=False`.
- 전이는 다신호 조건 → 현 상태+신호로 *다음 허용 상태* 산정(순차, `_STATE_ORDER` 가드).
- OutcomeProbe: `_reconstruct_alert(obs)` + `decision.env_verdict` + obs 신호를 넘김.
  기존 actor/exp/pb 제출과 나란히(가드·try 격리).

## 4. 트러스트
- **신뢰관측 전용** — env_verdict 는 OutcomeProbe 의 물리효과 판정(CONFIRMED_TP/FP),
  자기확증 아님. actor 적립·engage 와 동일 신뢰 경계. report 잠정 case 를 확증으로 승격.
- 봉합 obs.actor_id(신뢰 sim_bridge 산). 미존재 → 스킵(권위 승격 불가).
- 단조·스텝와이즈 — 후퇴/스킵 없음.

## 5. 테스트 (`tests/__tests__/test_incident_outcome.py`)
- CONFIRMED_TP → CONTAINMENT + provisional=False + 권위 CAT.
- recovery_applied → ERADICATION, +¬reoccurred → RECOVERY, +no_effect → CLOSED(순차).
- 스텝와이즈: 한 관측이 두 단계 스킵 안 함. CONFIRMED_FP(회복 후)→CLOSED / CAT3.
- 권위 CAT 순서표(tampered→CAT7, order11→CAT1). actor_id 없음 → 스킵.

## 5.1 Codex 설계검증 반영
- **H2 봉합 reconciliation**: observe_outcome 이 fingerprint case 병합(members·state 흡수+삭제).
- **H4 CAT 순서표**: order≥11→CAT1 / >2→CAT2 / 1~2→CAT6 / 0→CAT2, FP→CAT3(무중첩). CAT4/7 후속.
- **M1 INCONCLUSIVE**: 최상단 게이트에서 즉시 None(전진 금지). 전이 전부 CONFIRMED_TP/FP 조건.
- **M6 워커 격리**: `_submit_case` try/except(SOCPlatformError)→errors, BDA 패턴.

## 5.2 Codex diff 재검증 반영
설계지적 H2/M1/M6/스텝와이즈/provisional 전부 FIXED 확인. 잔여:
- H4 partial(predicate 논리중첩) → `_authoritative_cat` 를 `!= CONFIRMED_TP → CAT3` 로 airtight(무중첩).
- NEW-A(Medium): fingerprint(actor_id 무시)만으론 다른 actor 우연일치 오병합 → **fp-case 병합을
  `alert.id ∈ fp_case.member_alert_ids` 조건부**(동일 사건 확증)로 봉인.

## 6. 롤아웃
1. CaseManager.observe_outcome + 권위 CAT + _OUTCOME 전이.
2. OutcomeProbe 배선.
3. Codex 검증(설계→diff) → 게이트.
4. 브랜치 `feat/incident-lifecycle-outcome`, 커밋 `feat(incident): 후반 생명주기 신뢰관측(CONTAINMENT→CLOSED + 권위 CAT)`.
