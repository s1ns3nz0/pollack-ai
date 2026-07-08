# CAT7(악성 로직) 권위분류 — 신뢰 확정 SBOM 변조 신호

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (Codex 설계검증 → 구현) |
| 작성자 | s1ns3nz0 |
| 근거 | CJCSM 6510 CAT7(Malicious Logic). #30/#32 에서 소스 부재로 유보한 항목 |
| 선행 | Incident 권위 CAT(#30/#32), OutcomeProbe 신뢰관측, SBOM 검증 |
| base | `feat/incident-reporting-sla`(스택 최상단) |

## 1. 배경 & 동기
CAT7(악성 로직=malware/rootkit/펌웨어 변조)은 #30/#32 에서 **Observation 에 확정 SBOM
변조 신호가 없어** 유보됐다. 신뢰 센서가 확정 변조를 관측했을 때 세우는 **신뢰 관측 필드**(`Observation.sbom_tampered`,
canary_hit 과 같은 신뢰 부류)를 추가한다. **단 분류전용(Codex M): canary_hit 은 TP 를 *구동*
하지만 sbom_tampered 는 기존 CONFIRMED_TP 에 *올라타* CAT7 로 *분류*만 한다**(ProbeEngine
무변경 — 스코프 안전). sbom_tampered 가 독립적으로 TP 확정하게 하는 건 후속(scope 확대).

## 2. 목표 / 비목표
### 목표
- `Observation.sbom_tampered: bool`(신뢰 센서 산 — **분류전용**, TP 구동 아님).
- `_authoritative_cat(env, stage, is_dos, is_malicious_logic)` — 악성로직→CAT7.
- 순서표: FP→CAT3 / **악성로직→CAT7** / DoS→CAT4 / order≥11→CAT1 / >2→CAT2 / 1~2→CAT6 / else CAT2.
- `_submit_case` 가 obs.sbom_tampered → observe_outcome 로 전달.
### 비목표
- 실제 센서(sbom_tampered 를 세우는 주체)는 uav-sim-env lane — platform 은 계약만.
- report-node 권위 CAT7 금지(신뢰관측 전용, 자기확증 격상 불가 유지).

## 3. 설계
- `Observation` 에 `sbom_tampered: bool = False` 추가(canary_hit 동형 신뢰 필드).
- `observe_outcome(..., sbom_tampered: bool = False)` → `_authoritative_cat` 에 전달.
- precedence: 악성로직(CAT7) > DoS(CAT4) > 단계(CAT1/2/6). **교리근거**: 악성로직은 아티팩트
  기반(malware/rootkit 존재)이라 가장 특정 — malware 가 유발한 DoS 도 근원은 악성로직이므로
  CAT7 이 지배. 중첩(sbom_tampered ∧ DoS scenario) 시 first-match 로 CAT7(overlap 테스트 유지).
- 신뢰경계: sbom_tampered 는 신뢰 ObservationSource 산(untrusted alert 필드 아님).
  CONFIRMED_TP + provisional=False 일 때만 권위 CAT7 세팅.

## 4. 트러스트
- CAT7 은 **신뢰 확정 tamper 관측** 한정 — untrusted alert 의 sbom_components 로 격상 불가.
  (report 잠정 case 는 CAT8/6, 권위 CAT7 은 OutcomeProbe 신뢰채널 전담.)

## 5. 테스트 (`tests/__tests__/test_incident_cat7.py`)
- sbom_tampered=True + CONFIRMED_TP → CAT7. precedence: CAT7 > CAT4(DoS) > CAT1(order11).
- sbom_tampered=False → 기존 CAT(단계/DoS). CONFIRMED_FP → CAT3(악성로직 무관).
- _submit_case 가 obs.sbom_tampered 전달(워커 통합).

## 6. 롤아웃
1. Observation.sbom_tampered + _authoritative_cat CAT7 + observe_outcome 전달 + _submit_case.
2. Codex 검증(설계→diff) → 게이트.
3. 브랜치 `feat/incident-cat7-sbom`, 커밋 `feat(incident): CAT7(악성로직) — 신뢰 확정 SBOM 변조 신호`.
