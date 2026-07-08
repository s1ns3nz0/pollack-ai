# cATO — 지속 인가 + POA&M 합성(NIST 800-37 RMF / DoD DevSecOps)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (구현 완료, Codex diff 검증 대기) |
| 작성자 | s1ns3nz0 |
| 근거 | NIST 800-37 RMF, DoD Continuous ATO(cATO), NIST 800-53 통제. hackathon 선언(cATO MBCRA + OSCAL 자동 증거) |
| 선행 | BAS(방어검증)·SLOMonitor(상시감시)·SBOMVerifier(공급망)·OSCAL(증거) |

## 1. 배경 & 동기
팀 선언(cATO + OSCAL 자동증거) 미구현 조각. OSCAL 은 *증거*를 만들지만 그 증거의
**지속 인가 판정**이 없었다. BAS/SLO/SBOM 상시 검증 신호를 NIST 800-53 통제 갭으로
환산 → **POA&M**(미해결 갭 추적) → 갭 심각도로 인가태세(authorized/conditional/at_risk).

## 2. 목표 / 비목표
### 목표
- 방어 검증 신호 3종(BAS 탐지 커버리지·SLO 위반·SBOM 무결성) → 통제 갭 POA&M.
- 결정론 인가 판정: 고위험 갭→at_risk, 중/저→conditional, 무→authorized.
- 정책구동(cato-controls.yaml): 통제↔신호 매핑 + BAS 하한.
### 비목표
- 실시간 통제 스캐너/외부 GRC 연동 — 기존 신호 재사용만.
- OSCAL 문서 포맷 변경 — 별개(cATO 는 판정 계층).
- 자동 인가 승인 행위 — 판정·POA&M 제시까지(승인은 운영자).

## 3. 설계
| 요소 | 구현 |
|---|---|
| 모델 | `PoamItem`(control_id/family/severity/source/gap) + `CatoStatus`(authorization/poam) |
| 정책 | `cato-controls.yaml`: CA-8(bas)/SI-4(slo)/SR-4(sbom) + bas_detection_floor |
| 엔진 | `core/cato.py::CatoAssessor.assess(bas, slo_breaches, sbom_findings)` → CatoStatus |

### 갭 → 심각도
- BAS detection_ratio < 하한 → CA-8 high.
- SLO 위반 → SI-4, 심각도는 SloBreach 자체값.
- SBOM: tampered/vulnerable=high, unregistered=medium → SR-4.
- 인가태세 = POA&M 최고 심각도(high→at_risk, 그 외 갭→conditional).

## 4. 트러스트/견고성
- 입력은 신뢰 내부 검증기 산출(BAS/SLO/SBOM). from_yaml 은 비-dict/비정수 floor →
  PolicyError(graceful degrade). de-escalation 방향 아님(갭은 인가 강등만).

## 5. 테스트 (`tests/__tests__/test_cato.py`)
- 정책 로딩·빈/형식오류 graceful.
- clean→authorized, bas 하한미달→at_risk, slo→conditional, sbom 변조→at_risk, 혼합 최고심각도 지배.

## 6. 롤아웃
1. PoamItem/CatoStatus 모델 + cato-controls.yaml + core/cato.py.
2. Codex diff 검증 → black/ruff/mypy/pytest(617).
3. 브랜치 `feat/cato-poam`, 커밋 `feat(cato): 지속 인가(cATO) + POA&M 합성`.
