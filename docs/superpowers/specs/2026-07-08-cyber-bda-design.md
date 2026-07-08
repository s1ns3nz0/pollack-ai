# 사이버 교전피해평가(BDA) — 방어효과 → 기능피해 + 복구권고

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (구현 완료, Codex diff 검증 대기) |
| 작성자 | s1ns3nz0 |
| 근거 | JP 3-60 Battle Damage Assessment(사이버판), DoD 교전평가 |
| 선행 | `core/outcome.py`(effect 관측), `MissionContinuity`(임무 지속성), `RecoveryPlan`(복구) |

## 1. 배경 & 동기
outcome ProbeEngine 은 방어 effect(0~1)를 관측하지만 그것을 **교전피해 판정·조치
권고**로 정형화하지 않았다. BDA 는 effect 의 역을 기능피해로 환산하고, 복구 성공 여부와
임무 지속성을 결합해 재교전(복구) 필요성 + 평가 확신도를 산출한다. outcome=효과 관측,
BDA=피해 판정·조치 권고.

## 2. 목표 / 비목표
### 목표
- `BdaAssessor.assess(effect, obs, continuity?)` → `BdaReport`(피해등급/복구권고/확신도).
- 방어효과 역방향 피해 매핑 + 복구성공(적용∧미재발) 판정 + 관측충분도 확신도.
### 비목표
- 자동 복구 실행 — 권고까지(실행은 RecoveryPlanner/운영자).
- 물리 피해 정량화 — 기능피해 등급까지.

## 3. 설계
| 요소 | 구현 |
|---|---|
| 모델 | `BdaReport`(damage_level/effect/mission_impact/restore_recommended/confidence) |
| 엔진 | `core/bda.py::BdaAssessor.assess` |
| 피해 | effect≥0.8 none / ≥0.5 light / ≥0.2 moderate / <0.2 severe (effect clamp) |
| 복구권고 | 유의미 피해(moderate+) ∧ ¬(recovery_applied ∧ ¬reoccurred) |
| 확신도 | window≥5분 ∧ (effect/무효과 지속 관측) → high, else low |

## 4. 트러스트/견고성
- 입력 effect 는 신뢰 ProbeEngine 산출. clamp(0~1) 로 범위밖 방어. 순수 결정론.
  복구권고는 조치 제안일 뿐 자동 실행 없음.

## 5. 테스트 (`tests/__tests__/test_bda.py`)
- 피해등급(높은효과→none, 0→severe, clamp), 복구권고(미복구·재발→권고, 복구완료→무),
  경미피해 무권고, 확신도(짧은 윈도우→low), 임무영향 continuity 연계.

## 6. 롤아웃
1. BdaReport 모델 + core/bda.py.
2. Codex diff 검증 → black/ruff/mypy/pytest(637).
3. 브랜치 `feat/cyber-bda`, 커밋 `feat(bda): 사이버 교전피해평가 — 방어효과→기능피해+복구권고`.
