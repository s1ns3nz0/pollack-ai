# Diamond Model of Intrusion Analysis — 4 정점 정형화 + 정점 피벗

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (구현 완료, Codex diff 검증 대기) |
| 작성자 | s1ns3nz0 |
| 근거 | Diamond Model of Intrusion Analysis(Caltagirone et al.) — DoD/CTI 표준 침입분석 |
| 선행 | `actor_fingerprint`([[attacker-profile-store]]) — adversary/infra/capability 원천 |

## 1. 배경 & 동기
actor_fingerprint 는 (tactics·techniques·signals·ip24) 지문이지만 침입분석 다이아몬드
(교리) 로 정형화되지 않았다. 한 사건을 **Adversary·Capability·Infrastructure·Victim**
4 정점으로 사상하면, 정점 피벗("같은 인프라/능력을 쓰는 다른 공격자")으로 교차 상관이
가능하다. campaign(시퀀스)·predictor(n-gram) 와 상보 — 이건 *정점 공유* 축.

## 2. 목표 / 비목표
### 목표
- `DiamondEvent`: alert(+프로필) → 4 정점 사상(결정론).
- `DiamondAnalyzer.pivot`: 사건 집합 → 정점 공유 상관(서로 다른 공격자 2+).
- 프로필 누적 TTP/IOC 로 정점 보강(선택).
### 비목표
- 그래프 시각화/DB — 상관 산출까지.
- 자동 귀속 판정 — 정점 공유 제시(판단은 분석가).
- adversary 정점 피벗 — 사건별 고유라 상관축 제외.

## 3. 설계
| 요소 | 구현 |
|---|---|
| 모델 | `DiamondEvent`(adversary/capabilities/infrastructure/victim) + `DiamondPivot` |
| 엔진 | `core/diamond.py::DiamondAnalyzer.build(alert, profile?)` + `.pivot(events)` |
| 피벗 | (vertex,value)→공격자 집합, 서로 다른 공격자 ≥2 공유 시 상관. count 내림차순 |

## 4. 트러스트
- build 는 alert 값 + 선택적 신뢰 프로필. 순수 함수(외부조회 없음). pivot 은 결정론
  집계(정렬 산출). adversary 빈 사건은 피벗서 제외(무의미 상관 방지).

## 5. 테스트 (`tests/__tests__/test_diamond.py`)
- build: alert 사상·프로필 정점 보강.
- pivot: 인프라/능력 공유 상관·동일 공격자 비상관·무상관 빈 리스트.

## 6. 롤아웃
1. DiamondEvent/DiamondPivot 모델 + core/diamond.py.
2. Codex diff 검증 → black/ruff/mypy/pytest(623).
3. 브랜치 `feat/diamond-model`, 커밋 `feat(diamond): 침입분석 다이아몬드 4정점 + 정점 피벗`.
