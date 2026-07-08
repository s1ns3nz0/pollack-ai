# CPCON 사이버방어태세 사다리 — 전역 태세 → 전 alert 방어강도 하한

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (구현 완료, Codex diff 검증 대기) |
| 작성자 | s1ns3nz0 |
| 근거 | DoD CPCON(Cyberspace Protection Conditions 5→1), 국정원 사이버위기경보(정상/관심/주의/경계/심각). hackathon 선언(ATCIS/MIMS·국정원 태세 연동) |
| 선행 | 기존 `Alert.posture` + severity `posture_modifier`·`lock_no_downgrade_at` 스캐폴딩 |
| 자매 | `2026-07-08-mbcra-key-terrain-design.md`(지형 축 ↔ 본 태세 축) |

## 1. 배경 & 동기
severity 는 이미 `posture`(normal/elevated/high)를 소비하고 하향금지 lock 도 있으나
**전역 태세** 개념·외부 태세 어휘(CPCON/국정원)가 없었다. 팀 선언(ATCIS/MIMS + 국정원
태세)의 미구현 조각. "태세를 올리면 전 alert 방어강도가 최소 그 수준" 을 만든다.

축 상보: MBCRA=지형(공간, 어느 자산이 핵심), CPCON=태세(시간, 지금 위협수준).

## 2. 목표 / 비목표
### 목표
- CPCON 5단계 사다리(DoD 5→1 = 국정원 정상/관심/주의/경계/심각) 정책화.
- 전역 태세(`settings.cyber_posture_level`, 외부 피드/운영자 설정) → alert.posture **하한** 스탬프.
- 시나리오 posture 가 더 높으면 유지(floor 의미). 기존 severity posture_modifier·lock 재사용.
### 비목표
- posture 어휘(normal/elevated/high) 교체 — CPCON→기존 어휘 매핑으로 하위호환.
- COA/HITL 임계 태세연동 — 후속(현재는 severity 축만).
- 실시간 외부 태세 피드 커넥터 — settings 정수로 계약만(피드는 타 lane).

## 3. 설계
| 요소 | 구현 |
|---|---|
| 사다리 | `core/posture.py::PostureLadder` — cpcon-posture.yaml, CPCON level→posture |
| 전역 스탬프 | `PostureProvider.enrich` → alert.posture 하한(읽기전용, model_copy) |
| 배선 | `_triage_with_match` **첫** enricher(severity 진입 전) |
| 설정 | `settings.cyber_posture_level: int 1~5`(기본 5=정상) |
| 정책 | `cpcon-posture.yaml`: level→{name, posture, description} |

CPCON→posture 매핑: 5·4→normal, 3·2→elevated, 1→high(하향금지는 severity lock_at=elevated).

## 4. 트러스트
- 전역 태세는 신뢰 설정(settings/env)에서만. enrich 는 읽기전용·floor-only(상향만) —
  태세로 severity 를 낮추지 않는다. 시나리오 posture 우선(더 높으면 유지).

## 5. 테스트 (`tests/__tests__/test_posture.py`)
- 사다리 매핑(5→normal/3→elevated/1→high)·국정원 표기·빈정책 graceful.
- 하한 상향·시나리오 우선·정상 무변·통합(posture→severity 격상).

## 6. 롤아웃
1. settings.cyber_posture_level + cpcon-posture.yaml + core/posture.py.
2. graph 첫 enricher 배선.
3. Codex diff 검증 → black/ruff/mypy/pytest(606).
4. 브랜치 `feat/cpcon-posture`, 커밋 `feat(cpcon): CPCON 사이버방어태세 사다리 — 전역 태세 하한`.
