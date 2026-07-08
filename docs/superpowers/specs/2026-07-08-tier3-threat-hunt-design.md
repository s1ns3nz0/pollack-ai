# Tier3 위협 헌팅 — 예측/갭 신호 융합 hunt 가설(DoD SOC Tier3)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (Codex 설계검증 → 구현) |
| 작성자 | s1ns3nz0 |
| 근거 | DoD CSSP tiered SOC — Tier3(위협 헌팅) 미구현. hunt_candidates 산출만·실행 없음 |
| 선행 | 예측 폐루프(SequencePredictor), campaign next_expected, coverage gaps, staging |
| base | `feat/incident-lifecycle-outcome`(스택 최상단) |

## 1. 배경 & 동기
DoD SOC 매핑서 **Tier3 위협 헌팅**이 공백 — 예측 next-technique·campaign next_expected·
coverage gap 신호는 흩어져 있고(hunt_candidates 는 technique 나열뿐), **선제 hunt 백로그**로
융합·우선순위화하는 에이전트가 없다. 이걸 결정론 `HuntPlanner` 로 채운다 — "헌터가
지금 뭘 선제로 찾아야 하나".

## 2. 목표 / 비목표
### 목표
- `core/hunt.py`: `HuntHypothesis`(focus·source·priority·rationale·target_hint) + `HuntPlanner`.
- 3 소스 융합: **예측**(next_technique×probability) / **campaign**(next_expected) /
  **coverage gap**(현·인접 tactic 의 미탐 technique).
- 결정론 우선순위(kill-chain stage + 소스 가중) + focus dedup + top-k.
- report 노출(`SOCReport.hunt_hypotheses`) — 기존 bare hunt_candidates 대체·상위호환.
### 비목표(후속)
- KQL 리드 자동생성(autokql 별 브랜치 존재 — 중복 회피).
- 실 데이터레이크 hunt 실행, hunt 결과 폐루프.

## 3. 설계
```
HuntHypothesis: focus, source("prediction"|"campaign"|"coverage_gap"), priority:int,
                rationale, target_hint
HuntPlanner.plan(predictions, campaign_matches, current_tactics) -> list[HuntHypothesis]
```
- 예측: focus=next_technique, priority=base_pred + round(probability*10).
- campaign: focus=next_expected, priority=base_camp + matched(진행도).
- gap: 현 tactic + 인접의 미탐(coverage.gaps) → focus=technique, priority=base_gap.
- dedup(focus 첫 매치 최고우선), priority 내림차순 정렬, top_k(기본 10).
- 순수 결정론·읽기전용. 입력 부재 시 빈 리스트.

## 4. 트러스트/견고성
- 읽기전용 산출(신호 융합). predictions/campaign 는 신뢰 파이프라인 산출. coverage 는 정적
  정책. 미주입/빈 입력 graceful. hunt 는 *제시*지 자동 대응 아님(운영자 헌터용).

## 5. 배선
- ReportAgent: predictions(inv)·campaign_matches·current_tactics·coverage 로 HuntPlanner.plan
  → `SOCReport.hunt_hypotheses`. 기존 hunt_candidates 병존(하위호환) 또는 대체.
- graph: HuntPlanner(coverage) 주입(미주입 시 None → hypotheses 빈).

## 6. 테스트 (`tests/__tests__/test_hunt.py`)
- 예측→가설(probability 우선순위), campaign→가설(next_expected), gap→가설.
- dedup(중복 focus), 우선순위 정렬, top_k, 빈 입력 graceful.
- report end-to-end → hunt_hypotheses 노출.

## 5.1 Codex 설계검증 반영
- **H Q4 gap 스코프**: `gaps()` 전역 → 현 tactic order±1 필터 + (tactic_order,id) 정렬(홍수 방지).
- **M Q1 결정론 전순서**: `(-priority, source_rank, tactic, focus)` 키 + base 가중(pred100/camp80/gap50), set 은 멤버십만.
- **M Q2 병존**: hunt_candidates(legacy 예측나열) 유지, hunt_hypotheses=Tier3 백로그 신규. 대체 안 함.
- **Low Q2/Q3**: 필드 소유권(staged=방어준비/hunt_hypotheses=분석가백로그/AutoKQL=별lane)·trust 문서화.
  현 tactic 은 profile 누적 우선(신뢰), 없으면 alert.mitre(자문 스코프만·실행/변이 불가).
- **Note Q5**: current_tactics None/비-list → [] 정규화, coverage/tactic 없으면 gap 생략.

## 7. 롤아웃
1. core/hunt.py + SOCReport.hunt_hypotheses.
2. report 융합 + graph 배선.
3. Codex 검증(설계→diff) → 게이트.
4. 브랜치 `feat/tier3-threat-hunt`, 커밋 `feat(hunt): Tier3 위협 헌팅 — 예측/갭 신호 융합 hunt 가설`.
