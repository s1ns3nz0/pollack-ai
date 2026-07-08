# MITRE Engage 적 교전 폐루프 — decoy 레이어를 교전 작전계층으로 승격

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (grill 완료, Codex 교차검증 → 구현) |
| 작성자 | s1ns3nz0 |
| 관련 ADR | `docs/adr/0002-autonomous-self-improving-blue-soc.md` |
| 선행 spec | `2026-07-08-deception-decoy-layer-design.md` (decoy/canary) |
| 자매 spec | `2026-06-30-attacker-profile-store-design.md` (예측 폐루프 템플릿), `core/coa.py` (COA 동형) |
| 후속 | Affect(능동 교란) 자동화, sim_bridge 실제 engagement 센서 |

## 1. 배경 & 동기

교리 커버리지 감사 결과 **MITRE Engage**(Shield 후속, 적 교전 프레임워크)가 공백.
방금 만든 decoy/canary 레이어는 지금 *raw 기능* — Engage 작전 어휘에 매핑되지 않음.

Engage 로 승격 시 두 가치:
1. **traceability**: "미끼 있음" → "교전 작전 능력"(Expose/Elicit/Understand 목표 추적).
2. **"역공격" 본능의 합법 착지**: Engage 의 Elicit=적을 *유도*해 TTP 추출(hack-back 없이).
   첫 grill 에서 거부한 욕구를 교리가 인정하는 방식으로 실현.

COA 매트릭스엔 "Deceive" 셀이 있으나 그 뒤 *작전 계획*이 없다 — Engage 가 그 공백을 채운다.

## 2. 목표 / 비목표

### 2.1 목표
- **actor 별 Engage 상태기계** `NONE→EXPOSE→ELICIT→UNDERSTAND`(3 코어 목표).
- **폐루프**: canary 접촉(신뢰 TP) → 상태 전진 + adversary_cost 누적 → 다음 활동 권고 → 다음 접촉이 재전진(예측 폐루프 동형).
- **adversary_cost = kill-chain 지연 대리지표**: Σ(교전 시점 kill-chain stage-order).
- `EngagePlanner`(CoaPlanner 동형) — (Engage 목표 × kill-chain 단계) → 권고 engagement 활동.
- **COA Deceive 셀 enrich** + report 노출.
- 포이즈닝 면역 계승: **상태 전진은 신뢰 경로(canary→TP)로만.** untrusted decoy_hit 은 severity 색칠만.

### 2.2 비목표
- Affect(능동 교란·리다이렉트) 자동 실행 — 권고까지만(외향 행동은 휴먼 게이트).
  **후속 Affect 작업도 예외 없이 recommendation-only/HITL 고정**(자동 외향행동 영구 금지).
- Prepare 목표 상태화 — decoy 레지스트리 자체가 정적 Prepare, 별도 상태 불요.
- 실제 engagement 센서(canary_hit 을 밀어넣는 주체) — uav-sim-env lane. platform 은 계약만.
- 5목표 전부 — Expose/Elicit/Understand 3코어만(Prepare 정적, Affect 권고전용).

## 3. 결정 요약 (grill 결과)

| # | 결정 | 근거 |
|---|---|---|
| Q1 | MITRE Engage 채택(교리 공백 6개 중) | decoy 의 교리적 집 + "역공격" 합법 착지 + COA Deceive 뒷단 |
| Q2 | 폐루프 = actor 별 Engage 상태기계, **신뢰경로(canary→TP)로만 전진** | 프로필 변이 TP-only(포이즈닝 면역). 예측 폐루프가 템플릿 |
| Q3 | 3 코어 목표(Expose/Elicit/Understand), cost=kill-chain 지연 | Prepare 정적/Affect 외향. 지연=미끼 소각 노력 |
| Q4 | round-기반 전이(1/2/4) + adversary_cost=Σ(stage-order) | 결정론·CoverageMatrix 재사용·policy 튜닝 |
| Q5 | engage-matrix.yaml(목표×단계→활동) + COA Deceive enrich + report | coa-matrix.yaml 동형, Deceive 셀에 actor Engage 주입 |
| Q6 | 스코프=(b) 상태기계+훅+matrix+planner+COA enrich+report+submit 계약 | 센서는 밖, 계약만. 완결 수직 슬라이스 |

## 4. Architecture

```text
  canary 접촉(신뢰 관측) ─► ProbeEngine ─► CONFIRMED_TP ─► ActorWriteGate.submit(engagement=True)
                                                              │
                                                              ▼ (신뢰경로 전용 전진 훅)
                                          EngageAdvancer: 상태 전진 + adversary_cost += stage_order
                                                              │
                                    ┌─────────────────────────┼───────────────────────┐
                                    ▼                         ▼                        ▼
                          ActorProfile.engagement    EngagePlanner            report / COA Deceive enrich
                          (state/rounds/cost, 서명)   (목표×단계→권고활동)      (adversary_cost·다음활동)

  [untrusted decoy_hit] ── severity 색칠만, 상태 전진 절대 없음(루프 밖)
```

## 5. 상세 설계

### 5.1 모델 (`core/models.py`)
- `EngageGoal(StrEnum)`: `NONE / EXPOSE / ELICIT / UNDERSTAND`.
- `ActorEngagement(BaseModel)`: `state: EngageGoal = NONE`, `rounds: int = 0`, `adversary_cost: int = 0`, `last_activity: str = ""`.
- `ActorProfile.engagement: ActorEngagement = Field(default_factory=ActorEngagement)`.
- **`ActorProfile.fingerprint()` payload 에 engagement 포함** — 변조보호(신뢰 검증 대상).

### 5.2 전진기 (`core/engage.py`)
```python
class EngageAdvancer:
    """canary-driven TP 시 actor Engage 상태 전진 + adversary_cost 누적(신뢰경로 전용)."""
    def advance(self, profile: ActorProfile, alert: Alert) -> None:
        # rounds += 1
        # state = _state_for_rounds(rounds)  # 1→EXPOSE, 2→ELICIT, 4→UNDERSTAND (policy)
        # adversary_cost += CoverageMatrix.max_tactic_order(alert tactics)  # 지연 대리지표
```
- 임계(1/2/4)는 settings/engage-matrix 로 튜닝.
- **호출 조건**: `ActorWriteGate.submit` 이 `engagement=True`(canary-driven) 일 때만. mission_effect 등 다른 TP 는 상태 무변.

### 5.3 플래너 (`core/engage.py`)
```python
class EngagePlanner:
    """(Engage 목표 × kill-chain 단계) → 권고 engagement 활동(engage-matrix.yaml)."""
    def recommend(self, goal: EngageGoal, tactics: list[str]) -> EngageRecommendation | None: ...
```

### 5.4 정책 (`core/policy/engage-matrix.yaml`)
- `engage: {EXPOSE|ELICIT|UNDERSTAND: {tactic|"*": {activity, engage_id}}}`.
- 로더 `.from_yaml()` + `SOCPlatformError` graceful-degrade.

### 5.5 배관
- `ActorWriteGate.submit(..., engagement: bool = False)` — 신뢰 canary 여부 전달(기본 False → 기존 호출 무영향).
- `OutcomeProbeAgent`: Observation.canary_hit → submit(engagement=canary_hit) 전달(계약).
- `CoaPlanner`: Deceive 셀 산정 시 actor engagement(목표·권고활동·cost) 주입.
- `ReportAgent`: engagement 상태·adversary_cost 섹션 노출.

## 6. 트러스트/불변식
- **상태 전진 = 신뢰 canary→TP 경로로만.** untrusted decoy_hit(alert 본문)은 severity 색칠만 — 위조로 Engage 상태·adversary_cost 조작 불가(포이즈닝 면역 계승).
- engagement 은 `fingerprint()` 서명 payload 포함 → 저장소 변조 시 read gate 가 거부.
- Affect(외향 교란)는 권고까지만 — 자동 실행 무배선(COA=운영자 메뉴, 휴먼 게이트).

## 7. 테스트 (`tests/__tests__/test_engage.py`)
- `test_advance_expose_elicit_understand`: round 1/2/4 → 상태 전이.
- `test_adversary_cost_accrues_stage_order`: 후반단계 교전 → cost 큰 증가.
- `test_untrusted_decoy_no_advance`: engagement=False(decoy_hit only) → 상태 NONE 유지(포이즈닝 회귀 가드).
- `test_engagement_signed`: engagement 변조 → read gate 거부.
- `test_planner_recommends_by_goal_stage`: 목표×단계 → 활동 조회, 미정의 → None.
- `test_coa_deceive_enriched`: actor engagement 있을 때 Deceive 셀에 권고활동 주입.

## 9. Codex 교차검증 반영 (설계 하드닝)

| # | Codex 지적 | 심각도 | 수정 |
|---|---|---|---|
| 1 | `engagement: bool` 이 호출자 주장 — canary 와 구조적 미결합 | High | **`ProbeEngine.decide()` 가 유일 생산자.** `ProbeDecision.engagement = canary_hit AND verdict==CONFIRMED_TP` 를 신뢰 관측에서 산출. gate 는 `decision.engagement` 만 소비. submit 은 신뢰경계 메서드(hotpath 미호출 — 그래프는 enrich 만) 임을 계약 명시 |
| 2 | auto-fingerprint 신원으로 attacker-IOC 가 상태 조작 | High | **Engage 전진은 explicit actor_id 한정.** `_submit_actor` 가 이미 `obs.actor_id` 필수(line 130) → 전진도 동일 게이트. auto-fp 관측은 적립은 되나 **engage 전진 안 함** |
| 3 | replay 관측이 rounds/cost 이중계상 | High | **멱등키=alert_id.** `ActorEngagement.seen_alert_ids`(cap 200)에 기록, 기존 id 면 전진 skip |
| 4 | adversary_cost 가 가변 tactic 메타서 파생 | Med | 입력은 신뢰 ObservationSource 산 `obs.alert_mitre`. `CoverageMatrix.max_tactic_order` 로 서버정규화(미지 tactic→0). 신뢰경계 문서화 |
| 5 | 로드맵 "Affect 자동화" 가 no-hack-back 약화 | Med | §2.2·§10 에 후속 Affect 도 HITL 고정 명시 |
| 6 | fingerprint payload 변경이 기존 서명 프로필 무효화 | Low | **조건부 포함**: engagement 이 기본값(NONE·0·빈)일 때 payload 에서 생략 → 레거시 프로필 해시 불변(하위호환 마이그레이션) |

### 9.1 Codex diff 재검증(구현 후) 반영
H1·H2·L6 **HOLDS** 확인. 추가 Medium 3건 처리:

| 지적 | 수정 |
|---|---|
| M-a: canary+mission_effect 동시 관측 시 engagement 누락 → 루프 정지 | `decide()` 에서 engagement 을 effect 분기와 독립 산출(`mission_effect` 분기도 `engagement=obs.canary_hit`) |
| M-b: 빈 alert_id 미dedup + cap 축출 후 재계상 | 빈 alert_id → 전진 금지. cap 500(교전량 상한의 수배)로 상향 + 무한멱등은 신뢰 source 1차 dedup 위임 명시 |
| M-c: write 전 in-place 변이 | 기존 `_merge_profile`·prediction 카운터와 동일 패턴 → **수용**(한 필드만 다른 패턴 = 불일치). InMemoryStore 한정, 실 store 는 aload 사본 |

## 8. 롤아웃
1. 모델(EngageGoal/ActorEngagement/ActorProfile.engagement + fingerprint).
2. `core/engage.py`(Advancer/Planner) + engage-matrix.yaml.
3. ActorWriteGate.submit(engagement) 훅 + OutcomeProbeAgent 배관.
4. CoaPlanner Deceive enrich + ReportAgent 노출.
5. **Codex 교차검증**(설계 → diff 2회) → black/ruff/mypy/pytest.
6. 브랜치 `feat/engage-adversary-loop`, 커밋 `feat(engage): MITRE Engage 적 교전 폐루프 — decoy→Expose/Elicit/Understand + adversary-cost`.
