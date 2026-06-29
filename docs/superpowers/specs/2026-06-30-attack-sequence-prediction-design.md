# Attack Sequence Prediction — Kill Chain 다음 단계 예측 (C1)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-06-30 |
| 상태 | Approved (브레인스토밍 완료, 구현 계획 작성 단계) |
| 작성자 | s1ns3nz0 |
| 자매 spec | #1 Airspace/GNSS, #2 Attacker Profile, B1 Multi-Judge, D1 RAGAS |
| 의존 | #2 Attacker Profile Store 구현 후 (런타임 의존, spec 작성은 독립) |
| 후속 | LLM 기반 예측, 마르코프 n≥3, 멀티-actor 동시 예측 |

## 1. 배경 & 동기

본선 AI 공방전에서 *고정 상대* 가 반복 공격한다. #2 spec 으로 `ActorProfile.kill_chain` (시간순 alert technique 시퀀스) 가 축적된다. 이를 활용:

- **(prev → curr) → next** n-gram 빈도로 *다음 기법* 확률 예측.
- 예측이 임계 이상이면 **Watch List 사전 등록** 및 **헌트 KQL 자동 발사** 후보.
- 본선 점수 직격 — "다음 공격 미리 차단" 시연.

## 2. 목표 / 비목표

### 2.1 목표
- `ActorProfile.kill_chain` 에서 n-gram(n=2) 빈도 표 빌드.
- 현재 경보의 `(prev_technique, curr_technique)` 조건부 *다음 기법* top-K 예측.
- 신뢰 가드: `support_count ≥ 3` AND `probability ≥ 0.5` 미달 시 예측 제외.
- 예측 결과를 `InvestigationResult.predictions` 에 노출 → `ReportAgent` 가 헌트 후보로 명시.
- 미주입 / actor 미회상 / kill_chain 짧음 → 빈 예측 (graceful).

### 2.2 비목표
- LLM 기반 예측 (결정론 우선).
- n≥3 마르코프 (n=2 만).
- 멀티 actor 동시 예측.
- 자동 KQL 룰 생성 (사람 검토 필요 — 별도).
- Watch List **자동** 등록 (예측 ≠ 행동 — 본 사이클은 *권장* 만).

## 3. 결정 요약

| # | 결정 | 근거 |
|---|---|---|
| D1 | 결정론 n-gram(n=2) | 해석 가능 + 라벨 명확 + 본선 시간 |
| D2 | support ≥ 3 + p ≥ 0.5 가드 | 작은 표본의 잡음 제거 |
| D3 | Investigation 노드에서 예측 (별도 노드 X) | 그래프 위상 변경 없음 |
| D4 | 결과는 *권장* — 자동 행동 X | 잘못된 예측의 대응 폭주 방지 |

## 4. Architecture

```text
   Investigation 노드 (alert + actor 회상 후)
              │
              ▼
   ActorProfile.kill_chain (시간순 technique 시퀀스)
              │
              ▼
   SequencePredictor.predict(profile, current_technique) — top-K
              │
              ▼
   list[AttackPrediction(next_technique, probability, support_count)]
              │
              ▼
   InvestigationResult.predictions
              │
              ▼
   ReportAgent: predictions → SOCReport.hunt_candidates (운영자 노출)
```

## 5. Components

### 5.1 신규
| 경로 | 책임 |
|---|---|
| `core/predictor.py` | `SequencePredictor` 클래스 — `build_ngram(chain) -> dict`, `predict(profile, current, k=3) -> list[AttackPrediction]` |
| `tests/__tests__/test_sequence_predictor.py` | n-gram 빈도, 가드, top-K, 빈 chain 처리 |

### 5.2 수정
| 경로 | 변경 |
|---|---|
| `core/models.py` | 신규 `AttackPrediction(next_technique, probability, support_count, basis_actor_id)`; `InvestigationResult.predictions: list[AttackPrediction] = []`; `SOCReport.hunt_candidates: list[str] = []` |
| `agents/investigation_agent.py` | actor 회상 후 `SequencePredictor.predict(profile, current)` 호출. predictions 임베드 |
| `agents/report_agent.py` | `predictions` 가 있으면 `hunt_candidates` 채움 |
| `core/settings.py` | `predict_min_support: int = 3`, `predict_min_probability: float = 0.5`, `predict_top_k: int = 3` |

## 6. Data Model

```python
class AttackPrediction(BaseModel):
    next_technique: str                              # MITRE technique id
    probability: float = Field(ge=0.0, le=1.0)       # 조건부 빈도
    support_count: int                               # 관측 횟수
    basis_actor_id: str                              # 추론 근거 actor

class InvestigationResult(BaseModel):
    # 기존 ...
    predictions: list[AttackPrediction] = Field(default_factory=list)

class SOCReport(BaseModel):
    # 기존 ...
    hunt_candidates: list[str] = Field(default_factory=list)
```

## 7. Predictor 로직

```python
# core/predictor.py
class SequencePredictor:
    def __init__(self, min_support: int = 3, min_prob: float = 0.5, top_k: int = 3):
        self._min_support = min_support
        self._min_prob = min_prob
        self._top_k = top_k

    def predict(
        self, profile: ActorProfile, current: str
    ) -> list[AttackPrediction]:
        chain = profile.kill_chain
        if len(chain) < 2 or not current:
            return []
        # n-gram 빈도: { (prev, curr): { next: count } }
        ngram: dict[tuple[str, str], dict[str, int]] = {}
        for i in range(len(chain) - 2):
            key = (chain[i].technique, chain[i + 1].technique)
            nxt = chain[i + 2].technique
            ngram.setdefault(key, {})[nxt] = ngram.setdefault(key, {}).get(nxt, 0) + 1

        # 현재 경보 의 prev_technique 후보 = kill_chain 마지막 technique
        prev = chain[-1].technique if chain else ""
        next_counts = ngram.get((prev, current), {})
        if not next_counts:
            return []
        total = sum(next_counts.values())
        candidates = []
        for nxt, count in next_counts.items():
            prob = count / total
            if count >= self._min_support and prob >= self._min_prob:
                candidates.append(AttackPrediction(
                    next_technique=nxt,
                    probability=round(prob, 3),
                    support_count=count,
                    basis_actor_id=profile.actor_id,
                ))
        return sorted(candidates, key=lambda p: -p.probability)[: self._top_k]
```

## 8. Investigation 통합

```python
# investigation_agent.run() 에서 actor 회상 직후
profile = await self._recall_actor(alert)
predictions: list[AttackPrediction] = []
if profile is not None and self._predictor is not None:
    current = (alert.mitre.get("techniques") or [""])[0]
    predictions = self._predictor.predict(profile, current)

result["investigation"].predictions = predictions
if predictions:
    self._logger.info(
        "predictions: alert=%s next=%s",
        alert.id, [p.next_technique for p in predictions],
    )
```

## 9. Report 통합

```python
# report_agent.run()
predictions = state.get("investigation").predictions if state.get("investigation") else []
report.hunt_candidates = [p.next_technique for p in predictions]
```

OSCAL evidence 에도 포함 (`build_evidence` 가 predictions 직렬화).

## 10. Error Handling

| 시나리오 | 처리 |
|---|---|
| `actor_read` 미주입 → profile=None | 빈 예측 |
| `kill_chain` 길이 < 2 | 빈 예측 |
| 현재 alert technique 빈값 | 빈 예측 |
| (prev, curr) 가 ngram 에 없음 | 빈 예측 |
| support 또는 probability 가드 미달 | 해당 후보 제외 |

## 11. Testing

| 테스트 | 케이스 |
|---|---|
| `test_sequence_predictor_basic` | 단순 chain [A,B,C,A,B,C,A,B] → predict(profile, "B") = [C] |
| `test_sequence_predictor_support_guard` | support=2 (min=3) → 제외 |
| `test_sequence_predictor_probability_guard` | (A,B)→C:1, (A,B)→D:1 → 둘 다 prob=0.5 못 채택 (count=1 미달) |
| `test_sequence_predictor_top_k` | top_k=2 → 상위 2개만 |
| `test_sequence_predictor_empty_chain` | kill_chain=[] → 빈 결과 |
| `test_investigation_predict_integration` | profile 주입 + predict mock → InvestigationResult.predictions 채워짐 |
| `test_report_hunt_candidates` | predictions 있음 → SOCReport.hunt_candidates 노출 |

## 12. Settings

```bash
PREDICT_MIN_SUPPORT=3
PREDICT_MIN_PROBABILITY=0.5
PREDICT_TOP_K=3
```

## 13. YAGNI

- ❌ LLM 기반 예측
- ❌ n≥3 마르코프
- ❌ 멀티 actor 동시 예측
- ❌ Watch List 자동 등록 (권장만)
- ❌ 자동 KQL 룰 생성
- ❌ Decay (오래된 chain 가중 감소)
- ❌ 시각화

## 14. 마이그레이션

- `predict_min_support` 디폴트 3 — 작은 시연용 actor (chain≤6) 는 예측 못 함. 시연 시 임시 1로 낮춤 가능.
- `predictions` / `hunt_candidates` 디폴트 `[]` — 기존 코드 무영향.
- `SequencePredictor` 미주입 시 빈 결과 — 거동 보존.

## 15. 후속

- **LLM 기반 의미 예측** — LLM 이 TTP 의미 + 컨텍스트 예측
- **n=3 마르코프** — 더 긴 시퀀스 의존
- **자동 헌트 KQL** — 예측 → KQL draft → 검토 PR
- **Watch List 사전 등록** — 신뢰 임계 이상 자동 적용

## 16. 참조

- `2026-06-30-attacker-profile-store-design.md` — ActorProfile.kill_chain 정의
- `core/models.py:InvestigationResult` — 확장 대상
- `agents/report_agent.py` — hunt_candidates 노출
