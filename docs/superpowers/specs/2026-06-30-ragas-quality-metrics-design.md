# RAGAS 자동 측정 — Investigation 분석 품질 KPI (D1)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-06-30 |
| 상태 | Approved (브레인스토밍 완료, 구현 계획 작성 단계) |
| 작성자 | s1ns3nz0 |
| 자매 spec | #1 Airspace/GNSS, #2 Attacker Profile, B1 Multi-Judge Ensemble |
| 후속 | 동적 가중치 보정(Active Learning), 멀티-LLM 평가 |

## 1. 배경 & 동기

현재 Investigation 의 `summary`(LLM) 와 `similar_cases`(RAG) 품질은 **정성 평가**뿐. KPI 자동화 없음. 본선/방산 점수를 위해 다음이 필요:

- LLM 요약이 신뢰 컨텍스트와 정합한가? → `faithfulness`
- 요약이 경보에 답하는가? → `answer_relevancy`
- 검색 컨텍스트가 경보에 관련 있나? → `context_relevancy`

→ **RAGAS** 메트릭을 핫패스 외 비동기로 측정 + Prometheus 게이지 + Grafana 보드.

## 2. 목표 / 비목표

### 2.1 목표
- Investigation 노드 후 *비동기* RAGAS 측정 (핫패스 무영향).
- `faithfulness`, `answer_relevancy`, `context_relevancy` 세 메트릭.
- 측정 결과를 `SOCState.ragas` + Prometheus 게이지 + Grafana 노출.
- `faithfulness < 0.7` 시 `guardrail_flags` 추가 (분석 품질 저하 경고).
- RAGAS 라이브러리 미설치 시 graceful — 핫패스 거동 보존.

### 2.2 비목표
- 동적 가중치 자동 조정 (별도 후속).
- 추론 비용 최적화 / 캐시.
- 멀티-LLM 평가.
- 학습 데이터셋 자동 생성.

## 3. 결정 요약

| # | 결정 | 근거 |
|---|---|---|
| D1 | 비동기 백그라운드 측정 | RAGAS = LLM 호출 추가, 핫패스 SLO 보존 |
| D2 | 세 메트릭만 (`faithfulness`/`answer_relevancy`/`context_relevancy`) | RAGAS 표준 + 본 데이터에 충분 |
| D3 | 결과는 `SOCState.ragas` + Prometheus | 그래프 노출 + 대시보드 동시 |
| D4 | `faithfulness < 0.7` → `guardrail_flags` | 정량 임계 — 운영자 가시화 |
| D5 | RAGAS 미설치 시 graceful | optional dep |

## 4. Architecture

```text
Investigation 노드 완료 (InvestigationResult.summary + similar_cases)
        │
        ▼
   (asyncio.create_task — fire-and-forget 비동기)
        │
        ▼
   RagasEvaluator.aevaluate(alert, summary, contexts)
        │
        ▼
   RagasResult(faithfulness, answer_relevancy, context_relevancy)
        │
        ├──→ SOCState.ragas (병합)
        ├──→ Prometheus 게이지 갱신 (ragas_faithfulness 등)
        └──→ faithfulness < 0.7 → guardrail_flags 추가
```

핫패스: Investigation 노드는 RagasEvaluator 호출 후 *결과를 기다리지 않고* 다음 노드로 진행. 측정 결과는 **다음 alert** 의 메트릭 노출 시점에 누적된다 (실시간성보다 KPI 누적이 목적).

## 5. Components

### 5.1 신규
| 경로 | 책임 |
|---|---|
| `tools/ragas_evaluator.py` | `RagasEvaluator` 클래스 + Protocol. `aevaluate(alert, summary, contexts) -> RagasResult` |
| `tests/__tests__/test_ragas_evaluator.py` | 메트릭 호출 mock + 미설치 graceful + 임계 분기 |

### 5.2 수정
| 경로 | 변경 |
|---|---|
| `core/models.py` | 신규 `RagasResult`; `SOCState.ragas: RagasResult` |
| `agents/investigation_agent.py` | 생성자에 `ragas: RagasEvaluator \| None`. `_schedule_ragas(alert, summary, trusted)` 비동기 |
| `agents/graph.py` | `_default_ragas(settings, llm)` factory. `build_soc_graph(ragas=)` |
| `app/metrics.py` | 신규 게이지 4종 (`ragas_faithfulness`, `ragas_answer_relevancy`, `ragas_context_relevancy`, `ragas_evaluations_total`) |
| `deploy/monitoring/grafana-dashboard.yaml` | RAGAS 패널 추가 (avg / p50 / p95) |
| `core/settings.py` | `ragas_enabled: bool = False`, `ragas_faithfulness_threshold: float = 0.7` |
| `pyproject.toml` | `eval` extra 에 `ragas` 유지 (이미 있음) |

## 6. Data Model

```python
class RagasResult(BaseModel):
    faithfulness: float = Field(ge=0.0, le=1.0)
    answer_relevancy: float = Field(ge=0.0, le=1.0)
    context_relevancy: float = Field(ge=0.0, le=1.0)
    evaluated_at: str                                # ISO8601
    n_contexts: int                                  # 평가 컨텍스트 청크 수
    source: str = "ragas"

class SOCState(TypedDict, total=False):
    # 기존 ...
    ragas: RagasResult                               # 비동기 측정 결과 (옵션)
```

## 7. Evaluator 구현

```python
# tools/ragas_evaluator.py
class RagasEvaluator:
    def __init__(self, llm: LLMClient, threshold: float = 0.7) -> None:
        self._llm = llm
        self._threshold = threshold
        self._logger = get_logger("RagasEvaluator")

    async def aevaluate(
        self, alert: Alert, summary: str, contexts: list[RetrievedChunk]
    ) -> RagasResult | None:
        try:
            from ragas import evaluate
            from ragas.metrics import (
                faithfulness, answer_relevancy, context_relevancy,
            )
            from datasets import Dataset
        except ImportError:
            self._logger.warning("ragas 미설치 — 측정 생략")
            return None
        question = f"{alert.title}: {' '.join(alert.signals)}"
        data = Dataset.from_dict({
            "question": [question],
            "answer": [summary],
            "contexts": [[c.text for c in contexts]],
        })
        try:
            scores = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: evaluate(
                    data, metrics=[faithfulness, answer_relevancy, context_relevancy],
                ),
            )
            return RagasResult(
                faithfulness=float(scores["faithfulness"]),
                answer_relevancy=float(scores["answer_relevancy"]),
                context_relevancy=float(scores["context_relevancy"]),
                evaluated_at=_now_iso(),
                n_contexts=len(contexts),
            )
        except Exception as exc:                       # noqa: BLE001 RAGAS 내부 에러 변화 큼
            self._logger.warning("ragas 평가 실패: %s", exc)
            return None
```

## 8. Investigation 통합 (비동기)

```python
async def run(self, state):
    # 기존 RAG + TI + Sandbox + Vuln + exp 보강 후 ...
    result = {...}
    # 비동기 RAGAS — 핫패스 무영향
    if self._ragas is not None:
        asyncio.create_task(self._evaluate_and_record(alert, summary, trusted))
    return result

async def _evaluate_and_record(self, alert, summary, trusted):
    ragas = await self._ragas.aevaluate(alert, summary, trusted)
    if ragas is None: return
    metrics().observe_ragas(ragas)              # Prometheus 게이지 갱신
    if ragas.faithfulness < self._ragas_threshold:
        self._logger.warning(
            "RAGAS faithfulness 저하: alert=%s score=%.2f",
            alert.id, ragas.faithfulness,
        )
```

> **주의**: `asyncio.create_task` 의 결과는 그래프 머지에 반영되지 않음 — `SOCState.ragas` 는 *다음 alert* 또는 *별도 조회* 시 활용. 본 사이클은 *KPI 누적* 이 목적.

## 9. Prometheus / Grafana

`app/metrics.py` 확장:
```python
def observe_ragas(result: RagasResult) -> None:
    with _METRICS._lock:
        _METRICS.ragas_evaluations_total += 1
        _METRICS.ragas_faithfulness_sum += result.faithfulness
        _METRICS.ragas_answer_relevancy_sum += result.answer_relevancy
        _METRICS.ragas_context_relevancy_sum += result.context_relevancy
```

게이지 노출:
- `soc_ragas_evaluations_total` (counter)
- `soc_ragas_faithfulness_avg` (gauge)
- `soc_ragas_answer_relevancy_avg` (gauge)
- `soc_ragas_context_relevancy_avg` (gauge)

Grafana 패널: 누적 평가 수 / 메트릭별 avg / p50 / p95 (다음 사이클 — 본 spec 은 avg 만).

## 10. Error Handling

| 시나리오 | 처리 |
|---|---|
| `ragas` 미설치 | 호출 시 ImportError → None 반환 (logged warning) |
| `datasets` 미설치 | 동일 |
| RAGAS 내부 예외 (모델/네트워크) | None 반환 + warning |
| LLM 비용 폭주 | 비동기 호출 한도 (`asyncio.Semaphore(2)` — 최대 2개 동시 측정) |
| 빈 컨텍스트 | RAGAS 호출 생략 → None |

## 11. Testing

| 테스트 | 케이스 |
|---|---|
| `test_ragas_evaluator_import_missing` | ragas import 실패 → None, warning |
| `test_ragas_evaluator_metric_call` | mock evaluate → RagasResult 파싱 |
| `test_ragas_threshold_flag` | faithfulness < threshold → guardrail_flags 추가 (Investigation 통합) |
| `test_metrics_observe_ragas` | observe 후 avg 계산 정확 |
| `test_investigation_async_ragas` | fire-and-forget 동작 — Investigation 응답이 RAGAS 완료를 기다리지 않음 |

## 12. Settings

```bash
RAGAS_ENABLED=false                          # opt-in
RAGAS_FAITHFULNESS_THRESHOLD=0.7
RAGAS_ANSWER_RELEVANCY_THRESHOLD=0.7
RAGAS_CONTEXT_RELEVANCY_THRESHOLD=0.7
```

## 13. YAGNI

- ❌ p50/p95 분위수 (avg 만)
- ❌ 메트릭별 동적 임계 조정
- ❌ Active Learning 가중 보정 (별도 사이클)
- ❌ 멀티-LLM 평가
- ❌ 한국어 RAGAS 튜닝

## 14. 마이그레이션

- `ragas_enabled=False` 디폴트 — 미주입 시 거동 보존
- `ragas` 패키지는 `eval` extra (선택 설치)
- `SOCState.ragas` 는 옵션 — Report 가 있으면 노출

## 15. 후속

- **동적 judge 가중 보정** — B1 Multi-Judge 의 weights 를 RAGAS 점수로 자동 조정
- **분위수 / 히스토그램** — Prometheus histogram
- **LLM 비용 추적** — 토큰 사용량 게이지

## 16. 참조

- `agents/investigation_agent.py:_summarize` — 평가 대상 LLM 요약
- `app/metrics.py` — Prometheus exposition 패턴
- RAGAS: <https://docs.ragas.io>
