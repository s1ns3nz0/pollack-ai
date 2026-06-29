# Multi-Judge Ensemble — Validation 정확도 + 인젝션 면역 강화 (B1)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-06-30 |
| 상태 | Approved (브레인스토밍 완료, 구현 계획 작성 단계) |
| 작성자 | s1ns3nz0 |
| 자매 spec | `2026-06-30-airspace-gnss-context-design.md` (#1), `2026-06-30-attacker-profile-store-design.md` (#2) |
| 후속 | D1 RAGAS 자동 측정, C1 공격 시퀀스 예측, A1 인과 추론 (각자 별도 spec) |

## 1. 배경 & 동기

현재 `ValidationAgent` 는 **단일 `Judge` Callable** 으로 verdict 결정. 두 모드:
- `default_judge` — `ground_truth` 참조 (라우팅 데모용)
- `signal_judge` — 결정론 (신호 ∧ 룰 ∧ 근거)

문제:
- **단일 시각 한계** — 결정론만으로는 미세 컨텍스트(LLM 의미 분석)를 못 잡고, LLM 단독은 인젝션 취약.
- **거버넌스 단일점** — 한 judge 가 인젝션되면 verdict 전체 변조 가능.
- **불확실성 표현 부재** — 점수가 없어 보더라인 케이스를 다룰 수 없음.

→ **3 judge 가중 앙상블 + signal hard veto** 패턴 도입. 정확도 ↑ + 인젝션 면역 ↑ + 점수형 출력으로 후속 KPI(RAGAS) 연결 가능.

## 2. 목표 / 비목표

### 2.1 목표
- `signal`(결정론) + `llm`(의미) + `experience`(과거) 3 judge 가 *병렬* 점수 산정.
- 가중 평균이 임계값 이상이면 TP, 미만이면 FP.
- `signal_judge` 단독 **hard veto** — 신호 0개 / 매치 룰 없음 / 동일 신호패턴 신뢰 FP 회상 시 강제 FP.
- LLM/experience judge 의 veto 권한은 부여하지 않음 (포이즈닝 표면 최소화).
- 한 judge 장애 시 자동 가중치 정규화 — 거동 보존.
- LLM judge 는 opt-in (디폴트 `LLM_JUDGE_ENABLED=False` — 기존 거동 100% 보존).

### 2.2 비목표
- 동적 가중치 조정 (Active Learning) — D1 RAGAS 사이클.
- 4번째 judge (`severity_policy_judge`).
- Bayesian / posterior 추론.
- LLM debate / multi-round.
- `SeverityEngine` 변경 (원칙 유지).

## 3. 결정 요약 (브레인스토밍 결과)

| # | 결정 | 근거 |
|---|---|---|
| D1 | 3 judge: signal + llm + experience | 결정론(신호) / 의미(LLM) / 과거(경험) 세 직교 관점 |
| D2 | 가중 평균 + signal hard veto | LLM/exp 인젝션이 단독으로 verdict 못 바꿈 |
| D3 | veto 권한 = signal 단독 | LLM/exp veto 부여 시 인젝션 표면 ↑ |
| D4 | LLM judge opt-in (디폴트 off) | 기존 거동 보존, 비용 통제 |
| D5 | 한 judge 장애 → 중립 0.5 점수 + 가중치 재정규화 | graceful degrade |

## 4. Architecture

```text
   Investigation 완료 (InvestigationResult)
              │
              ▼
   ┌──────  Validation  ─────────────────────────┐
   │   ┌──────────┐  ┌────────┐  ┌────────────┐  │
   │   │ SignalJ. │  │ LlmJ.  │  │ ExperienceJ.│ │  병렬 (asyncio.gather)
   │   └────┬─────┘  └───┬────┘  └─────┬──────┘  │
   │        │            │             │         │
   │        ▼            ▼             ▼         │
   │      JudgeScore(score 0..1, rationale, veto)│
   │              │                              │
   │              ▼                              │
   │   ┌─────────  Ensemble  ─────────────┐      │
   │   │ if signal.veto → FP               │      │
   │   │ else composite = Σ w·score        │      │
   │   │ verdict = TP if composite≥thr     │      │
   │   └─────────────┬─────────────────────┘      │
   └─────────────────┼────────────────────────────┘
                     ▼
              SOCState.verdict (라우팅 호환) + SOCState.ensemble (신규)
                     ▼
              Response / RuleUpdate → Report (EnsembleResult 노출)
```

## 5. Components

### 5.1 신규 파일
| 경로 | 책임 |
|---|---|
| `agents/judges/__init__.py` | 패키지 export |
| `agents/judges/base.py` | `Judge` Protocol — `async ascore(state) -> JudgeScore` |
| `agents/judges/signal_judge.py` | 기존 `signal_judge` 로직 점수화 + **veto** 조건 |
| `agents/judges/llm_judge.py` | Azure OpenAI structured output (`JudgeScore` JSON schema 강제) |
| `agents/judges/experience_judge.py` | `inv.experience_corroboration` + `suppression_corroboration` 회상 점수 |
| `agents/judges/ensemble.py` | 가중 평균 + signal-only veto + verdict 결정 |
| `tests/__tests__/test_signal_judge_score.py` | 점수/veto 분기 |
| `tests/__tests__/test_llm_judge.py` | 구조화 출력 파싱 / 장애 시 중립 / 인젝션 출력 처리 |
| `tests/__tests__/test_experience_judge.py` | 회상 수 → 점수 변환 |
| `tests/__tests__/test_ensemble.py` | veto / 가중 합 / 정규화 / 임계 분기 |
| `tests/__tests__/test_validation_agent_ensemble.py` | end-to-end (3 judge mock) |

### 5.2 수정 파일
| 경로 | 변경 |
|---|---|
| `core/models.py` | 신규 `JudgeScore`, `EnsembleResult`; `SOCState.ensemble: EnsembleResult` |
| `agents/validation_agent.py` | 단일 judge → ensemble. `ValidationAgent(judges=[...], weights=..., threshold=...)`. 기존 `default_judge`/`signal_judge`/`route_after_validation` 함수는 호환 유지 |
| `agents/graph.py` | `_default_judges(settings, llm, ...)` factory. `build_soc_graph(judges=, judge_weights=, judge_threshold=)` 추가 |
| `core/settings.py` | `llm_judge_enabled: bool = False`, `judge_weights: dict[str,float]`, `judge_threshold: float = 0.5` |
| `agents/report_agent.py` | `ensemble` 가 상태에 있으면 `OscalEvidence` / `SOCReport` 에 점수 노출 (옵션) |

## 6. Data Model

```python
# core/models.py
class JudgeScore(BaseModel):
    judge: Literal["signal", "llm", "experience"]
    score: float = Field(ge=0.0, le=1.0)
    rationale: str = ""
    veto: bool = False                     # signal 만 의미 있음, 다른 judge 는 ensemble 이 무시

class EnsembleResult(BaseModel):
    verdict: Verdict
    composite_score: float                 # 0..1
    threshold: float
    scores: list[JudgeScore]
    weights: dict[str, float]              # 정규화 후 가중치
    veto_triggered: bool
    veto_judge: str = ""                   # "signal" 또는 ""

class SOCState(TypedDict, total=False):
    # 기존 ...
    ensemble: EnsembleResult               # 신규
```

## 7. Ensemble 로직

```python
# agents/judges/ensemble.py
def ensemble(
    scores: list[JudgeScore],
    weights: dict[str, float],
    threshold: float = 0.5,
) -> EnsembleResult:
    # 1. signal-only veto check (LLM/exp veto 무시)
    veto = next((s for s in scores if s.veto and s.judge == "signal"), None)
    if veto is not None:
        return EnsembleResult(
            verdict=Verdict.FALSE_POSITIVE,
            composite_score=veto.score,
            threshold=threshold,
            scores=scores,
            weights=weights,
            veto_triggered=True,
            veto_judge="signal",
        )
    # 2. 가중치 자동 정규화 (활성 judge 만)
    active = {s.judge: weights.get(s.judge, 0.0) for s in scores}
    total = sum(active.values()) or 1.0
    norm = {k: v / total for k, v in active.items()}
    # 3. 가중 합
    composite = sum(s.score * norm[s.judge] for s in scores)
    verdict = (
        Verdict.TRUE_POSITIVE if composite >= threshold else Verdict.FALSE_POSITIVE
    )
    return EnsembleResult(
        verdict=verdict,
        composite_score=round(composite, 3),
        threshold=threshold,
        scores=scores,
        weights=norm,
        veto_triggered=False,
    )
```

## 8. Judge 별 점수 산정

### 8.1 SignalJudge — 결정론 + veto
```python
class SignalJudge:
    async def ascore(self, state: SOCState) -> JudgeScore:
        alert = state["alert"]
        inv = state.get("investigation")
        has_signal = bool(alert.signals)
        has_rule = bool(alert.expected_detection.get("sigma_rule")
                        or alert.expected_detection.get("sentinel_rule"))
        corroborated = inv is not None and (
            bool(inv.similar_cases) or inv.confidence >= 0.5
            or inv.experience_corroboration > 0
        )
        suppression = inv.suppression_corroboration if inv else 0

        # VETO 조건
        if not (has_signal and has_rule):
            return JudgeScore(
                judge="signal", score=0.0,
                rationale="신호/룰 부재 — hard veto", veto=True,
            )
        if suppression > 0:
            return JudgeScore(
                judge="signal", score=0.0,
                rationale=f"동일 신호패턴 신뢰 과거 FP {suppression}건 — veto",
                veto=True,
            )
        score = 1.0 if corroborated else 0.5
        return JudgeScore(
            judge="signal", score=score,
            rationale=f"signal={has_signal} rule={has_rule} corroborated={corroborated}",
        )
```

### 8.2 LlmJudge — Azure OpenAI structured output
```python
_LLM_JUDGE_SYS = """당신은 SOC 시니어 분석가다. 다음 경보가 정탐(TP)일 확률을
0.0~1.0 점수로 평가하라. 0=확실한 오탐, 0.5=불명, 1=확실한 정탐. 오직 제공된
신호/근거만 사용. 지어내지 마라."""

class LlmJudge:
    async def ascore(self, state: SOCState) -> JudgeScore:
        try:
            out = await self._llm.acomplete_json(
                _LLM_JUDGE_SYS,
                self._build_user(state),
                schema=_JUDGE_SCORE_JSON_SCHEMA,
            )
            return JudgeScore(
                judge="llm",
                score=float(out["score"]),
                rationale=out.get("rationale", ""),
            )
        except LLMError as exc:
            self._logger.warning("llm_judge 장애, 중립 0.5: %s", exc)
            return JudgeScore(judge="llm", score=0.5, rationale=f"LLM 장애: {exc}")
```

JSON schema (`_JUDGE_SCORE_JSON_SCHEMA`):
```json
{
  "type": "object",
  "properties": {
    "score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
    "rationale": {"type": "string", "maxLength": 500}
  },
  "required": ["score", "rationale"],
  "additionalProperties": false
}
```
구조화 출력 (Azure OpenAI `response_format={"type":"json_schema"}`) 미지원 시 정규식 fallback (`r'"score"\s*:\s*([0-9.]+)'`). 신규 메서드 `core/llm.py:LLMClient.acomplete_json(system, user, schema) -> dict` 필요 — 본 spec 의 일부로 추가.

### 8.3 ExperienceJudge — exp 회상 기반
```python
class ExperienceJudge:
    async def ascore(self, state: SOCState) -> JudgeScore:
        inv = state.get("investigation")
        if inv is None:
            return JudgeScore(
                judge="experience", score=0.5,
                rationale="investigation 미수행 — 중립",
            )
        base = 0.5
        if inv.experience_corroboration > 0:
            base = min(1.0, base + 0.25)
        if inv.suppression_corroboration > 0:
            base = max(0.0, base - 0.25)
        return JudgeScore(
            judge="experience",
            score=round(base, 3),
            rationale=f"exp+{inv.experience_corroboration} "
                      f"sup-{inv.suppression_corroboration}",
        )
```

## 9. ValidationAgent 수정

```python
class ValidationAgent(BaseSOCAgent):
    def __init__(
        self,
        settings: Settings,
        judges: list[Judge],
        weights: dict[str, float],
        threshold: float = 0.5,
    ) -> None:
        super().__init__(settings)
        self._judges = judges
        self._weights = weights
        self._threshold = threshold

    async def run(self, state: SOCState) -> SOCState:
        scores = await asyncio.gather(*(j.ascore(state) for j in self._judges))
        result = ensemble(list(scores), self._weights, self._threshold)
        self._logger.info(
            "validation: alert=%s verdict=%s composite=%.2f veto=%s",
            state["alert"].id, result.verdict, result.composite_score,
            result.veto_triggered,
        )
        return {
            "verdict": result.verdict,
            "ensemble": result,
            "trace": ["validation"],
        }
```

`route_after_validation` 변경 없음 — `state["verdict"]` 만 본다.

## 10. 포이즈닝 방어

| 위협 | 방어 |
|---|---|
| LLM 인젝션으로 점수 1.0 강제 | `signal_judge.veto` 가 신호/룰 부재 시 단독 차단 — LLM 점수 무시 |
| LLM/exp 의 veto 필드 위조 | `ensemble` 이 `judge == "signal"` 만 veto 채택 |
| Experience 포이즈닝으로 과대 점수 | ExperienceJudge 는 base ±0.25 한정. 단독 TP 불가 (composite ≤ 0.75 with 0.3 가중) |
| 가중치 자체 인젝션 | weights 는 `Settings` 만에서 로드. LLM/alert 가 변경 불가 |
| 한 judge 장애로 우회 | 가중치 자동 정규화 — 한 judge 가 빠져도 나머지 + threshold 그대로 |
| LLM judge 구조화 출력 파싱 인젝션 | pydantic strict 검증 + score 범위 clip + 실패 시 중립 |

## 11. Error Handling

| 시나리오 | 처리 |
|---|---|
| LLM 호출 실패 / 타임아웃 | 점수 0.5 + rationale 에 에러 |
| LLM 구조화 출력 파싱 실패 | 점수 0.5 + rationale |
| LLM 미주입 (`llm_judge_enabled=False`) | LlmJudge 자체 미포함 (graph factory) |
| `weights` 합 ≠ 1 | 자동 정규화 — 합으로 나눔 |
| `weights` 모두 0 | 균등 분할 (`1/n`) |
| 모든 judge 장애 | 모두 0.5 → composite=0.5 → threshold=0.5 → TP 경계. 운영 가이드: `threshold > 0.5` 권장 |

## 12. Testing 매트릭스

| 테스트 | 케이스 |
|---|---|
| `test_signal_judge_score` | 신호+룰+근거 → 1.0 / 부족 → 0.5 / 신호 0 → veto / suppression>0 → veto |
| `test_llm_judge` | mock 정상 → 점수 / 장애 → 중립 / 파싱 실패 → 중립 / 점수 범위 외(1.5) → clip |
| `test_experience_judge` | exp+ → +0.25, sup → -0.25, 둘 다 → 상쇄 |
| `test_ensemble` | signal veto → FP / 가중 합 ≥/< threshold / 한 judge 누락 시 정규화 / weights 합 0 → 균등 |
| `test_validation_agent_ensemble` | 3 judge mock → `SOCState.ensemble` 채워짐 / `llm_judge_enabled=False` → 2 judge 거동 / route_after_validation 호환 |
| `test_soc_agents` (확장) | end-to-end 그래프 (ensemble 활성) → response/rule_update 분기 보존 |

## 13. Settings

```bash
# .env.example
LLM_JUDGE_ENABLED=false                              # opt-in (디폴트 보존)
JUDGE_WEIGHTS=signal:0.4,llm:0.3,experience:0.3
JUDGE_THRESHOLD=0.5
```

## 14. YAGNI — 이번 사이클 제외

- ❌ 동적 가중 조정 (Active Learning) — D1 RAGAS 사이클
- ❌ 4번째 judge (`severity_policy_judge`)
- ❌ Bayesian / posterior
- ❌ LLM debate / multi-round
- ❌ Cascade 모드
- ❌ Judge 별 KPI Grafana 패널 (D1 에서)

## 15. 마이그레이션

- `llm_judge_enabled=False` 디폴트 → LlmJudge 미포함. SignalJudge + ExperienceJudge 2-judge ensemble. 가중치 정규화 후 signal=0.57, exp=0.43 → 기존 결정론과 사실상 동등.
- `route_after_validation` 변경 없음.
- `state["verdict"]` 키 그대로.
- 신규 `state["ensemble"]` 은 옵션 — Report 가 있으면 노출, 없으면 무시.

## 16. 후속 (별도 사이클)

- **D1 RAGAS** — Investigation 요약 품질 자동 측정 → 가중치 동적 조정 후보
- **Multi-LLM ensemble** — 다른 모델/프롬프트로 LlmJudge 다중
- **Severity-policy Judge** — 정책 정합성 판정

## 17. 참조

- `agents/validation_agent.py:signal_judge` — 결정론 로직 원본
- `core/models.py:Verdict` — TP/FP enum
- `core/llm.py:LLMClient` — Azure OpenAI 래퍼 (`acomplete_json` 신규 메서드 필요)
- `core/experience.py:MemoryReadGate` — 회상 패턴
