# OutcomeProbe — 시뮬 관측 자동 라벨 + 3 gate 적립 (A-1)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-06-30 |
| 상태 | Approved (브레인스토밍 완료, 구현 단계) |
| 작성자 | s1ns3nz0 |
| 자매 spec | #2 Attacker Profile, B-1 PB 효과 점수, T1 Threat Landscape |
| 후속 | 실제 sim_bridge ObservationSource 어댑터, LLM 자문, effect 자체 학습 |

## 1. 배경 & 동기

자가발전 루프의 *시발점* — 현재까지 모든 gate(exp/actors/pb_scores) 는
`env_verdict` + `effect` 입력을 외부 호출자에 의존. **자동 라벨링 통로가 없으면 본
파이프라인은 *수동 라벨* 없이는 학습 불가**.

본 spec 은 `ObservationSource` Protocol + `ProbeEngine`(결정론 룰) +
`OutcomeProbeAgent`(BaseWorkerAgent) 를 도입해 시뮬에서 관측된 후속 신호를 자동으로
3 gate 에 fan-out 한다.

## 2. 목표 / 비목표

### 2.1 목표
- `ObservationSource` Protocol — 호출자가 시뮬 관측을 push 또는 pull 로 공급.
- `ProbeEngine.decide(observation)` — 결정론 매트릭스 → `(env_verdict, effect)`.
- `OutcomeProbeAgent.run()` (BaseWorkerAgent) — 사이클당 observation 일괄 처리 →
  `MemoryWriteGate` + `ActorWriteGate` + `ActorPlaybookOutcomeGate` 호출.
- `app/learning.py` 통합 — outcome_probe 미주입 시 거동 보존.
- 인젝션 표면 최소화 — 결정론 룰만, LLM 사용 X.

### 2.2 비목표
- 실제 `sim_bridge` 어댑터 (후속 spec).
- 큐/이벤트 인프라.
- LLM 판정.
- effect 자체 학습 (피드백 루프).
- 가중 점수 모델.

## 3. 결정 요약

| # | 결정 | 근거 |
|---|---|---|
| D1 | 입력 = `ObservationSource` Protocol | 시뮬 결합 분리, spec scope 작음, 교체 쉬움 |
| D2 | 결정 = 결정론 룰 매트릭스 | 인젝션 면역, 재현 가능, 정책 yaml 화 가능 |
| D3 | 통합 = BaseWorkerAgent | 핫패스 영향 0, T1 패턴 일관 |
| D4 | effect 매트릭스 = env_verdict + 재발 조합 | 단순·해석 가능 |
| D5 | 3 gate 모두 fan-out (exp/actors/pb_scores) | 자가발전 루프 닫음 |

## 4. effect 매트릭스

| 관측 조건 | env_verdict | effect | 근거 |
|---|---|---|---|
| `mission_effect_observed=True` AND `reoccurred=True` | `CONFIRMED_TP` | 0.0 | PB 완전 실패 (재발 = 차단 못함) |
| `mission_effect_observed=True` AND `reoccurred=False` | `CONFIRMED_TP` | 0.3 | PB 부분 효과 (효과 났지만 첫 발생) |
| `no_effect_sustained=True` AND `window_min ≥ 5` | `CONFIRMED_FP` | 1.0 | PB 차단 완료 / 오탐 |
| 그 외 | `INCONCLUSIVE` | 0.5 | 관측 불충분 — 보류 |

`min_window_for_fp` 디폴트 5분 — 너무 짧으면 transient FP 위장 위험. 운영자가 settings 조정 가능.

## 5. Architecture

```text
[시뮬 / 외부 신호 소스]
        │  ObservationSource.apoll() → list[Observation]
        ▼
Deployment B run_cycle → OutcomeProbeAgent.run()
        │
        ├── 각 Observation:
        │     ProbeEngine.decide() → (env_verdict, effect)
        │
        ├── MemoryWriteGate.submit  (exp/)            — INCONCLUSIVE/AUTO suppression 거부
        ├── ActorWriteGate.submit   (actors/)         — TP-only 가드
        └── ActorPlaybookOutcomeGate.submit (pb_scores) — playbook_id+actor_id 둘 다 있을 때
        │
        ▼
WorkerReport(processed, applied=exp+actor+pb, errors)
```

## 6. Components

### 신규
| 경로 | 책임 |
|---|---|
| `core/outcome.py` | `Observation` 모델 + `ProbeDecision` + `ObservationSource` Protocol + `InMemoryObservationSource` (테스트/MVP) + `ProbeEngine` |
| `agents/outcome_probe_agent.py` | `OutcomeProbeAgent(BaseWorkerAgent)` |
| `tests/__tests__/test_outcome_probe.py` | engine 매트릭스 / agent fan-out / 부분 적립 / 통합 |

### 수정
| 경로 | 변경 |
|---|---|
| `app/learning.py` | `run_cycle` 에 `outcome_probe: OutcomeProbeAgent \| None` 인자 추가. 사이클마다 실행 |
| `core/settings.py` | `outcome_probe_min_window_min: int = 5` |

## 7. Data Model

```python
class Observation(BaseModel):
    """시뮬 후속 관측 한 건(spec A-1).

    호출자가 alert 원본 메타(signals/severity/verdict/asset)를 채워야 exp/actors
    적립이 가능하다. 일부 누락 시 해당 gate 만 skip.
    """

    alert_id: str
    scenario_id: str
    actor_id: str | None = None
    playbook_id: str | None = None
    window_min: int = Field(ge=0)
    mission_effect_observed: bool = False
    no_effect_sustained: bool = False
    reoccurred: bool = False
    dwelling_min: int = 0
    ts: str
    # exp 적립용 알림 원본 메타.
    alert_signals: list[str] = Field(default_factory=list)
    alert_severity: Severity | None = None
    alert_verdict: Verdict | None = None
    alert_iocs: list[str] = Field(default_factory=list)
    alert_mitre: dict[str, object] = Field(default_factory=dict)
    asset_id: str = ""
    asset_tier: str = ""
    judge_features: JudgeFeatures | None = None


class ProbeDecision(BaseModel):
    env_verdict: EnvVerdict
    effect: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


@runtime_checkable
class ObservationSource(Protocol):
    async def apoll(self) -> list[Observation]: ...
```

## 8. ProbeEngine

```python
class ProbeEngine:
    def __init__(self, min_window_for_fp: int = 5) -> None:
        self._min_window_fp = min_window_for_fp

    def decide(self, obs: Observation) -> ProbeDecision:
        if obs.mission_effect_observed:
            if obs.reoccurred:
                return ProbeDecision(
                    env_verdict=EnvVerdict.CONFIRMED_TP, effect=0.0,
                    rationale="mission_effect + reoccurred → PB 완전 실패",
                )
            return ProbeDecision(
                env_verdict=EnvVerdict.CONFIRMED_TP, effect=0.3,
                rationale="mission_effect 단발 → PB 부분 효과",
            )
        if obs.no_effect_sustained and obs.window_min >= self._min_window_fp:
            return ProbeDecision(
                env_verdict=EnvVerdict.CONFIRMED_FP, effect=1.0,
                rationale=f"no_effect_sustained + window>={self._min_window_fp}분 → 차단 완료/오탐",
            )
        return ProbeDecision(
            env_verdict=EnvVerdict.INCONCLUSIVE, effect=0.5,
            rationale="관측 불충분 — 보류",
        )
```

## 9. OutcomeProbeAgent

```python
class OutcomeProbeAgent(BaseWorkerAgent):
    def __init__(
        self,
        settings: Settings,
        source: ObservationSource,
        engine: ProbeEngine,
        exp_gate: MemoryWriteGate | None = None,
        actor_gate: ActorWriteGate | None = None,
        pb_gate: ActorPlaybookOutcomeGate | None = None,
    ) -> None: ...

    async def run(self) -> WorkerReport:
        try:
            obs_list = await self._source.apoll()
        except SOCPlatformError as exc:
            return WorkerReport(cycle_at=_now_iso(), errors=[f"source: {exc}"])
        exp_n, actor_n, pb_n = 0, 0, 0
        errors: list[str] = []
        for obs in obs_list:
            decision = self._engine.decide(obs)
            # exp 적립
            if (self._exp_gate and obs.alert_verdict
                    and obs.alert_severity and obs.judge_features):
                try:
                    rec = ExperienceRecord(
                        scenario_id=obs.scenario_id,
                        signals=obs.alert_signals,
                        asset_id=obs.asset_id, asset_tier=obs.asset_tier,
                        verdict=obs.alert_verdict, severity=obs.alert_severity,
                        judge_features=obs.judge_features,
                        playbook_id=obs.playbook_id,
                        env_verdict=decision.env_verdict,
                        provenance=Provenance.ENV_VERIFIED,
                        ts=obs.ts,
                    )
                    d = await self._exp_gate.submit(rec)
                    if d.written: exp_n += 1
                except SOCPlatformError as exc:
                    errors.append(f"exp[{obs.alert_id}]: {exc}")
            # actors 적립 (TP-only — gate 가드)
            if self._actor_gate and obs.actor_id:
                fake_alert = _reconstruct_alert(obs)
                try:
                    d = await self._actor_gate.submit(
                        fake_alert, decision.env_verdict, Provenance.ENV_VERIFIED
                    )
                    if d.written: actor_n += 1
                except SOCPlatformError as exc:
                    errors.append(f"actor[{obs.alert_id}]: {exc}")
            # pb_scores 적립
            if self._pb_gate and obs.actor_id and obs.playbook_id:
                try:
                    d = await self._pb_gate.submit(PlaybookOutcome(
                        actor_id=obs.actor_id, playbook_id=obs.playbook_id,
                        effect=decision.effect, ts=obs.ts,
                        reason=decision.rationale,
                    ))
                    if d.written: pb_n += 1
                except SOCPlatformError as exc:
                    errors.append(f"pb[{obs.alert_id}]: {exc}")
        return WorkerReport(
            cycle_at=_now_iso(),
            auto_applied=exp_n + actor_n + pb_n,
            errors=errors,
        )
```

`_reconstruct_alert(obs)` 는 `ActorWriteGate.submit` 가 필요한 최소 필드만 채운 임시 Alert.

## 10. learning.py 통합

```python
async def run_cycle(
    threat_landscape: ThreatLandscapeAgent | None = None,
    outcome_probe: OutcomeProbeAgent | None = None,  # 신규
    last_landscape_refresh: list[float] | None = None,
    settings: Settings | None = None,
) -> None:
    _logger.info("learning 사이클 tick")
    # ... 기존 threat_landscape ...
    if outcome_probe is not None:
        try:
            report = await outcome_probe.run()
            _logger.info(
                "outcome_probe: applied=%d errors=%d",
                report.auto_applied, len(report.errors),
            )
        except Exception as exc:                          # noqa: BLE001
            _logger.warning("outcome_probe 실패(계속): %s", exc)
```

## 11. 포이즈닝 / 신뢰 경계

| 위협 | 방어 |
|---|---|
| 외부 Observation 인젝션 (가짜 `no_effect_sustained=True` → exp 억제 학습) | ObservationSource = 신뢰 SP (sim_bridge / 운영자 SP) 만 호출. 본 spec 은 *통로*만 — 신뢰 경계는 호출자 책임. 운영 가이드: source 구현체 화이트리스트 |
| 단일 관측으로 PB 효과 과대 | gate 가 누적 평균 (B-1) — 1건은 영향 작음 |
| INCONCLUSIVE 다발 → store 부하 | gate 가 INCONCLUSIVE 거부 (exp 기존 정책). 본 agent 도 sub-call 카운터로 추후 throttle 가능 |
| `mission_effect` 위장 | 호출자(sim_bridge) 신뢰 경계 + 별도 검증 hook 차후 |
| `provenance=ENV_VERIFIED` 위장 | 본 agent 하드코딩 — Observation 이 provenance 못 바꿈 |

## 12. Error Handling

| 시나리오 | 처리 |
|---|---|
| source.apoll() 실패 | SOCPlatformError → WorkerReport(errors=[...]) 즉시 반환 |
| 개별 gate submit 실패 | errors 누적, 다음 observation 계속 |
| alert 재구성 필수 필드 부족 | 해당 gate skip (count 증가 없음) |
| pb_gate REJECTED_NO_ACTOR | 무시 (다음 사이클에 actor 적립 후 처리) |
| ProbeEngine 결정 자체 실패 | 일어날 수 없음 (결정론 룰) — defensive try 만 |

## 13. Testing 매트릭스

| 테스트 | 케이스 |
|---|---|
| `test_probe_matrix_mission_reoccur` | TP + effect 0.0 |
| `test_probe_matrix_mission_single` | TP + effect 0.3 |
| `test_probe_matrix_no_effect_long_window` | FP + effect 1.0 |
| `test_probe_matrix_short_window_inconclusive` | INCONCLUSIVE + 0.5 |
| `test_agent_fans_out_to_three_gates` | 1 obs → exp/actors/pb 각각 호출 |
| `test_agent_skips_when_metadata_missing` | judge_features 없으면 exp skip |
| `test_agent_no_playbook_skips_pb` | playbook_id 없으면 pb skip |
| `test_agent_no_actor_skips_actor_and_pb` | actor_id 없으면 actor/pb skip |
| `test_agent_source_failure_returns_errors` | apoll() 예외 → WorkerReport.errors |
| `test_learning_outcome_probe_integration` | run_cycle 통합 — 미주입 거동 보존 |

## 14. Settings

```bash
OUTCOME_PROBE_MIN_WINDOW_MIN=5
```

## 15. YAGNI

- ❌ 실제 sim_bridge 어댑터 (후속 spec)
- ❌ LLM 자문
- ❌ 가중 점수 모델
- ❌ effect 자체 학습
- ❌ 큐/이벤트 인프라
- ❌ 다중 ObservationSource 합성

## 16. 마이그레이션

- `outcome_probe` 디폴트 None — learning.run_cycle 거동 보존
- 신규 모듈 추가만 — 기존 코드 무수정
- gate 정책 변경 X
- BaseWorkerAgent 기존 패턴 재사용

## 17. 후속 (별도 spec)

- `SimBridgeObservationSource` — sim_bridge 실 어댑터
- LLM-augmented decision (INCONCLUSIVE 시 LLM 자문)
- effect 가중 모델 (현재 4-case → 더 정밀)
- Observation 누적 큐 (분산 처리)

## 18. 참조

- `core/experience.py:MemoryWriteGate` — exp 적립 gate
- `core/actors.py:ActorWriteGate` — actors 적립 gate
- `core/playbook_outcome.py:ActorPlaybookOutcomeGate` — pb_scores 적립 gate
- `agents/base.py:BaseWorkerAgent` — 사이클 패턴
- `agents/threat_landscape_agent.py` — 유사 BaseWorkerAgent 사례
