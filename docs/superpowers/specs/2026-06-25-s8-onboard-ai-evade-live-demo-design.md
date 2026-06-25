# S8 온보드 인식 AI 적대공격 — 라이브 폐루프 데모 설계

> 작성: 2026-06-25 · 시나리오: `projects/dah2026/scenarios/S8-onboard-ai-evade.yaml`
> 목표: S1(GNSS 스푸핑)처럼 **레드 주입 → BLUE SOC 탐지 → 드론 가시 반응**의
> 폐루프를 S8(온보드 EO/IR 표적인식 AI 적대공격)에 대해 구성하고 녹화 가능하게 한다.

---

## 1. 배경 / 문제

S1 폐루프는 SITL 드론을 MAVLink `PARAM_SET`으로 실제로 흔들어(`sim_inject_gps_spoof.py`)
EKF 잔차·위성 급감을 telemetry-tap NDJSON으로 흘리고, `GpsSpoofDetector`가 탐지하면
6-에이전트 SOC가 RTB를 작동시킨다. QGC에서 드론이 흔들리고 복귀하는 "영상"이 나온다.

S8은 **온보드 EO/IR 카메라의 표적인식 AI**를 적대적 패치·열 디코이·dazzling으로
속이는 공격이다. 그러나:

- 시뮬(uav-sim-env)에는 **속일 인식 AI 모델이 없다** — 비행제어(ArduPilot)만 시뮬.
- 탐지 신호가 비행 텔레메트리가 아니라 `perception_inference_log`·`multisensor_fusion_log`다.
- 따라서 S1 인젝터처럼 기존 시뮬을 건드리는 방식이 불가능하다.

현재 S8은 시나리오 정의 + KB 인시던트 케이스
(`projects/uav_soc_rag_poc/.../incident_case_onboard_ai_adversarial_evade.md`) +
Sentinel 룰 이름(`onboard_ai_adversarial_evade.yml`)까지만 존재하며,
**SOC 6-에이전트 콘솔 데모(`projects/dah2026/run_demo.py`)에서는 이미 판정까지 돈다**
(검증: severity=m, verdict=true_positive→response).

## 2. 핵심 결정 (브레인스토밍 합의)

| 결정 | 선택 | 근거 |
|---|---|---|
| 녹화 payoff | **하이브리드** — 인식 대시보드 + 드론 반응 | S1 수준 그림 + S8 고유 스토리 양립 |
| 탐지 신호 범위 | **핵심 2개** — 센서 불일치 + 신뢰도 이상분포 | yaml `expected_detection.logic` 그대로, 과임 방지 |
| 드론 반응 | **Hold→RTB** — 자율교전 차단 후 보수적 복귀 | playbook PB-ONBOARDAI-08의 "자율교전 차단→HITL→보수적 RTB" 재현 |

## 3. 데이터 흐름

```
[RED] scripts/sim_inject_onboard_evade.py
   ├─ (a) SITL goto: 드론을 '표적 웨이포인트'로 전진 (자율교전 접근 연출)
   └─ (b) 적대 인식 스트림 방출: EO=vehicle / IR=bird 불일치 + 신뢰도 gap≥0.15
                              │ (perception NDJSON 스트림)
                              ▼
[BLUE] scripts/sim_live_bridge.py --scenario onboard
   → OnboardAIDetector.observe() → S8 Alert
   → SimBridge.process() → 6-에이전트 SOC + RAG 근거 + LLM 분석
   → 인식 대시보드 출력(EO↔IR 불일치, 신뢰도 이상분포, RAG N건, LLM 요약)
   → [HITL] 자율교전 차단 승인? [y/N]
   → actuator: LOITER hold(전진 멈춤) → RTB(복귀)   ← QGC 영상
```

정상 구간에서는 EO/IR이 일치하고 신뢰도가 단봉(고신뢰)이라 탐지기가 침묵하고,
RED 주입 시점부터 불일치+이상분포가 누적되어 발화한다.

## 4. 컴포넌트 (각 단일 책임)

| 파일 | 신규/수정 | 책임 |
|---|---|---|
| `sim_bridge/models.py` | +`PerceptionRecord` | EO/IR 추론·융합 로그 1건: `uav_id, ts, msg_type, target_id, eo_class, ir_class, eo_conf, ir_conf` |
| `sim_bridge/perception_synth.py` | **신규** | `benign_perception()`(EO/IR 일치·단봉 고신뢰) / `adversarial_perception()`(클래스 불일치 + 신뢰도 gap) + `synth_perception_records()` / `synth_perception_stream()`. **RED 공격 콘텐츠** |
| `sim_bridge/detector.py` | +`OnboardAIDetector` | 센서 불일치 OR 신뢰도 이상분포(gap≥0.15) 결합 판정 → S8 Alert. 기존 `GpsSpoofDetector`의 **auto-rearm·중복억제(`_fired`)·상관 패턴 그대로** |
| `sim_bridge/bridge.py` | 일반화 | `Detector` Protocol(`observe(record) -> Alert \| None`) 도입, `SimBridge`가 detector 주입받게(기본=`GpsSpoofDetector`, 하위호환 유지) |
| `sim_bridge/actuator.py` | +`send_loiter` | LOITER hold(자율교전 차단) 추가, 기존 `send_rtb` 유지. `hold_then_rtb` 연출용 헬퍼 |
| `scripts/sim_inject_onboard_evade.py` | **신규** | RED: 표적 goto + 적대 인식 스트림 방출. `--clear`로 정상 복원 |
| `scripts/sim_live_bridge.py` | +`--scenario onboard` | BLUE: 인식 스트림 소비 → 대시보드 → HITL → hold→RTB. 기존 `--auto/--no-rtb/--no-llm` 플래그 호환 |
| `tests/__tests__/test_sim_bridge.py` | +S8 케이스 | benign 무발화 / 적대 발화 / 불일치만 / 신뢰도만 / 재무장. LLM·SITL은 mock |

## 5. 탐지 로직 (yaml `expected_detection.logic` 준수)

- **신호 A — 센서 불일치:** 동일 `target_id`에서 `eo_class != ir_class` (예: vehicle vs bird)
- **신호 B — 신뢰도 이상분포:** `|eo_conf − ir_conf| ≥ 0.15` (FULL-EXPORT의 `MaxConfidenceGap_d=0.15`)
  또는 신뢰도 이중봉(bimodal)
- **발화:** S1과 동일하게 단발 오탐 방지를 위해 신호의 결합/지속을 요구하고,
  `_fired`로 동일 사건 중복발화 억제, 정상 복귀 시 auto-rearm(재촬영 대비)
- **Alert 필드:** `scenario_id=AI-ONBOARD-EVADE-008`, `asset_id=PAYLOAD_EOIR`,
  `asset_tier=T2-Important`, `severity_baseline=Severity.MEDIUM`,
  `mitre={"atlas": ["AML.T0015-EvadeMLModel", "AML.T0043-CraftAdversarialData"]}`,
  `expected_detection={"sigma_rule": "onboard_ai_adversarial_evade.yml"}`,
  `defense_playbook=PB-ONBOARDAI-08`(actions/onboard_defense/failover/hitl),
  `ground_truth=Verdict.TRUE_POSITIVE`

## 6. 에러 처리 & 안전

- SITL 미기동/goto 실패 → `ActuatorError` 발생, 데모는 탐지·대시보드까지는 진행하고
  드론 반응만 생략(`--no-rtb`와 동일 거동).
- LLM 미가용 → 기존 `--no-llm` 결정론 폴백 재사용.
- perception 스트림 파싱 실패 → 구체 예외(`SOCPlatformError` 하위) + 해당 레코드 스킵.
  bare `except` 금지, 미검증 외부 입력 검증 규칙 준수.

## 7. 기존 미커밋 작업 보존

작업 트리의 `agents/`·`core/`·`sim_bridge/detector.py`(auto-rearm)·
`tests/__tests__/test_sim_bridge.py` 변경은 **건드리지 않고 그 위에 추가만 한다**.
`detector.py`는 기존 `GpsSpoofDetector` 아래에 `OnboardAIDetector`를 덧붙이는 방식.

## 8. 테스트 / 검증

- 오프라인(mock) S8 탐지 단위테스트가 `pytest` 통과.
- `black . && ruff check . && mypy . && pytest` 전부 통과.
- 라이브 SITL 연동(드론 hold→RTB)은 `opus-codex` 구현 후 Opus가 수동 1회 실행 검증.

## 9. 비목표 (YAGNI)

- 실제 EO/IR 이미지/추론 모델 통합 — 합성 스트림으로 충분.
- yaml의 5개 신호 전체 구현 — 핵심 2개만.
- 지형항법(지도 타일 해시) 변형 — 이번 범위 제외(후속).
- 새 Sentinel/Sigma 룰 파일 작성 — 런타임 탐지기 근사판만.
