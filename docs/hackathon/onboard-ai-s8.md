# S8 — 온보드 표적인식 AI 적대공격 대응 (전체 정리)

> 시나리오 `AI-ONBOARD-EVADE-008` · 자산 `PAYLOAD_EOIR`(EO/IR 페이로드 + 온보드 표적인식 AI, Tier T2)
> 공격받는 AI(S8) ↔ 방어하는 AI(S5) 를 양쪽 다 다뤄 대회 "Defense AI" 주제에 정면 대응.
> 실 시뮬(uav-sim-env, ArduPilot SITL) + RAGFlow + 로컬 LLM(qwen2.5:14b) 으로 폐루프 동작 검증 완료.

---

## 1. 한눈에

| 항목 | 내용 |
|---|---|
| **공격 대상** | 드론 **온보드 EO/IR 표적인식 AI**(자율 표적 식별/추적) |
| **공격 방식** | 적대적 패치 · 열(IR) 디코이 · 센서 dazzling → 인식 모델 오분류/미탐 유도 |
| **핵심 관측 신호** | ① EO(가시)/IR(열) **표적 클래스 불일치** ② **탐지 신뢰도 이상분포**(gap) |
| **MITRE** | ATLAS **AML.T0015**(Evade ML Model) · **AML.T0043**(Craft Adversarial Data) / EMB3D 센서변조 |
| **탐지** | `OnboardAIDetector` — 불일치/이상분포 신호 + 연속확정(confirm) |
| **판정** | 6-에이전트 SOC → 심각도 **m**, **true_positive** (RAG 근거 + LLM 분석) |
| **대응(폐루프)** | **자율교전 차단(LOITER hold) → 보수적 RTB** + HITL 승인 |
| **차별점** | 공격면이 RF 가 아닌 **인식 AI** 로 이동(재밍 내성 자율표적 시대) |

---

## 2. 위협 / 공격 방식

재밍 내성 자율표적(예: Skynode S, Shahed-136 MS — 가시+열 카메라+Jetson) 시대에는 통신을
끊어도 드론이 **스스로 표적을 인식**한다. 따라서 공격면이 **RF → 온보드 인식 AI** 로 이동.

- **적대적 패치(adversarial patch)**: 사람 눈엔 정상이나 AI가 오분류하는 특수 무늬/위장.
- **열(IR) 디코이**: 가짜 열 신호로 IR 시커를 기만(저비용 실사례 — 우크라 <$1,000 디코이).
- **센서 dazzling**: 레이저로 EO/IR 센서를 일시 무력화.
- **변형(GPS-denied)**: 재밍으로 비전/지형항법 전환한 기체에 지도/랜드마크 오염(S1과 직교).

**Kill chain**: `모델정찰 → 적대샘플 생성 → 패치/디코이 배치 → 인식 회피 → 임무 무력화`
**영향**: 표적 오분류/미탐 → 임무 실패, 최악의 경우 민간 오인(무장유도 연계 시 심각도 상향).

> 실측 근거/검증 플래그: 적대적 패치의 전장 실사용은 실험실·연구 단계(arXiv 2202.08892 등)만
> 확인, 실전 미확인. 레이저 dazzling 은 시커 파장 의존. (출처: `docs/hackathon/references.md`)

---

## 3. 탐지 방식 — `OnboardAIDetector`

시나리오의 탐지 로직("**센서간 표적 불일치 OR 탐지 신뢰도 이상분포** 시 적대 공격 의심 →
HITL 승급")을 런타임으로 구현. 두 신호를 결합하고, **단발 오탐을 막기 위해 연속 확정**한다.

| 신호 | 조건 | 의미 |
|---|---|---|
| **다중센서 불일치** | `EoClass ≠ IrClass` | EO=vehicle 인데 IR=bird → 한 센서가 속고 있음 |
| **신뢰도 이상분포** | `|EoConf − IrConf| ≥ 0.15` | 센서간 확신도 괴리(정상은 둘 다 고신뢰·근접) |

- **연속 확정(`confirm=2`)**: 신호가 2 레코드 연속 지속될 때만 발화(트랜지언트 오탐 방지).
- **중복 억제 + 자동 재무장**: 1회 발화 후 억제, 정상 복귀가 `rearm_after`(10) 이어지면 재무장(재촬영 대비).
- **임계 근거**: `MaxConfidenceGap_d = 0.15` (FULL-EXPORT 수치표). 본선 환경에서 센서모델 실측 보정.

```python
# sim_bridge/detector.py — 핵심 판정부
def _evaluate(self, record: PerceptionRecord) -> list[str]:
    signals = []
    if record.eo_class and record.ir_class and record.eo_class != record.ir_class:
        signals.append(f"EO/IR 표적 불일치(EO={record.eo_class} vs IR={record.ir_class})")
    if record.eo_conf is not None and record.ir_conf is not None:
        gap = abs(record.eo_conf - record.ir_conf)
        if gap >= self._conf_gap_threshold:           # 0.15
            signals.append(f"탐지 신뢰도 이상분포(gap={gap:.2f}≥{self._conf_gap_threshold})")
    return signals
```

---

## 4. 분석 결과 (실제 SOC 파이프라인 출력)

탐지된 경보는 **6-에이전트 SOC**(Triage→Investigation→Validation→Response→Report)를 통과한다.
아래는 실 데모 실행 결과(`s8-demo-recording/blue-soc-console.log`):

| 단계 | 결과 |
|---|---|
| **경보** | 온보드 표적인식 AI 적대공격 의심 |
| **탐지 신호** | EO/IR 표적 불일치(EO=vehicle vs IR=bird), 탐지 신뢰도 이상분포(gap=0.46≥0.15) |
| **심각도(정책엔진)** | **m** (baseline=m, asset[T2]=+0, phase[on-station]=+0, posture[normal]=+0) |
| **RAG 근거** | 5건 — `kb/incident_cases__incident_case_onboard_ai_adversarial_evade.md` 등 |
| **LLM 분석** | "온보드 표적인식 AI가 적대적 공격을 받은 것으로 보인다. EO와 IR 센서 사이의 탐지 결과 불일치와 탐지 신뢰도 이상분포(gap=0.46)가 확인되었다. **디코이를 이용한 회피공격(AML.T0015, AML.T0043)** 을 시사한다." |
| **판정/대응** | **true_positive → response** |

> 심각도는 **LLM이 아닌 정책 엔진**이 산정(자산·임무단계·태세 규칙) → RAG/프롬프트 포이즈닝으로
> 등급을 못 낮춤(S5 저항성과 동일 아키텍처). RAG 장애 시 빈 컨텍스트로 우아하게 강등(대응 지속).

---

## 5. 대응 — 폐루프 (Playbook `PB-ONBOARDAI-08`)

**대응 액션:**
1. 다중센서 융합 교차검증 — 불일치 표적 **보류**
2. 탐지 신뢰도 이상 시 **자율교전 차단 + HITL 표적확인**
3. 적대적 견고화(robust) 모델 / 입력 정규화 런타임 방어
4. 인식 신뢰 불가 시 **보수적 RTB**

**온보드/엣지 방어 레이어 (통신 두절에도 자율):**
- **메타 AI 가 주 비전모델 출력·판단 패턴 상시 감시**(AI 가 AI 를 감시)
- 적대 의심 시 **경량 백업 비전모델 자동 전환 + 주 모델 격리**

**폐루프 작동(실측):** `자율교전 차단(LOITER hold) → 보수적 RTB(RETURN_TO_LAUNCH)`
- HITL: severity=m → 자율교전 차단 후 운용자 표적확인(`--auto` 면 자동)
- 실 드론 모드 전환: **GUIDED → LOITER(22.2s) → RTL(22.7s)** (`drone-mavlink-timeline.log`)

```python
# sim_bridge/actuator.py — 폐루프(자율교전 차단 → 복귀)
def hold_then_rtb(actuator: OnboardActuator, uav_id: str) -> list[str]:
    return [actuator.send_loiter(uav_id),   # LOITER = 자율교전 차단(표적 접근 정지)
            actuator.send_rtb(uav_id)]      # RETURN_TO_LAUNCH = 보수적 복귀
```

---

## 6. 코드 구조

### 데이터 흐름
```
[RED] sim_inject_onboard_evade.py            (적대 EO/IR 인식 주입)
        │  append → /tmp/pollack_perception.ndjson
        ▼
[BLUE] sim_live_bridge_onboard.py  (tail -F 스트림)
        │  PerceptionRecord
        ▼
   OnboardAIDetector.observe()  ──(불일치/이상분포 + 연속확정)──▶ Alert(AI-ONBOARD-EVADE-008)
        ▼
   SimBridge.run_alert() → build_soc_graph (6-에이전트: RAG+LLM, 정책 심각도)
        ▼
   BridgeEvent(보고서·RAG근거·LLM요약) → 대시보드 출력
        ▼
   hold_then_rtb(MavlinkActuator)  → MAVLink LOITER → RTL  → 드론 복귀(QGC)
```

### 파일별 역할
| 파일 | 역할 |
|---|---|
| `sim_bridge/models.py` | `PerceptionRecord` — EO/IR 인식 NDJSON(EoClass/IrClass/EoConfidence/IrConfidence) |
| `sim_bridge/perception_synth.py` | 합성 인식 스트림(정상/적대) — 실 인식모델 없이 검증 |
| `sim_bridge/detector.py` | `OnboardAIDetector` — 불일치+이상분포 결합, 연속확정·재무장 |
| `sim_bridge/bridge.py` | `SimBridge.run_alert` — 탐지 Alert → 6-에이전트 SOC 실행 |
| `sim_bridge/actuator.py` | `OnboardActuator`/`hold_then_rtb` — LOITER(교전차단)→RTB 폐루프 |
| `scripts/sim_inject_onboard_evade.py` | RED — 적대 인식 스트림 주입(`--clear` 재무장) |
| `scripts/sim_live_bridge_onboard.py` | BLUE — 스트림 tail→탐지→SOC→폐루프(`--auto/--no-rtb/--no-llm`) |
| `projects/dah2026/scenarios/S8-onboard-ai-evade.yaml` | 시나리오 정의(공격·탐지·플레이북·레드팀) |

### 핵심 데이터 모델
```python
# sim_bridge/models.py
class PerceptionRecord(BaseModel):           # 온보드 EO/IR 추론 한 줄
    eo_class: str | None  = Field(alias="EoClass")       # EO(가시) 표적 클래스
    ir_class: str | None  = Field(alias="IrClass")       # IR(열) 표적 클래스
    eo_conf:  float | None = Field(alias="EoConfidence") # EO 탐지 신뢰도
    ir_conf:  float | None = Field(alias="IrConfidence") # IR 탐지 신뢰도
```

### 합성 인식 스트림 (정상 vs 적대)
```python
# 정상: EO/IR 동일 클래스 + 고신뢰 근접
{"EoClass":"vehicle","IrClass":"vehicle","EoConfidence":0.93,"IrConfidence":0.90}
# 적대: 클래스 불일치 + 신뢰도 gap(0.46)
{"EoClass":"vehicle","IrClass":"bird",   "EoConfidence":0.88,"IrConfidence":0.42}
```

> 메모: SITL 엔 실제 인식 모델이 없어 **합성 perception 스트림**으로 대체. 키가 perception-tap
> NDJSON 스키마와 동일해, 실 온보드 추론 로그가 생기면 그대로 교체 가능(브리지/탐지기 무변경).

---

## 7. 데모 결과 (실행 로그 — `s8-demo-recording/`)
| 파일 | 내용 |
|---|---|
| `red-inject.log` | 정상→적대 인식 주입 |
| `blue-soc-console.log` | SOC 탐지·대응 대시보드(신호·심각도·RAG·LLM·폐루프) |
| `drone-mavlink-timeline.log` | 드론 모드 GUIDED→LOITER→RTL |
| `DEMO-REPORT.md` | 3로그 통합 + 핵심 포인트(팀 공유용) |

## 8. 재현
```bash
cd ~/pollack-ai && source .venv/bin/activate
python scripts/sim_takeoff.py                       # (사전) 드론 이륙
python scripts/sim_live_bridge_onboard.py --auto    # BLUE(SOC)
python scripts/sim_inject_onboard_evade.py          # RED(공격, 다른 터미널)
#   재촬영: python scripts/sim_inject_onboard_evade.py --clear  (탐지기 자동 재무장)
```
상세 절차: `docs/demo-runbook-s8.md`.
