# fried-pollack-ai 교리 반영 갭 분석 + 적용 브리프

> 대상 레포: `github.com/s1ns3nz0/fried-pollack-ai` (커밋 기준 `docs/DOCTRINE.md`/`ARCHITECTURE.md`
> 확인, 442 tests green, D8 불변식: red↔blue 코드 결합 없음, 단방향 `UAV*_CL` 브릿지만).
> 이 문서는 **처음부터 새로 짜라는 게 아니라, 이미 있는 걸 지키면서 5개 개념 중 실제로
> 비어있는 지점만 정확히 채우라는 브리프**다. 레포가 이미 JP 3-60/3-85/3-12/3-0/3-13.4/DoDD
> 3000.09를 상당히 깊게 반영하고 있어서, 대부분은 "이미 있음 — 건드리지 말 것"이다.

---

## 결론 먼저 (5개 개념 현황)

| 개념 | 현재 상태 | 필요한 작업 |
|---|---|---|
| Information(합동기능 7번째) | ✅ **이미 있음**(`docs/DOCTRINE.md` §4-3, MILDEC·§C에 매핑) | 없음 — 손대지 말 것 |
| OODA/Decision Advantage | ✅ **이미 있음**(`tempo/`, `assessment/replan`에 명시) | 비교 지표 1개만 추가 |
| Kill Web(Mosaic) | 🟡 **부분적**(`killchain/`=선형 7단계, `maneuver/`=차단시 재경로는 있음) | 명명·구조 승격 필요 |
| 임무형 지휘(Mission Command) | 🟡 **암묵적**(`roe/`+`command/`=승인체인만, "의도 기반 재량"은 없음) | 신규 구조체 1개 추가 |
| JADC2 노드 개념 | ⚠️ **D8과 충돌 위험** — 문자 그대로 적용 금지 | red 내부에만 국한해서 적용 |

---

## 1. Information (7번째 합동기능) — 손대지 말 것, 대신 1개만 보강

`docs/DOCTRINE.md` §4-3에 이미 "정보활동 Information → §H MILDEC·§C"로 매핑돼 있음. 이건
완성된 걸로 보고 재작업하지 말 것.

**보강 제안(선택)**: "정보 산출물 자체의 무결성"을 공격 목표로 삼는 KPI 1개 추가.
- 은밀 관통(§11 결론에 이미 "GNSS·JAM은 D3FEND 미커버=은밀 성공" 확인됨)이 성공했을 때,
  **blue의 `SOCReport`/OSCAL 산출물이 "이상 없음"으로 기록되는지**를 `assessment/bda`나
  `kpi/`에서 관측(D8 준수 — blue 코드 임포트 없이 blue가 발행한 산출물 파일만 읽기).
  이미 §6 핵심발견에 "GNSS 재밍 미매핑 사각지대" 확인이 있으니, 여기에 "그래서 blue 리포트가
  거짓 청정기록을 남긴다"는 한 줄만 추가하면 Information 기능 공격이 완성됨. 새 모듈 불필요,
  기존 관측에 한 문장 결론만 추가.

---

## 2. OODA / Decision Advantage — 비교 지표 1개만 추가

`tempo/`와 `assessment/replan`(태그: "Persistent Engagement·OODA")이 이미 OODA를 다룸.
추가로 필요한 건 **red의 OODA 사이클 vs blue의 OODA 사이클을 같은 숫자로 비교**하는
것뿐임.

**제안**: `benchmarks/decision_advantage_eval.py` 신설 (또는 `kpi/`에 함수 추가).
- 입력: (1) 자기 `tempo/`·`kpi/` 산출값(레드팀 자체 사이클타임), (2) pollack-ai가 발행한
  KPI 아티팩트(`kpi-evidence.md` 또는 `run_kpi.py` 출력 JSON) — **파일만 읽기, import 없음
  (D8 준수)**.
- 산출: "red 사이클타임 / blue MTTT+MTTC" 비율 하나. 이게 1보다 작으면 "red가 blue의
  결정루프보다 빠르게 돈다"는 JADC2식 decision advantage 주장의 정량 근거가 됨.
- 비용: 낮음(기존 두 숫자를 나누기만 하면 됨), 보고서 임팩트: 큼.

---

## 3. Kill Web (Mosaic Warfare) — 명명·구조 승격

지금 `killchain/`은 Lockheed 7단계 **선형** 파이프라인이고, `maneuver/`가 "차단시 재경로"를
이미 수행 중(§0.1 공격면 표에 이미 존재). 근데 이 재경로가 **한 단계 안에서의 국소 우회**에
머물러 있고, **캠페인 전체가 그래프처럼 재구성**되는 수준은 아님.

**제안**:
1. `campaigns/`의 캠페인 체인(C8~C18)이 `assessment/bda` 피드백을 받아서, 막힌 전달경로
   (예: MAVLink UDP 차단)를 **다른 평면**(SATCOM `emso`/`transport`)으로 **단계를 건너뛰고
   대체**할 수 있는지 확인 — 지금은 같은 단계 안에서만 우회하는지, 아니면 단계 자체를
   스킵/치환하는지가 핵심 질문.
2. 확인 결과에 따라 `docs/DOCTRINE.md` §3(통합 킬체인 제어 흐름)의 선형 다이어그램 옆에,
   "각 단계가 여러 평면(MAVLink/SATCOM/RF/온보드AI) 중 가용한 것으로 동적 치환 가능"이라는
   **kill web** 절 하나만 추가. 코드 재작성보다 **이미 있는 재경로 능력을 캠페인 레벨로
   한 단계 승격 + 문서에 "kill chain"이 아니라 "kill web"이라고 명명**하는 게 핵심.
3. 이게 보고서에서 "우리 레드팀은 고정된 킬체인이 아니라 Mosaic Warfare식 kill web으로
   동작한다"는 차별화 문장이 됨.

---

## 4. 임무형 지휘 (Mission Command) — 신규 구조체 1개 추가

지금 `roe/`+`command/`는 "권한은 모델 밖, 상급 승인 필수"(fail-closed 승인체인)만 구현함 —
이건 사실 임무형 지휘의 반대 축인 **통제형 지휘(Befehlstaktik/positive control)**에 가까움.
무장/물리비가역 액션엔 이게 맞음(그대로 유지). 근데 **저위험·계획 단계**에서는 "의도만 주고
재량은 맡기는" 임무형 지휘 축이 지금 없음.

**제안**: `MissionIntent` 경량 구조체 신설 (예: `redteam_core/command/intent.py` 또는
`targeting/`에 추가).
```
MissionIntent:
  purpose: str          # 왜 (예: "blue의 severity 판정을 h→m으로 억제")
  end_state: str        # 도달상태 (예: "자동대응 미발동 상태에서 목표행동 완료")
  key_tasks: list[str]  # 핵심과업(우선순위), 절차가 아니라 결과 중심
  constraints: dict      # 제약(스코프 CIDR, 금지 액션, 스텔스 예산 등 — 기존 opsec.py/egress.py 재사용)
```
- `planner`/`assessment/replan`이 **저위험 액션 선택 시**(read/write_lowrisk 등급만) 이
  `MissionIntent`의 end_state를 기준으로 스스로 경로를 고르게 하고, `maneuver/`의 "차단시
  재경로"를 **"disciplined initiative"**로 문서에 명시적으로 라벨링.
- 물리 비가역·고위험 액션은 지금 그대로 `roe/`+`command/`(통제형)로 유지 — **둘을 분리해서
  공존시키는 게 핵심**(저위험=임무형 재량, 고위험=통제형 승인). 이게 실제 미군 교리에서도
  임무형 지휘와 positive control이 계층별로 공존하는 방식과 정확히 일치함.
- 비용: 구조체 하나 + 기존 `planner`/`replan`에 필드 하나 추가하는 수준. 큰 리팩터 불필요.

---

## 5. JADC2 노드 개념 — 문자 그대로 적용 금지, red 내부에만 국한

**주의**: JADC2는 "모든 센서를 하나의 네트워크로 융합"하는 개념인데, 이걸 곧이곧대로
적용하면 red가 blue 데이터를 직접 융합하려는 시도로 이어질 위험이 있고, 이는 **D8 불변식
위반**(red↔blue 코드 결합 없음)임. **D8을 절대 깨지 말 것.**

**올바른 적용 범위 — red 내부에서만**:
- `intel/`(attack/atlas/kev 피드) + `assessment/bda`(blue의 관측 가능한 반응, 단방향 브릿지
  통해서만) + `targeting/`(CARVER/HPTL)가 지금 각자 따로 조회되는지, 아니면 하나의 공유
  상태 객체로 융합되는지 확인.
- 셋을 하나의 내부 "공통작전상황도(red 자체 COP)"로 묶어서 재계획(replan) 속도를 높이는 것 —
  이게 D8을 지키면서도 JADC2의 "융합→결정우위" 철학을 구현하는 유일하게 안전한 방식.
- **하지 말 것**: blue의 `pollack-ai` 코드를 import하거나, blue의 내부 상태(SOCState 등)를
  직접 참조하는 어떤 형태의 "노드 연동"도 금지. 오직 blue가 **발행한 로그/산출물 파일**
  (`UAV*_CL`, 공개된 KPI 아티팩트)만 읽기.

---

## 요약 (AI 파싱용)

```
DO_NOT_TOUCH: information_joint_function(already in DOCTRINE.md §4-3), ooda_tempo(already in tempo/, assessment/replan)
ADD_SMALL: decision_advantage_ratio(benchmarks/decision_advantage_eval.py, file-read only vs pollack-ai KPI artifact)
ADD_SMALL: information_integrity_finding(one sentence in assessment/bda: stealthy success -> blue report false-clean)
UPGRADE_NAMING: killchain -> kill_web(campaigns/ + maneuver/ existing reroute, elevate to campaign-level plane substitution, rename in DOCTRINE.md §3)
ADD_STRUCT: MissionIntent(purpose/end_state/key_tasks/constraints) for LOW-RISK planning only; keep roe/+command/ untouched for high-risk/physical-irreversible
HARD_CONSTRAINT: JADC2 fusion internal-to-red ONLY (intel/+assessment.bda+targeting/), NEVER import or couple with pollack-ai code (D8 invariant, non-negotiable)
```
