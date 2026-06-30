# 온도브 AI (1)

- **Status**: To Do
- **URL**: https://app.notion.com/p/38df5e835bb48008a69fe35013aead5e

---

## 온보드 AI

### 온보드 AI란?
드론 기체에 탑재되어 통신(C2/GPS)이 끊겨도 스스로 인식·판단하는 AI다 — EO(가시)/IR(열) 표적인식, 센서퓨전, 자율 표적 식별·추적. 재밍 내성 자율표적(예: Skynode S, Shahed-136 MS — 가시+열 카메라+Jetson) 시대엔 통신을 끊어도 드론이 스스로 표적을 인식하므로, 공격면이 'RF → 온보드 인식 AI'로 이동한다.

**우리 프로젝트 위치:** 시나리오 S8(AI-ONBOARD-EVADE-008, 자산 PAYLOAD_EOIR·Tier T2). '공격받는 AI(S8) ↔ 방어하는 AI(S5)'를 양쪽 다 다뤄 대회 'Defense AI' 주제에 정면 대응.

### 막아야 할 공격 방식
- 적대적 패치(adversarial patch): 사람 눈엔 정상이나 AI가 오분류하는 위장 무늬
- 열(IR) 디코이: 가짜 열 신호로 IR 시커 기만 (우크라 <$1,000 저비용 사례)
- 센서 dazzling: 레이저로 EO/IR 센서 일시 무력화
- GPS-denied 변형: 비전/지형항법 전환 기체에 지도·랜드마크 오염(S1과 직교)

Kill chain: 모델정찰 → 적대샘플 생성 → 패치/디코이 배치 → 인식 회피 → 임무 무력화.

### ① 활용한 코드 / 구현 (sim_bridge)
S8 탐지·대응을 repo(pollack-ai)의 sim_bridge로 직접 구현. 핵심 파일:

| 파일 | 역할 |
|---|---|
| sim_bridge/models.py | PerceptionRecord — EO/IR 인식 NDJSON(EoClass/IrClass/EoConfidence/IrConfidence) |
| sim_bridge/perception_synth.py | 합성 인식 스트림(정상/적대) — 실 인식모델 없이 검증 |
| sim_bridge/detector.py | OnboardAIDetector — 불일치+신뢰도 이상분포 결합, 연속확정·재무장 |
| sim_bridge/bridge.py | SimBridge.run_alert — 탐지 Alert → 6-에이전트 SOC 실행 |
| sim_bridge/actuator.py | hold_then_rtb — LOITER(자율교전 차단)→RTB 폐루프 |
| scripts/sim_inject_onboard_evade.py | RED — 적대 EO/IR 인식 주입 |
| scripts/sim_live_bridge_onboard.py | BLUE — 스트림 tail→탐지→SOC→폐루프 |

- **탐지:** EO/IR 표적 클래스 불일치 OR 탐지 신뢰도 이상분포(|EoConf−IrConf|≥0.15) + 연속확정(confirm=2, 트랜지언트 오탐 방지) + 자동 재무장
- **대응(폐루프):** 자율교전 차단(LOITER) → 보수적 RTB(RETURN_TO_LAUNCH) + HITL 표적확인. 실측 모드전환 GUIDED→LOITER(22.2s)→RTL(22.7s)
- **심각도 = 정책 엔진(LLM 아님):** m 등급, RAG/프롬프트 포이즈닝으로 못 낮춤. RAG 장애 시 빈 컨텍스트로 우아하게 강등

### ② 활용한 데이터

| 데이터 | 분류 | 용도 |
|---|---|---|
| RAG DB (126문서, bge-m3 임베딩) | 벡터화 지식 | Investigation 검색 근거. Recall@5/MRR=1.0 |
| IEEE UAV Attack (PX4 로그, 684M) | 원천 | GPS 시그니처 추출·탐지 임계값 도출(Benign/Jamming/Spoofing) |
| UAV NetworkCommunication (PCAP/PKL, 655M) | 원천 | 네트워크 공격 분석 |
| Aissou GPS Spoofing (XLSX, 248M) | 원천 | GPS 3D/2D 스푸핑 채널 |
| misc (cyberphysical·mitre_ics·iec62443) | 원천 | 소규모 보조 |

데이터 흐름: 원천 raw(PCAP/CSV/XLSX) → 분석·특징추출 → 요약·시그니처·사건카드(.md) → 임베딩 → RAG DB.

### ③ 환경 / 스택
- 시뮬레이터: ArduPilot SITL (uav-sim-env), MAVLink actuator → QGC
- RAG/LLM: RAGFlow + 로컬 Ollama(챗 qwen2.5:14b, 임베딩 bge-m3) — Azure 비용 없음·데이터 로컬
- 판정/대응: 6-에이전트 SOC(soc_core: agents·core·tools) — 정책엔진 심각도 + RAG+LLM 분석

### 탐지·대응 요약 (실 데모 출력)

| 단계 | 결과 |
|---|---|
| 탐지 신호 | EO/IR 표적 불일치(EO=vehicle vs IR=bird) + 신뢰도 이상분포(gap=0.46≥0.15) |
| 심각도(정책엔진) | m |
| RAG 근거 | 5건 (kb/incident_case_onboard_ai_adversarial_evade.md 등) |
| LLM 분석 | '디코이 회피공격(AML.T0015·T0043)' 시사 |
| 판정/대응 | true_positive → response (LOITER→RTB 폐루프) |

### MITRE 매핑
ATLAS AML.T0015 · AML.T0043 / EMB3D 센서변조.

### 재현
```bash
cd ~/pollack-ai && source .venv/bin/activate
python scripts/sim_takeoff.py
python scripts/sim_live_bridge_onboard.py --auto
python scripts/sim_inject_onboard_evade.py
```

(첨부 파일: onboard-ai-s8.md)
