# 회사 PC 보완 계획 — 황준식 lane (검토 결과 기반)

> 작성: 2026-06-18 · 작성 위치: 집 노트북 → **회사 PC로 이관용**
> 기준: 팀 레포 `pollack-ai` (main, RAG 브랜치 머지 완료) + `RAG_DEFENSE_STATUS.md` + 브레인스토밍 설계 대조
> 실제 에이전트 코드·런타임(RAGFlow/LLM)은 회사 PC에 있으므로, 검증이 필요한 보완은 거기서 진행.

---

## 0. 한 줄 결론

에이전트 코어(6-에이전트 + 정책기반 심각도 + 출처검증 + 시나리오/레드팀 매핑)는 **설계 뼈대를 충실히 구현**했다.
남은 보완은 ① Investigation 외부연동 ② 실제 HITL 인터럽트 ③ LLM 실연동 ④ (문서) GraphRAG 표기 정리 + 벤치마크.

---

## 1. 설계 ↔ 빌드 대조 (검토 결과)

| 브레인스토밍 설계 | 빌드 상태 | 판정 |
|---|---|---|
| 6-에이전트 (Triage→Investigation→Validation→{RuleUpdate\|Response}→Report) | `agents/` 실 LangGraph 구현 | ✅ 일치 |
| 심각도 = 정책 엔진(LLM 불신, 인젝션 내성) | `core/severity.py` + dynamics + posture lock | ✅ 일치 |
| Investigation = RAG 유사사례 + 출처 검증(kb/만 신뢰) | 구현됨(미신뢰 컨텍스트 격리) | ✅ 일치 |
| Investigation = + 외부 TI + 샌드박스 + URL평판 + MCP | 없음 (RAG 검색만) | ✗ 미구현 |
| GraphRAG(연관 엔티티/그래프 추론) | RAGFlow(평면 검색)로 대체 | △ 차이(문서 표기) |
| Validation 오탐/정탐 + 라우팅 | 구현됨 | ✅ |
| Validation + 오탐 이력 DB 관리 | 없음 | ✗ 미구현 |
| Response = 플레이북 + HITL(방산 필수) | 등급별 `hitl` 필드 기록은 됨 / 실제 승인 대기 인터럽트 없음 | △ 부분 |
| Rule Update = Sigma 수정 + GitHub PR | PR stub | ✅(stub) |
| Report = OSCAL 아카이빙 | `core/oscal.py` stub | ✅(stub) |
| 시나리오 + MITRE(ICS/ATLAS/EMB3D) | S1~S11 | ✅ |
| METT+TC / cATO MbCRA | scenario `mission_context.METT_TC` + severity mission_phase 가중 | ✅ 부분 반영 |
| LLM = Azure OpenAI(GPT-4o-mini 등) | **mock** (RAG만 실연동) | ✗ 아직 |
| Detection-as-Code 자동화(위협모델→PyRIT→Sigma→Sentinel) | redteam 매핑만 | ✗ (김수지·김동언 lane) |
| PyRIT/Garak | objective/probe 정의·매핑 / 실행 별도 | △ |

---

## 2. GraphRAG vs RAGFlow → **RAGFlow 유지 (변경 불필요)**

- 둘은 층위가 다름: GraphRAG=RAG **기법**(지식그래프·다중 hop, 적재비용 높음, global 질의용) / RAGFlow=RAG **엔진**(딥 문서파싱·하이브리드 검색·리랭크, local 질의 강점).
- SOC Triage/Investigation = "이 경보 관련 사례·TTP·플레이북 검색" = **local 검색** → RAGFlow가 적합. GraphRAG가 빛나는 global sensemaking 영역이 아님.
- GraphRAG의 핵심 가치였던 **자산 연관성(상위자산 침해→의존 기체)은 이미 severity 정책엔진의 `lateral_correlation` dynamics로 구현**됨. 즉 능력 손실 아님, 레이어만 다름.
- RAGFlow도 옵션으로 knowledge graph 지원 → 필요 시 나중에 켜면 됨.
- **조치(문서만)**: 발표/보고서의 "GraphRAG" 표기를 **"RAGFlow 기반, 자산 연관성은 정책엔진 lateral correlation으로 처리"** 로 정리 → 심사 질문 차단.

---

## 3. 회사 PC에서 보완할 것 (우선순위)

> 코드 골격은 집에서도 작성·push 가능하지만, **실연동·검증은 RAGFlow/LLM이 떠 있는 회사 PC에서.**

### B-2. 실제 HITL 인터럽트 (방산 핵심, 데모 임팩트 큼)
- 현재: `response_agent.py`가 등급별 `hitl`/`auto_response` **필드만 기록**. 실제 승인 대기 없음.
- 보완: LangGraph `interrupt`로 **Response 실행 전 사람 승인 대기** 노드 추가. 등급 h·임무중(METT+TC)일 때 자동 발동.
- 파일: `agents/response_agent.py`, `agents/graph.py`
- 검증: 정탐 시나리오 → 승인 대기 → 승인 후 플레이북 실행 흐름 데모.

### B-3. Investigation 외부연동 최소 1개
- 현재: RAG 검색만. 설계의 TI/샌드박스/URL/MCP 없음.
- 보완: 최소 **외부 TI 1종**(VirusTotal 등) 또는 샌드박스 mock→실 1개. 가능하면 **Sentinel MCP** 연동.
- 파일: `agents/investigation_agent.py` (+ `tools/` 에 TI tool 추가, `ContextRetriever`처럼 Protocol로)
- 검증: alert IOC → TI 조회 결과가 investigation 결과에 반영.

### B-4. LLM 실연동 (요약/Judge)
- 현재: LLM mock. RAG 검색만 실연동.
- 보완: `LLMClient` 자리에 **qwen2.5(로컬) 또는 Azure OpenAI** 연결. Investigation 요약 + LLM-as-Judge.
- 결정: 비용·주권=로컬 / 추론품질=Azure. swappable 유지(Protocol).
- 검증: 같은 입력에 mock vs 실 LLM 출력 비교.

### (선택) Validation 오탐 이력
- FP 판단 시 이력 저장→다음 유사 alert에 반영. DB(Cosmos 등) 필요해 범위 큼 → 여유 시.

---

## 4. 벤치마크 계획 (이 대화에서 합의된 프레임 그대로)

### 측정 항목
- **RAG 품질**: RAGAS (Faithfulness / Answer Relevancy / Context Precision·Recall) + 검색 Recall@k·MRR
- **SOC 에이전트 KPI**: TP율 >90% / FP율 <10% / TTP 커버리지 / MTTD·MTTC(파이프라인 처리시간)
- **판정 품질**: LLM-as-Judge (황준식 루브릭)
- **보안(차별점)**: PyRIT 공격성공률(ATLAS + OWASP LLM Top 10 커버리지), Garak probe pass율, **S5 RAG 포이즈닝 저항성**(오염 주입 시 등급 h 유지율)
- **정당화**: 위 지표를 **NIST AI RMF MEASURE**에 매핑

### 무엇을 어디서
| 벤치 | LLM 필요? | 어디서 |
|---|---|---|
| 정책엔진 정확도 / 라우팅 / S5 저항성 | ❌ | **집 PC(프로토타입)에서도 지금 가능** |
| 검색 Recall@k·MRR | RAG만 | 회사 PC(RAGFlow) |
| RAGAS / LLM-as-Judge | ✅ | 회사 PC(LLM 실연동 후) |
| PyRIT / Garak | ✅(타깃 LLM) | 회사 PC |

### 준비물
- **골든 평가셋**: 시나리오(S1~S11)별 질문 2~3개 + 정답 KB 문서 라벨
- **라벨된 alert 세트**: TP/FP 섞어서 (FP율/TP율 측정용)

### 우선순위 (배점 공격30·방어25·에이전트25)
1. RAGAS  2. S5 저항성  3. FP율/TP율  4. PyRIT 커버리지

> ⚠️ LLM이 mock인 동안엔 RAGAS·LLM-Judge가 의미 없음. **LLM 붙이기(B-4)가 벤치마크 선행조건.**
> 단 **S5 저항성·정책엔진·라우팅·검색 Recall은 LLM 없이 먼저 측정 가능.**

---

## 5. 착수 순서 제안
1. (집/회사 무관) GraphRAG 표기 정리 — 문서 한 줄
2. (집/프로토타입) S5 저항성 + 정책엔진 벤치 스크립트
3. (회사) B-4 LLM 실연동 → B-2 HITL → B-3 외부연동
4. (회사) LLM 붙은 뒤 RAGAS·LLM-Judge·PyRIT 벤치 → NIST AI RMF MEASURE 매핑
5. EMB3D 실제 TID / 부가자료 ZIP (제출 직전)
