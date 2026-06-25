# KPI · 측정 근거 (방어 25점 / AI 에이전트 25점)

> 6-에이전트 SOC 파이프라인을 **라벨된 평가셋**에 돌려 산출한 실측 수치.
> 정성 서술이 아니라 **측정식 + 검증 출처**로 제시 — 심사 "이 점수 믿을 만한가" 대비.
> 재현: `python benchmarks/run_kpi.py` (KPI) · `python benchmarks/run_benchmarks.py` (RAG/저항성)
> 산출물: `benchmarks/results/kpi_results.json` · `bench_results.json`

평가셋: **정탐 11**(S1~S11 실공격) + **오탐 6**(양성 노이즈: 도심 GPS 저하·서명 펌웨어
업데이트·기상 RSSI 저하·인가 재지정·예정 점검·이륙 EKF 수렴). 판정은 `signal_judge`
(근거 기반, 라벨 비참조)라 FPR/FNR 이 의미를 갖는다.

---

## 1. 에이전트별 KPI (AI 에이전트 25점)

| 에이전트 | KPI | 측정값 | 측정식 / 검증 출처 |
|---|---|---|---|
| **Triage** | MTTT (Mean Time To Triage) | **0.04 ms** | triage 노드 소요(정책 엔진 산정) · node_timings(객관적) |
| **Investigation** | Confidence Score(평균) | **0.76** | 신뢰 청크 점수·커버리지 기반(결정론) · 라벨 대조 가능 |
| | Context(신뢰 사례 평균) | **4.12건** | RAG 검색 트러스트 청크 수 |
| **Validation** | Precision / Recall | **1.0 / 1.0** | 혼동행렬(pred=verdict, 라벨) |
| | FPR / FNR | **0.0 / 0.0** | FP/(FP+TN) · FN/(FN+TP) — 혼동 {tp11, fp0, fn0, tn6} |
| **Response** | MTTC (Mean Time To Contain) | **0.09 ms** | response 노드 소요(플레이북 결정) · node_timings(객관적) |
| | Playbook Success Rate | **1.0** | 플레이북 선택 성공 / 정탐 |
| **Report** | Report Latency | **0.09 ms** | report 노드 소요 · node_timings(객관적) |
| | Evidence Completeness | **1.0** | OSCAL 증거 생성 / 전체 |
| (파이프라인) | 총 소요(평균) | **≈2.84 s** | 전 노드 합(LLM 분석 포함) |

> **MTTT·MTTC 가 sub-ms 인 이유**: Triage(정책 엔진)·Response(플레이북 매핑)는
> **결정론적 판단**이라 즉시 결정된다. 지연은 Investigation 의 RAG+LLM 분석(≈2.8s)에
> 집중. 즉 "위협 우선순위·대응 결정은 즉각, 근거 분석에 시간" 구조. (실제 차단 *실행*
> 시간은 플레이북 실행계에서 별도 — 여기 MTTC 는 결정 지연.)

## 2. 방어 전략 · RAG 품질 (방어 25점)

| 지표 | 측정값 | 의미 / 검증 출처 |
|---|---|---|
| **라우팅 정확도** | **1.0 (22/22)** | 정탐→response / 오탐→rule_update (S1~S11 × {TP,FP}) |
| **S5 RAG 포이즈닝 저항성** | **1.0 (11/11)** | 적대 제안등급('i') 주입에도 정책 등급 유지율 — Triage+엔진 이중 방어 |
| **LLM-Judge Faithfulness** | **≈3.0–3.6 / 5** | 요약이 컨텍스트에만 근거하는가(실 Ollama judge, 런별 변동) |
| **LLM-Judge Relevancy** | **≈3.8–4.1 / 5** | 요약이 경보 질문에 적절한가 |
| **검색 Recall@5 / MRR** | **1.0 / 1.0 (11/11)** | 시나리오별 정답 incident_case 가 전부 rank 1 로 검색 |

> **S5 저항성 = 핵심 차별점**: 적대적 등급 인하 주입을 Triage 가드레일과 정책 하한이
> 이중으로 막아 11/11 유지. RAG 장애 시에도 Investigation 이 빈 컨텍스트로 우아하게
> 강등(복원력)하여 대응 지속.

## 3. NIST AI RMF MEASURE 매핑 (정당화)

| NIST AI RMF (MEASURE) | 대응 KPI/근거 | 비고 |
|---|---|---|
| MEASURE 2.3 — 시스템 성능/정확도 | Precision/Recall 1.0, 라우팅 1.0 | 라벨셋 기반 정량 |
| MEASURE 2.5 — 신뢰성/견고성 | S5 저항성 1.0, RAG 강등 복원력 | 적대 주입·장애 대응 |
| MEASURE 2.6 — 안전(오작동 영향) | FPR/FNR 0.0, HITL 승인 | 오탐·미탐·비가역 액션 게이트 |
| MEASURE 2.7 — 보안/회복력 | S5 포이즈닝 저항, 출처 가드레일 | 미신뢰 컨텍스트 격리 |
| MEASURE 2.9 — 설명가능성 | severity_rationale, node_timings | 등급 산정·지연 추적 가능 |
| MEASURE 2.11 — 유해/편향 | (레드팀 PyRIT/Garak 매핑) | 동언 lane 연계 |

## 4. 검증 출처 (객관 로그 vs LLM 자체평가)

| KPI | 검증 출처 | 객관성 |
|---|---|---|
| MTTT·MTTC·Report Latency | node_timings(perf_counter) | ✅ 객관 |
| Precision/Recall/FPR/FNR | 라벨셋 혼동행렬 | ✅ 객관(라벨 = 레드팀 정답지로 교체 가능) |
| Confidence Score | 검색 점수·커버리지(결정론) | ◐ 도출값 — 레드팀 라벨 대조 권장 |
| Faithfulness/Relevancy | LLM-as-Judge(1~5) | ⚠ LLM 자체평가 — 정답 라벨 보강 필요 |
| S5 저항성·라우팅 | 정책 등급/라우팅 결정 | ✅ 객관 |

> **의존 메모**: FPR/FNR·Confidence 검증의 최종 정답지는 **레드팀(김동언) 주입 로그**.
> 현재 오탐셋은 합성(양성 노이즈)이며, 레드팀 라벨 공유 시 그대로 교체해 측정.

## 5. 한계 · 다음

- 검색 품질 Recall@5/MRR = 1.0 — KB 메타 태깅(incident_cases 13건, S1~S11) 적용 완료.
- LLM-Judge Faithfulness 3.0/5 — 요약 근거성 개선 여지(프롬프트/모델 튜닝).
- 오탐셋을 레드팀 실 주입 로그로 교체 시 FPR/FNR 신뢰도 상승.
