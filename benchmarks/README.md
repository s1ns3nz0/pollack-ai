# 벤치마크 — SOC 에이전트 / RAG

예선 보고서용 정량 지표. **LLM 불필요**(정책엔진·라우팅·검색은 결정론적)라 즉시 측정 가능.
LLM 연동(요약) 후 RAGAS·LLM-as-Judge 지표를 추가할 수 있다.

## 실행
```bash
# RAGFlow 라이브 + 시나리오(projects/dah2026/scenarios) 필요
python benchmarks/run_benchmarks.py
# → 콘솔 표 + benchmarks/results/bench_results.json
```

## 측정 항목 & 결과 (2026-06-18, KB 126 docs, S1~S11)

| 지표 | 값 | 설명 |
|---|---|---|
| **라우팅 정확도** | **1.0 (22/22)** | TP→Response, FP→RuleUpdate (S1~S11 × {TP,FP}) |
| **S5 포이즈닝 저항성** | **1.0 (11/11)** | 적대 제안등급('i') 주입 시 정책 등급 유지율 — **핵심 차별점** |
| **검색 Recall@5** | **1.0 (11/11)** | 시나리오 질의 시 정답 incident_case 가 top-5 에 포함 |
| **검색 MRR** | **1.0** | 정답 문서 평균 역순위(전부 rank 1) |
| LLM-Judge Faithfulness | 3.73 / 5 | Investigation 요약이 컨텍스트에만 근거하는가(실 Ollama 판정) |
| LLM-Judge Relevancy | 4.0 / 5 | Investigation 요약이 경보에 적절한가 |

> LLM-as-Judge(Faithfulness/Relevancy)는 실 Ollama(qwen2.5)로 Investigation 요약을
> 1~5점 채점한 RAGAS-style 지표. Azure OpenAI 전환 시 동일 프레임으로 재측정.

> S5 저항성 100% = 적대적으로 심각도를 낮추려는 RAG 포이즈닝/프롬프트 인젝션에도
> 정책 엔진이 등급 하한을 강제해 **단 1건도 하향되지 않음**. NIST AI RMF MEASURE 에 매핑.

## 지표 ↔ 평가 프레임 매핑
- 라우팅/S5 저항성 → 방어 전략(25점) · AI 에이전트(25점) 정량 근거
- Recall@k/MRR → RAG 검색 품질(도메인 주입 신뢰성)
- (추후 LLM 연동 시) RAGAS Faithfulness/Relevancy, LLM-as-Judge, PyRIT 공격성공률

## 골든셋
- **시나리오별 정답 문서**: KB 메타데이터 `scenarios` 태그로 자동 구성(시나리오당 사례 1~2개, 집합으로 평가)
- **라벨된 alert**: 각 시나리오를 TP/FP 양쪽으로 생성(라우팅 측정)
