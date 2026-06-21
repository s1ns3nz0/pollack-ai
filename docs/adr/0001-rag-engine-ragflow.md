# ADR 0001 — RAG 엔진: RAGFlow (GraphRAG 아님)

- 상태: 채택 (2026-06)
- 담당: 황준식 (RAG/방어 에이전트 lane)

## 배경

킥오프 초기 아키텍처에 "GraphRAG"가 언급되었고, 팀 리서치(C-ai-agent)에는 RAGFlow도
후보로 있었다. SOC 에이전트의 Investigation 단계에 쓸 RAG 엔진을 확정해야 했다.

## 결정

**RAGFlow 를 RAG 엔진으로 채택한다. GraphRAG 는 쓰지 않는다.**

발표/보고서에서는 "GraphRAG" 대신 다음과 같이 표기한다:
> **"RAGFlow 기반 RAG (딥 문서파싱·하이브리드 검색·리랭크). 자산 연관성(상위자산
> 침해 → 의존 기체 등급 상향)은 심각도 정책엔진의 `lateral_correlation` dynamics 로 처리."**

## 근거

1. **층위가 다름**: GraphRAG = RAG *기법*(지식그래프·다중 hop, 적재비용 높음, global
   sensemaking 질의용) / RAGFlow = RAG *엔진*(local 질의·검색 품질 강점).
2. **SOC 질의 = local 검색**: "이 경보 관련 사례·TTP·플레이북 검색"은 local retrieval →
   RAGFlow 가 적합. GraphRAG 가 빛나는 global 요약 영역이 아님.
3. **GraphRAG 의 핵심 가치(자산 연관성)는 이미 구현됨**: 상위자산 침해 → 의존 기체
   등급 상향을 `core/severity.py` 의 `lateral_correlation` dynamics 로 처리. 즉 능력
   손실이 아니라 레이어만 다름.
4. **비용/주권**: 로컬(Ollama 임베딩) 운용으로 Azure 비용 없이 구동.
5. **swappable**: `RetrievedChunk` 계약(`tools/ragflow_tool.py`)으로 추상화 → 추후
   GraphRAG/다른 엔진으로 도구만 교체 가능. RAGFlow 자체도 옵션으로 knowledge graph
   지원이라 필요 시 켤 수 있음.

## 영향

- `tools/ragflow_tool.py` (`RagflowRetrievalTool`) 가 단일 RAG 진입점.
- 보고서/발표의 "GraphRAG" 표기를 위 문구로 통일 → 심사 질문 차단.
