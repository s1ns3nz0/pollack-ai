# tools/ — SOC Agent 도구

LangChain `BaseTool` 을 상속한 도구 모음. Agent 는 도구의 입출력 계약만 의존한다.

## ragflow_tool.py — `RagflowRetrievalTool`

UAV 보안 지식베이스(RAGFlow)를 비동기로 검색하는 RAG 도구.

- **입력**: 자연어 질의(`query`) + 반환 개수(`k`)
- **출력**: `core.models.RetrievedChunk` 목록 — `{text, source, score}`.
  `source` 는 `kb/<문서명>` 으로 정규화되어 Investigation Agent 의 출처
  가드레일(신뢰 출처 `kb/` 만 채택)을 통과한다.
- **백엔드**: 로컬 RAGFlow `/api/v1/retrieval` (임베딩 `bge-m3`, 챗 `qwen2.5:14b`,
  KB `uav_soc_rag` = UAV 공격 incident case · MITRE ATT&CK for ICS · IEC 62443 ·
  Aissou/IEEE/NetworkComm 데이터셋 실측 분석 117문서). 원천 문서 목록은
  `data/knowledge_base/MANIFEST.md` 참고(본문은 코드 레포에 커밋하지 않음).

### 사용

```python
from tools.ragflow_tool import RagflowRetrievalTool

tool = RagflowRetrievalTool()                       # 설정은 RAGFLOW_* env/.env 에서
chunks = await tool.aretrieve("GPS 재밍 탐지", k=5)  # 타입 안전 API
text = await tool.ainvoke({"query": "GPS 재밍", "k": 5})  # LangChain 표준 진입점
```

### 설정 (`.env`)

```
RAGFLOW_BASE_URL=http://127.0.0.1:9380
RAGFLOW_API_TOKEN=<RAGFlow API 토큰>
RAGFLOW_DATASET_ID=<지식베이스 dataset id>
```

### GraphRAG 와의 관계

팀 스택의 GraphRAG(Azure) 로 교체하더라도 Agent 는 동일한 `RetrievedChunk`
계약만 의존하므로 `graphrag_tool.py` 로 도구만 갈아끼우면 된다. RAGFlow 는
Azure 비용 없이 로컬에서 즉시 동작하는 RAG 경로를 제공한다.

### 지식베이스 적재

RAGFlow 엔진과 ingest 스크립트는 별도 위치(`uav_soc_rag_poc`)에 있다. KB 원천
문서는 데이터/코드 분리 원칙에 따라 코드 레포에 커밋하지 않으며, 목록과 복원
방법은 `data/README.md` 와 `data/knowledge_base/MANIFEST.md` 를 따른다.
