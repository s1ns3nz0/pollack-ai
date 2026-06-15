# data/ — 데이터 자산

데이터와 코드를 분리한다. RAG 지식베이스 **원천 문서는 코드 레포에 커밋하지 않고**
별도로 관리하며, 여기에는 무엇이 들어가는지(매니페스트)와 어떻게 채우는지만 둔다.

## knowledge_base/

RAGFlow 지식베이스(`uav_soc_rag`)에 적재되는 UAV 보안 원천 문서.

- **무엇이 들어가나** → `knowledge_base/MANIFEST.md` (문서 목록)
- **원본은 커밋 안 함** → `.gitignore` 로 제외 (용량·변경빈도·라이선스 고려)
- **로컬에 채우는 법**: 정본 위치에서 복사
  ```bash
  cp -r /gpfs/home/jm00055/uav_soc_rag_poc/ragflow_ingest/. data/knowledge_base/
  ```
- **RAG 적재**: 문서는 RAGFlow KB(임베딩 `bge-m3`)로 ingest 되어 검색된다.
  GraphRAG(Azure) 로 전환 시에는 Azure Blob(`GRAPHRAG_STORAGE_ACCOUNT`)로 적재한다.

> 즉 이 폴더의 실제 문서 파일은 "검색 엔진에 넣는 입력 데이터"이지 애플리케이션
> 코드가 아니므로, 레포에는 매니페스트만 남기고 본문은 데이터 저장소에서 관리한다.
