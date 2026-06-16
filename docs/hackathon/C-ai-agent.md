# C. AI 에이전트 설계 · 멀티에이전트

> Notion 미러 — 자동 추출. 원본: LIG D&A Hackathon

## Microsoft AI Agents for Beginners (한국어)

**원본**: [github.com/microsoft/ai-agents-for-beginners](http://github.com/microsoft/ai-agents-for-beginners)[ (ko)](https://github.com/microsoft/ai-agents-for-beginners/blob/main/translations/ko/README.md)
1. 12개 레슨으로 AI 에이전트 개발의 기초부터 멀티 에이전트·도구 사용·안전까지.
1. 마이크로소프트 공식, 한국어 번역본 제공.
1. 팀 공통 입문 커리큘럼으로 직접 활용.

## Gas Town — N-에이전트 조율 (PyTorchKR)

**원본**: [share.google/9LZLkUMbQaEBrR2kZ](http://share.google/9LZLkUMbQaEBrR2kZ)
1. Git을 백본으로 **20~30개 코딩 에이전트**를 충돌 없이 조율하는 멀티 에이전트 시스템.
1. 컨텍스트 재시작·작업 격리·충돌 해결 패턴 제시.
1. N-에이전트 스케일링의 실전 레퍼런스.

## 클로드 멀티에이전트 개발팀 구축 (WikiDocs)

**원본**: [wikidocs.net/book/19736](http://wikidocs.net/book/19736)
1. 클로드를 활용해 **PM · 개발자 · 테스터** 역할 에이전트 팀을 만드는 한국어 가이드.
1. 역할 분리·메모리·도구 사용 패턴 정리.
1. 우리 에이전트 R&R 설계에 직접 차용.

## AI Agent 설계 및 검증 가이드 (Honbul)

**원본**: [honbul.tistory.com/87](http://honbul.tistory.com/87)
1. AI 에이전트 **구조 선택의 논리·이론적 근거·검증 기준** 통합 가이드.
1. "왜 이 구조인가"를 설명할 수 있도록 재구성된 문서.
1. 발표용 논리 무기로 활용.

## Agent Learning Hub (PyTorchKR)

**원본**: [discuss.pytorch.kr/.../10326](http://discuss.pytorch.kr/.../10326)
1. AI 에이전트 학습 자료 큐레이션 허브.
1. Crew/Role-Play 데모 너머의 **실전 운영 안정성 패턴** 모음.
1. 추가 자료 발굴의 인덱스로 사용.

## turbovec(Github)

**원본**: [https://github.com/RyanCodrai/turbovec](https://github.com/RyanCodrai/turbovec) / [turbovec 딥다이브 — 초보자용](https://ai-news-5min-kr.netlify.app/repos/turbovec-deep-dive.html)
1. 대용량 임베딩 벡터를 **로컬에서 작게 압축 저장하고 빠르게 검색**하기 위한 Rust/Python 벡터 인덱스.
1. 단순 벡터 검색 데모를 넘어, **양자화·SIMD 최적화·필터링 검색·stable ID·저장/로드** 같은 실전 RAG 운영 패턴 모음.
1. FAISS 대체/보완, air-gapped RAG, hybrid retrieval, 메모리 절감형 semantic search 구현을 위한 **참고 인덱스이자 벤치마크 자료**.

## RAG 모델 정리

[https://github.com/HKUDS/RAG-Anything?utm_source=pytorchkr&ref=pytorchkr](https://github.com/HKUDS/RAG-Anything?utm_source=pytorchkr&ref=pytorchkr)
[https://github.com/infiniflow/ragflow](https://github.com/infiniflow/ragflow)
[https://github.com/HKUDS/LightRAG](https://github.com/HKUDS/LightRAG)
[https://github.com/OpenBMB/UltraRAG](https://github.com/OpenBMB/UltraRAG)(자체 IDE까지 가능)
[https://github.com/rag-web-ui/rag-web-ui](https://github.com/rag-web-ui/rag-web-ui)(RAG기능 + UI, UltraRAG와 겹침)
구글, '스스로 판단하고 재검색'하는 차세대 에이전틱 RAG 공개 < 산업일반 < AI산업 < 기사본문 - AI타임스 [https://share.google/n6HCVGnaCpm864gKN](https://share.google/n6HCVGnaCpm864gKN)

### Plugin 잘 쓰는 법

[https://www.linkedin.com/posts/kuandyk-kaiyrzhan_claude-plugin-나올-때마다-거의-다-써봤습니다-결국-지금까지-share-7470425377711095808-Sr5r/?utm_source=share&utm_medium=member_android&rcm=ACoAAEIhR_8BPW4ZYfZDYhfSmOV-xIYOYctegTo](https://www.linkedin.com/posts/kuandyk-kaiyrzhan_claude-plugin-%EB%82%98%EC%98%AC-%EB%95%8C%EB%A7%88%EB%8B%A4-%EA%B1%B0%EC%9D%98-%EB%8B%A4-%EC%8D%A8%EB%B4%A4%EC%8A%B5%EB%8B%88%EB%8B%A4-%EA%B2%B0%EA%B5%AD-%EC%A7%80%EA%B8%88%EA%B9%8C%EC%A7%80-share-7470425377711095808-Sr5r/?utm_source=share&utm_medium=member_android&rcm=ACoAAEIhR_8BPW4ZYfZDYhfSmOV-xIYOYctegTo)

### IBM ATOM

- PDF는 카톡 방에.. (용량 문제로 업로드 실패)
- file

### 스킬 모음

[https://www.threads.com/@choi.openai](https://www.threads.com/@choi.openai)

### LAST 30 DAYS -SKILL

[https://github.com/mvanhorn/last30days-skill](https://github.com/mvanhorn/last30days-skill)

### 언제 모른다고 말해야 되냐

[https://www.sktenterprise.com/bizInsight/blogDetail/dev/15687](https://www.sktenterprise.com/bizInsight/blogDetail/dev/15687)

### I’m not AI

- link_preview: https://github.com/epoko77-ai/im-not-ai

### 에이전트 간의 통신

- 메시지 브로커+ 이벤트 버스 구조

### 하네스 하면 뭐 넣을지

- 하네스로 만든다고 했을 때 어떤 규칙들을 넣을 지
[https://luma.com/2ew4xn7b](https://luma.com/2ew4xn7b)

### 하네스 

- link_preview: https://github.com/revfactory/harness-100/blob/main/README_ko.md
- 코딩 컨벤션 맞추기 python 기준으로([https://peps.python.org/pep-0008/](https://peps.python.org/pep-0008/))
- 시큐어 코딩 테스트
- 로컬에서 테스트 할 만한 내용들 + 어떤 도구 쓸지

---
