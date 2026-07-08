# AIBOM — AI Bill of Materials / 모델 출처·거버넌스

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-09 |
| 상태 | Approved (Codex 2H+2M 반영 → 구현) |
| 근거 | NIST AI RMF(MAP/MANAGE 공급망), SSDF/SLSA 공급망 무결성, EO 14028 SBOM 확장(AIBOM) |
| 선행 | core/sbom.py(SBOMVerifier 3요소) — 이 구조를 AI 컴포넌트로 확장 |
| base | main(CI green) |

## 1. 배경 & 동기
SW 공급망은 SBOM(core/sbom.py)으로 검증하나, **플랫폼 자기 AI 스택**(LLM·임베딩·RAGAS
모델 등)의 출처·무결성·버전 거버넌스는 공백이다. 프롬프트 인젝션 가드가 "무엇이 LLM 에
들어가나"를 지켰다면, AIBOM 은 "**어떤 모델이 돌고 있나**"를 지킨다 — 비인가 모델 치환,
부동 태그(:latest) 드리프트, 미신뢰 소스, digest 불일치(가중치 포이즌)를 잡는다.

## 2. 목표 / 비목표 (Codex 2H+2M 반영)
### 인벤토리 = 선언 매니페스트 (H1 — silent under-coverage 방지)
from_settings 1-모델은 "거버넌스 착시"(embedding/RAGFlow/GraphRAG/RAGAS 누락). → 관측
인벤토리는 **선언 매니페스트** `core/policy/ai-components.yaml`(전 AI 컴포넌트: chat_llm·
embedding·ragflow·graphrag·ragas). + **coverage_gap** — settings flag(ragas_enabled 등)로
*기대되나 매니페스트에 미선언* 시 finding(under-coverage 를 시끄럽게). chat_llm 은 항상 기대 +
매니페스트 chat_llm 버전이 settings.ollama_chat_model 과 불일치하면 version_mismatch(선언≠실행).

### 목표 (SBOM 미러 + AI 확장)
- `core/aibom.py` — 결정론·**동기**(I/O 없음):
  - `AIBOMVerifier.verify(components, expected_types) -> list[AibomFinding]` — 컴포넌트별
    **precedence(M4)**: ① unregistered(승인목록 부재)→append+stop. 승인분은 이하 독립:
    ② untrusted_source(승인 소스 밖) ③ unpinned(버전 ""/"latest"/":latest"/mutable 채널)
    ④ version_mismatch ⑤ 무결성 — 양쪽 digest 존재+불일치→**tampered** / 승인 digest 존재+관측
    digest 부재→**integrity_unverifiable**(H2: ollama 태그엔 digest 없으므로 하드 tamper 아님,
    always-fail 노이즈 방지). 추가: expected_types 중 미커버 → **coverage_gap**.
  - `AibomInventory.from_manifest(path)` — 매니페스트 적재(공유 policy_loader, graceful).
  - `expected_component_types(settings) -> set[str]` — {"chat_llm"} + ragas_enabled→{"ragas"}.
  - `ApprovedAibom.from_yaml` — 승인 목록.
- 정책 `approved-aibom.yaml`(승인 version/digest/source/pinned), `ai-components.yaml`(선언 인벤토리).
- 모델 `AibomComponent(name,component_type,version,digest,source)`, `AibomFinding(component,
  component_type,issue,detail)`. SOCReport +aibom_findings.
- metric `record_aibom_violation()`.
### 비목표
- 모델 실측 digest 계산(런타임 weight 해시 — 인프라). 관측 digest 는 선언값.
- 데이터셋 계보 전체 추적·모델카드 파싱(fast-follow). 자동 차단/롤백(자문만).

## 3. 트러스트/견고성
- 결정론·읽기전용 — 판정/응답 비구동(거버넌스 신호). SBOM 과 동일 fail-closed(관측 digest
  누락 시 tampered — 빈값 우회 방지).
- graceful: 승인목록 로드 실패 → PolicyError(graph 가 잡음) 또는 verifier 미주입 시 skip.
- 관측 인벤토리는 **신뢰 설정(Settings)** 기반 — untrusted alert 비구동(포이즈닝 표면 없음).

## 4. 설계
- SBOMVerifier 미러: ApprovedAibom(dict[name→{version,digest,source,pinned}]),
  AIBOMVerifier.verify(list[AibomComponent], expected_types)→findings. **동기**(I/O 없음).
- **정적 posture — 1회 계산·캐시(M3)**: ReportAgent.__init__ 에서 manifest→verify 1회 →
  findings 캐시 + metric **1회**(위반 수). 각 report 는 캐시된 aibom_findings 노출(재계산·재계상
  없음). 위반 있으면 guardrail_flag 는 report 당 1개(캐시 참조) — 정적 posture 표식.

## 5. 테스트
- test_aibom.py: unregistered/version_mismatch/untrusted_source/unpinned/tampered 각 판정,
  정상 무탐, digest 누락 fail-closed, from_settings 인벤토리, 정책 graceful.
- report 배선: 위반 → aibom_findings + guardrail_flag.

## 6. 롤아웃
1. 모델 + core/aibom.py + 정책 YAML + metric + 테스트.
2. report 배선. 3. Codex(설계→diff) → 게이트. 브랜치 feat/aibom-model-provenance.
