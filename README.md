# 🛸 UAV AI SOC Platform

[![CI](https://github.com/s1ns3nz0/pollack-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/s1ns3nz0/pollack-ai/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/🐍_Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![LangGraph](https://img.shields.io/badge/🕸️_LangGraph-Multi--Agent-1C3C3C?logo=langchain&logoColor=white)](https://langchain-ai.github.io/langgraph/)
[![Azure](https://img.shields.io/badge/☁️_Azure-Sentinel_+_OpenAI-0078D4?logo=microsoftazure&logoColor=white)](https://azure.microsoft.com/)
[![FastAPI](https://img.shields.io/badge/⚡_FastAPI-Dashboard-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Built with Claude Code](https://img.shields.io/badge/🤖_Built_with-Claude_Code-DA7857?logo=anthropic)](https://claude.ai/code)

[![Version](https://img.shields.io/badge/📦_version-0.1.0-blue)](https://github.com/s1ns3nz0/pollack-ai)
[![Tests](https://img.shields.io/badge/🧪_tests-1,363_passed-success)](https://github.com/s1ns3nz0/pollack-ai/actions/workflows/ci.yml)
[![Agents](https://img.shields.io/badge/🤖_agents-11_+_4_judges-8A2BE2)](https://github.com/s1ns3nz0/pollack-ai)
[![MITRE](https://img.shields.io/badge/🎯_MITRE-ATT%26CK_%2F_ATLAS-C8102E)](https://attack.mitre.org/)
[![Red Team](https://img.shields.io/badge/🔴_Red_Team-PyRIT_%2F_RAGAS-8B0000)](https://github.com/Azure/PyRIT)

방산 UAV 보안 SaaS 플랫폼 — LangGraph 기반 멀티 에이전트 AI SOC 시스템

---

## 🎯 개요

무인기(UAV) 운용 환경을 겨냥한 AI 보안관제(SOC) 플랫폼. Azure Sentinel에서 수집한 알림을
LangGraph 멀티 에이전트 파이프라인(트리아지 → 조사 → 대응 → 검증 → 보고)이 자율 처리하고,
GraphRAG 기반 지식베이스와 위협 인텔리전스(MITRE ATT&CK/ATLAS, CISA KEV)를 근거로
판정 신뢰도를 계량한다.

핵심 차별점:

- **임무 중심 트리아지** — 심각도(severity)와 별개의 임무위험(priority) 축, METT-TC 기반 판정
- **지휘관 결심우위 계층** — OODA 루프, Kill Web, BLUF 브리핑 등 군 결심 프레임워크 내장
- **폐루프 학습** — 예측(predictor)·억제 재심(cold-case)·경험 판정(experience judge)으로 오탐 재발 억제
- **AI 자기방어** — 프롬프트 인젝션 가드, LLM Judge 펜싱, PyRIT/ATLAS 레드팀 회귀 게이트
- **정직성 불변식** — stub/미검증 데이터의 과장 금지, 검색 출처(provenance) 공개

운영 형태: AKS 위에서 hotpath(실시간 관제)와 learning(학습 루프) 트랙을 분리 배포,
kagent 오케스트레이터 + ArgoCD GitOps.

---

## 🧰 기술 스택

| 영역 | 기술 |
|---|---|
| AI Agent | LangGraph, LangChain, Azure OpenAI (GPT-4o), kagent |
| 보안 분석 | Azure Sentinel (KQL), GraphRAG, MITRE ATT&CK/ATLAS, CISA KEV |
| Red Teaming / 평가 | PyRIT, RAGAS, 자체 벤치마크 하니스 |
| 서비스 | FastAPI (대시보드·헬스·메트릭), AKS, ArgoCD, Prometheus/Grafana |
| 언어 | Python 3.11+ |

---

## 🧭 적용 도메인 개념 맵

코드에 실제 구현된 군사 교리·보안 표준·분석 모델과 **구체 적용 방식**. 전 모듈 `core/` 소재, 클래스/함수명은 실제 코드 기준.

**설계 불변식 4가지** (전 모듈 공통):

1. **판정권은 결정론 엔진에** — severity/verdict은 정책 YAML 기반 결정론 코드가 결정. LLM은 요약·설명 생성만 (프롬프트 인젝션이 판정을 못 바꾸는 구조)
2. **자문 렌즈는 읽기전용** — 교리 모듈(OODA·COA·Kill Web 등)은 report에 관점만 추가, verdict/severity/CAT 불변
3. **비대칭 신뢰** — 전방 enrich 플래그(위조 가능한 alert 본문 유래)는 severity 격상까지만. 공격자 프로필 적립·Engage 전진·PB 학습 등 상태 변경은 후방 신뢰 관측(`ProbeEngine`)의 CONFIRMED_TP만 트리거
4. **미배선 정직 표기** — 구현됐지만 파이프라인 미연결인 모듈은 아래 표에 🧪로 명시 (과장 금지)

**배선 범례**: ✅ hotpath 파이프라인 | 🔬 학습 워커·CI·모니터링 경로 | 🧪 미배선 (라이브러리/parked)

### 파이프라인 골격 (`agents/graph.py`)

```
[enrich 체인] posture(CPCON 하한) → dynamics → prediction_match → killchain 진행도 → decoy_hit → key_terrain
      ↓
   triage ──▶ investigation ──▶ (active_hunt: opt-in) ──▶ validation
                                                              │
                              ┌───── true_positive ───────────┴── false_positive ─────┐
                              ▼                                                        ▼
                    (HITL시 approval) ──▶ response ──▶ report ◀────────────────── rule_update
                                                        │
자문 렌즈 집결지: diamond·stride·campaign·causal·coa·killweb·ooda·brief·intent·commander·hunt·recovery·staging·honeypot·ioa_graph는 전부 report 노드에 선택 주입 ──▶ END
```

별도 트랙: `app/hotpath.py`(실시간, AlertCorrelator 전역 상태) / `app/learning.py`(주기 워커: OutcomeProbe·AutoKQL) / CI (AI 레드팀·BAS 게이트).

### ⚔️ 군사 교리 / 지휘·결심 프레임워크

| 개념 (출처) | 코드 적용 방식 | 배선 |
|---|---|---|
| METT-TC / MBCRA·핵심지형 (JP 3-12, JP 5-0) | `KeyTerrainDetector.enrich`가 `asset-tiers.yaml` 기준 핵심지형 플래그를 **정책 파생값으로 강제 덮어씀**(inbound 위조 차단). `MissionRiskAssessor.assess`는 지형·의존자산수·킬체인·dwelling 신호 가중합 → `MissionRisk`(severity와 독립인 priority 축) | ✅ enrich + triage/report |
| 임무형 지휘 — Commander's Intent (ADP 6-0) | `IntentFilter.assess` — main_effort 자산/시나리오 매칭. **비대칭 게이팅**: 격상은 provisional 판정으로도, 위임(routine)은 authoritative 확정만. 정책 검증 실패 시 전량 surfaced로 degrade | ✅ report |
| OODA 결심우위 (Boyd) | `DecisionAdvantageAssessor.assess` — actor kill_chain 타임스탬프 델타 중앙값 = 적 템포, SOC latency와 비교 → `margin`/`contested`/`unknown` (측정 불가 시 과장 없이 unknown) | ✅ report |
| BLUF Commander Brief | `CommanderBriefBuilder.build` — 완성된 SOCReport 필드만 재조립하는 **순수함수**(새 주장 0). confidence는 `incident_case.provisional`에 정박 | ✅ report |
| COA Matrix (교리 COA 분석) | `CoaPlanner.plan` — `coa-matrix.yaml`(tactic × 7D: Deny/Disrupt/Degrade/Deceive…) 셀 조회. 미정의 셀은 **gap으로 정직 노출**. Engage 주입 시 Deceive 셀에 adversary_cost 보강 | ✅ report |
| Kill Web / Mosaic (DARPA) | `KillWebBuilder.resilience` — 킬체인 단계별 covered 기법수로 multi/single/uncovered 분류 + breadth ratio. "기법수 ≠ 독립 센서, SPOF 미증명" rationale 명시 | ✅ report |
| JADC2 Releasability | `for_partner` — **default-deny allowlist**로 STIX 번들 필터(victim 정점 제거, REL-TO/caveat 마킹, 파트너 티어별) | 🧪 미배선 |
| BDA 교전피해평가 (JP 3-60) | `BdaAssessor.assess` — 방어효과 역환산 → 기능피해 등급(none~severe), 복구성공+유의미피해 → 재교전 권고 | 🔬 probe 워커 |
| CPCON 방어태세 (DoD/국정원) | `PostureProvider.enrich` — 전역 태세를 alert posture **하한으로만 상향**(floor). enrich 체인 최우선 실행 | ✅ enrich |
| Mission Assurance 임무지속 | `DegradationAssessor.assess` — TP 확정 + 자산 특정 시에만 SUSTAINED/MINIMAL/ABORT + 대체경로 | ✅ response/report |
| Incident Commander (CJCSM 6510) | `IncidentCommander.direct` — 교리 상수로 escalation·HITL(권위 신호만)·tier·CISA 72h 보고시한 판정. 순수·total 함수 | ✅ report |

### 🔍 위협 분석 모델

| 개념 (출처) | 코드 적용 방식 | 배선 |
|---|---|---|
| Cyber Kill Chain (Lockheed Martin) | `KillChainProgressor.enrich` — actor 누적 tactic 최고 order가 C2 이후(order≥11)면 `kill_chain_advanced` 스탬프 → severity 격상 입력 | ✅ enrich |
| Diamond Model (Caltagirone) | `DiamondAnalyzer.build` — alert+프로필 → 4정점 `DiamondEvent`. `pivot`(공유 인프라/기법 역색인으로 공격자 연결)은 구현만 | ✅ report (pivot 🧪) |
| STRIDE (Microsoft) | `StrideClassifier.classify` — 명시 태그 우선, 없으면 tactic→STRIDE 추론 + 완화 매핑 (`stride-model.yaml`) | ✅ report |
| ACH 경쟁가설 (Heuer/CIA) | `AchEvaluator.evaluate` — 14개 증거키 정규화 → 가설별 지지/반증 원장, **반증 최소 순위**. 귀무가설(HYP-BENIGN-ENV) 필수. confidence 라우팅 비관여(자문) | ✅ investigation |
| IoA 그래프 | `IoAGraphBuilder.build_from_state` — actor/기법/예측/인과 노드+엣지 → Cytoscape.js JSON | ✅ report |
| 다중경보 상관 | `AlertCorrelator.observe` — 슬라이딩 윈도우 3패턴: 공유IOC+의존엣지 **union-find 클러스터** / multi-axis / storm → S9 집약경보로 파이프라인 재투입 | ✅ hotpath 전역 |
| 캠페인 체인 | `CampaignDetector.detect` — 시나리오 히스토리 vs C1~C7 체인 **순서보존 prefix 매칭** → next_expected 예고 | ✅ report |
| 인과 추론 | `CausalReasoner.build_chain` — signals → `causal-rules.yaml` 결정론 체인. explanation 문장만 LLM(펜싱 하), LLM 실패해도 체인 보존 | ✅ report |
| 공격자 프로파일링 | `fingerprint` — TTP+IP/24 canonical JSON SHA-256. `ActorWriteGate.submit`은 **CONFIRMED_TP만 적립+서명**, `ActorReadGate.recall`은 서명 검증 통과만 반환(포이즈닝 면역) | ✅ probe write / 다수 read |

### 🌐 위협 인텔리전스 표준

| 개념 (출처) | 코드 적용 방식 | 배선 |
|---|---|---|
| ATT&CK / ATLAS / KEV 피드 | `MitreStixFeed`·`AtlasFeed`·`CisaKevFeed` — httpx fetch → technique/CVE 추출 + raw_hash 스냅샷 | 🔬 피드 갱신 |
| STIX 2.1 생산 (OASIS/NIST 800-150) | `StixExporter.from_diamond` — **victim 완전 생략(OPSEC)**·TLP 마킹·uuid5 결정론 id → bundle, TAXII envelope 조립까지(전송 없음) | 🧪 미배선 |
| IOC egress 신뢰경계 | `IocEgressFilter.sanitize` — 사설/내부 IOC·우회표기(IPv6-mapped·octal·punycode) 드롭 후에만 외부 TI/샌드박스 조회 허용 | ✅ investigation |

### 🕸️ 능동방어 / 예측 폐루프

전방(예측→표시)과 후방(관측→학습)이 비대칭: 전방 플래그는 severity까지만, 상태 전진은 후방 신뢰 관측만.

```
[전방] predictor(n-gram 예측) → staging(커버리지 대조) → honeypot(미끼 배치안) → report
       └ PredictionMatcher/DecoyDetector가 다음 alert에 prediction_match/decoy_hit 스탬프 → severity 격상
[후방] ProbeEngine.decide(canary_hit/mission_effect 관측) → CONFIRMED_TP/FP
       └ ActorWriteGate(프로필 적립+예측 hit/miss 정산) · EngageAdvancer(교전 전진) · PB 효과 학습
```

| 개념 (출처) | 코드 적용 방식 | 배선 |
|---|---|---|
| 공격 시퀀스 예측 | `SequencePredictor.predict` — kill_chain **n=2 마르코프** 조건부빈도, min_support 3·min_prob 0.5 가드, top-3 | ✅ investigation + write 게이트 |
| 예측 대조 | `PredictionMatcher.enrich` — pending 예측과 읽기전용 대조 → `prediction_match`(저장소 무변이) | ✅ enrich |
| 선제 스테이징 | `DefenseStager.stage` — 예측 TTP를 coverage 역인덱스 조회 → staged/accelerate/**gap** | ✅ report |
| 예측 gap → AutoKQL | `gap_techniques` → KQL draft 초안(proposed-only) 설계 | 🧪 parked (AutoKQL은 신규 technique 경로로 별도 가동 🔬) |
| 예측 유도 허니팟 | `HoneypotPlanner.plan` — 예측 technique→디코이 유형 매핑(UAV/ICS 특화) 배치안 | ✅ report |
| Deception decoy/canary | `DecoyDetector.enrich` — decoy 자산/canary 해시 접촉 → `decoy_hit`(TP 승격은 안 함) | ✅ enrich |
| MITRE Engage 적 교전 | `EngageAdvancer.advance` — 신뢰 TP만, alert.id 멱등 dedup 후 EXPOSE→ELICIT→UNDERSTAND **단조 전진** + adversary_cost 누적. Affect(능동교란)는 범위 밖 | ✅ write 게이트 |
| Tier-3 헌팅 | `HuntPlanner.plan` — 예측(가중 100) &gt; 캠페인(80) &gt; coverage gap(50) 융합 top-10 백로그. 실행은 opt-in `active_hunt` 노드 | ✅ report + opt-in 노드 |
| Cold-case 재심 | `ColdCaseReopener` — 동일 actor/signature TP 확정 시 과거 억제(FP) revoke + 재심 원장 | 🧪 게이트 지원, 핫패스 미주입 |
| 폐루프 검증 | `ProbeEngine.decide` — **canary_hit이 engagement의 유일 트리거**(호출자 주장 불가), no_effect 5분 지속 → CONFIRMED_FP | 🔬 probe 워커 |
| PB 효과 학습 | `ActorPlaybookOutcomeGate.submit` — playbook별 avg_effect 누적 + 프로필 재서명(자동 선택은 안 함) | 🔬 probe 워커 |

### 🛡️ 대응·복구 표준

| 개념 (출처) | 코드 적용 방식 | 배선 |
|---|---|---|
| CACAO 2.0 (OASIS) | `resolve_playbook` — workflow 워크 + **AST whitelist 조건식**(eval/exec 없음), no-exec manual command만, mission_risk 분기 실패 시 HITL fail-safe. 검증기가 NIST IR phase 커버·source_ref 정합 강제 | ✅ response + approval |
| D3FEND Evict/Restore | `RecoveryPlanner.plan` — 도달 최고 단계의 축출→복구→검증 스텝. `RecoveryVerifier.check` — 재발 시 FAILED(공격자 잔존) 메트릭 | ✅ report + metrics |
| Runbook (NIST IR) | `load_runbooks` + BAS/CACAO/tactic 정합 검증. `approval.required`면 HITL 강제 | ✅ response + approval |
| 심각도 정책 | `SeverityEngine.compute` — baseline + asset/phase/posture modifier + dynamics(prediction_match·decoy_hit·dwelling·key_terrain 격상, posture lock 시 강등 차단). **판정권 보유 주체 = 이 결정론 엔진** | ✅ triage |

### 🤖 AI 보안 / 거버넌스

| 개념 (출처) | 코드 적용 방식 | 배선 |
|---|---|---|
| 프롬프트 인젝션 방어 (OWASP LLM01 / ATLAS AML.T0051) | `PromptInjectionGuard.neutralize` — UNTRUSTED 펜스 + 위조 구분자 redact. `scan`은 텔레메트리 전용(판정 비구동 — 판정권이 결정론이라 인젝션 무력) | ✅ LLM 경로 |
| AI 레드팀 회귀 게이트 (PyRIT/ATLAS) | `AiRedTeamRunner.run` — 시나리오 payload를 guard에 통과시켜 expect(high/detected/benign) 대조 → pass_ratio 게이트 | 🔬 CI/워커 |
| BAS 방어 상시 검증 | `BASRunner.run` — 공격 케이스별 탐지/준비 판정 + 계측품질(native~design_blind) 갭 백로그 → monitoring·cATO 입력 | 🔬 |
| AIBOM | `AIBOMVerifier.verify` — 선언 vs 승인 매니페스트 대조: 미등록/미신뢰 출처/unpinned/변조/모델카드 누락 + coverage_gap | 🔬 |
| SBOM 공급망 | `SBOMVerifier.averify` — 미등록/버전 불일치/변조(**해시 누락 fail-closed**)/KEV 악용중 CVE | ✅ report |
| RAG 품질 (RAGAS) | `RagasEvaluator.aevaluate` — faithfulness/relevancy 측정, fire-and-forget(핫패스 비차단) | ✅ investigation (플래그) |

### 📋 컴플라이언스 / 신뢰성

| 개념 (출처) | 코드 적용 방식 | 배선 |
|---|---|---|
| cATO 지속 인가 (NIST 800-37) | `CatoAssessor.assess` — BAS+SLO+SBOM 신호를 NIST 800-53 통제 갭으로 환산 → authorized/conditional/at_risk + POA&amp;M (미지 심각도는 high로 fail-safe) | 🔬 |
| OSCAL 증거 (NIST) | `build_evidence` — 완료 state → 등급별(full~log-only) 증거 조립. `implementation_status="stub"` **정직 표기** | ✅ report |
| Zero Trust (CISA ZTMM 2.0) | `ZtAssessor.assess` — 근거(verified_runtime/implemented_static) 없는 advanced 주장을 **initial로 cap**(성숙도 세탁 방지) | 🔬 |
| 데이터 라인리지 | `LineageCollector.snapshot` — git SHA·정책파일 SHA-256·LLM 모델·노드별 latency → OSCAL 증거 임베드 | ✅ report (플래그) |
| Continuous Monitoring | `SLOMonitor.evaluate` — 런타임 카운터(eviction 실패·mission abort 등) vs `slo-rules.yaml` → breach → cATO 입력 | 🔬 |

---

## 📊 프로젝트 현황

| 지표 | 값 |
|---|---|
| Python 소스 파일 | 289개 (~48,800 LOC) |
| SOC 에이전트 | 11개 (+ Judge 앙상블 4개) |
| 분석/도메인 모듈 (`core/`) | 60+ |
| 외부 연동 도구 (`tools/`) | 18개 |
| 테스트 | 파일 147개 / 테스트 함수 1,363개 |
| Sentinel 콘텐츠 | Analytic Rules + Watchlists 18개 파일 |
| 배포 자산 | Dockerfile, k8s 매니페스트, ArgoCD 앱, 모니터링 |
| CI 워크플로 | 2개 (`ci.yml`, `kpi-weekly.yml`) |

---

## 🚀 온보딩 — 처음 세팅하는 경우

### 1. 필수 도구 설치

**Python 환경**
```bash
# pyenv — Python 버전 관리
curl https://pyenv.run | bash
pyenv install 3.11.9
pyenv local 3.11.9

# uv — 빠른 패키지 설치 (pip 대체)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Claude Code**
```bash
npm install -g @anthropic-ai/claude-code
```

**Azure CLI**
```bash
# macOS
brew install azure-cli

# Ubuntu
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# 로그인
az login
```

**Docker Desktop**
- https://www.docker.com/products/docker-desktop 에서 설치

**VS Code 확장 (선택)**
- Python, Pylance
- Ruff
- Black Formatter
- GitLens

### 2. 프로젝트 세팅

```bash
# 저장소 클론
git clone https://github.com/s1ns3nz0/pollack-ai.git
cd pollack-ai

# 환경변수 세팅
cp .env.example .env
# .env 파일 열고 실제 값 채우기 (Azure 키 등)

# 의존성 설치 (dev 포함)
uv pip install -e ".[dev]"
# 또는 pip 사용 시
pip install -e ".[dev]"

# pre-commit hook 등록 (커밋 전 자동 검사)
pre-commit install
```

### 3. Azure 인증 세팅

```bash
# Service Principal로 인증
az login --service-principal \
  --username $AZURE_CLIENT_ID \
  --password $AZURE_CLIENT_SECRET \
  --tenant $AZURE_TENANT_ID
```

### 4. 정상 동작 확인

```bash
# 도구 검사
black --version
ruff --version
mypy --version
pytest --version

# 전체 검사 한 번 돌리기
black --check .
ruff check .
mypy .
pytest
```

---

## 🌿 브랜치 전략

### 브랜치 구조

```
main          ← 배포 브랜치. 직접 push 금지. PR + 리뷰 필수
develop       ← 통합 브랜치. 기능 브랜치는 여기서 분기
feat/*        ← 기능 개발
fix/*         ← 버그 수정
refactor/*    ← 리팩토링
```

### 브랜치 네이밍

```bash
feat/triage-agent-graphrag
feat/sentinel-query-tool
fix/pyrit-connection-timeout
refactor/investigation-agent-async
```

### 작업 흐름

```
develop에서 분기
    ↓
feat/<이름> 에서 개발
    ↓
develop으로 PR
    ↓
CI 통과 + 리뷰 1명 이상 승인
    ↓
develop 머지
    ↓
배포 준비 완료 시 develop → main PR
```

### 보호 규칙 (GitHub Branch Protection)

`main`, `develop` 브랜치에 아래 규칙 적용:

- 직접 push 금지
- PR 머지 전 CI 통과 필수
- 리뷰어 1명 이상 승인 필수
- CodeQL 분석 통과 필수

---

## ✍️ 커밋 컨벤션

```
feat: 새 기능
fix: 버그 수정
refactor: 리팩토링 (동작 변경 없음)
test: 테스트 추가/수정
docs: 문서 수정
chore: 빌드/설정/의존성
```

**예시**
```
feat: TriageAgent GraphRAG 컨텍스트 연동
fix: SentinelQueryTool 타임아웃 처리 추가
test: PyRIT 시나리오 단위 테스트 추가
```

---

## 🛡️ 보안 자동화 (CI/CD)

PR 또는 push 시 아래 검사가 **자동으로** 실행됨.

### 로컬 (커밋 전 — pre-commit)

| 단계 | 도구 | 역할 |
|---|---|---|
| 1 | trailing-whitespace | 후행 공백 제거 |
| 2 | gitleaks | API 키 / 시크릿 커밋 방지 |
| 3 | black | 코드 포맷 통일 |
| 4 | ruff | PEP 8 린트 + 미사용 임포트 |
| 5 | mypy | 타입 힌트 검사 |

### 원격 (PR / push — GitHub Actions)

| 단계 | 도구 | 역할 | 실패 시 |
|---|---|---|---|
| 1 | black / ruff / mypy | 코드 품질 | PR 머지 차단 |
| 2 | pytest | 단위 테스트 | PR 머지 차단 |
| 3 | **CodeQL** | SAST — SQL Injection, 경로 탐색, 인증 우회 등 | PR 머지 차단 |
| 4 | **Dependency Review** | PR에서 새로 추가된 취약 의존성 탐지 | PR 머지 차단 |

### GitHub Advanced Security (GHAS) — 상시 동작

> GHAS 라이선스 필요 (GitHub Enterprise). 레포 Settings → Security에서 활성화.

| 기능 | 역할 |
|---|---|
| **Secret Scanning + Push Protection** | API 키, 토큰 push 자체를 실시간 차단 |
| **Dependabot Alerts** | 의존성 CVE 발견 시 자동 알림 |
| **Dependabot Security Updates** | 취약 의존성 자동 업데이트 PR 생성 |
| **Security Overview** | 전체 레포 보안 현황 대시보드 |

---

## 📐 코딩 컨벤션

상세 규칙 → `.claude/rules/python-conventions.md`

**요약**

- 타입 힌트 필수 (모든 public 함수)
- Google 스타일 독스트링 필수
- `Any` 타입 금지
- `print()` 금지 → `get_logger()` 사용
- 하드코딩 금지 → `pydantic-settings` + `.env`
- `bare except:` 금지

---

## ⚡ 자주 쓰는 명령어

```bash
# 전체 검사
black . && ruff check . && mypy . && pytest

# 특정 Agent만 테스트
pytest tests/__tests__/test_mett_tc_triage.py -v

# 벤치마크 (오프라인 KPI / 레드팀 게이트)
python benchmarks/run_benchmarks.py
python benchmarks/check_gates.py

# 대시보드 로컬 기동
uvicorn app.dashboard:app --reload

# pre-commit 전체 파일 수동 실행
pre-commit run --all-files

# 의존성 취약점 확인
pip-audit

# Claude Code 시작
claude
```

---

## 🗂️ 프로젝트 구조

```
pollack-ai/
├── agents/                  # SOC 에이전트 — BaseSOCAgent 상속, {role}_agent.py
│   ├── graph.py             # LangGraph 파이프라인 배선
│   ├── triage_agent.py      # 트리아지 (METT-TC 임무위험 판정)
│   ├── investigation_agent.py
│   ├── response_agent.py
│   ├── active_hunt_agent.py # opt-in 위협 헌팅
│   └── judges/              # LLM/Signal/Experience Judge 앙상블
├── tools/                   # 외부 연동 — {service}_tool.py
│   ├── sentinel_query_tool.py
│   ├── graph_retriever.py   # GraphRAG 검색
│   ├── mitre_stix_feed.py / cisa_kev_feed.py / atlas_feed.py
│   └── ragas_evaluator.py
├── core/                    # 도메인 모델·분석 모듈 60+ (killchain, ooda, coa,
│                            #  correlation, predictor, prompt_guard, settings ...)
├── app/                     # FastAPI — dashboard / hotpath / learning / health / metrics
├── kb/                      # 지식베이스 (ATT&CK 기법, 사고 사례, 표준)
├── sentinel/                # Sentinel 콘텐츠 (Analytic Rules, Watchlists)
├── benchmarks/              # KPI·레드팀·FP-재발 벤치 + 게이트 검사
├── deploy/                  # Dockerfile, k8s 매니페스트, ArgoCD, 모니터링
├── compliance/              # OSCAL 컴플라이언스 산출물
├── sim_bridge/              # UAV 시뮬레이터(MAVLink) 브리지
├── tests/                   # __tests__/ 구조, 테스트 함수 1,363개
├── docs/                    # 설계 문서, ADR, 데모 런북
├── CLAUDE.md                # Claude Code 프로젝트 규칙
└── pyproject.toml
```

---

## 🐛 이슈 리포트

버그, 오탐/미탐 사례, 개선 제안은 GitHub Issues로:

[GitHub Issues](https://github.com/s1ns3nz0/pollack-ai/issues)

리포트 시 포함할 것:

- 문제 설명 또는 제안 내용
- 재현 절차 (버그의 경우 알림 fixture / 시나리오 포함)
- 기대 동작 vs 실제 동작
- 관련 로그·스크린샷

---

## 📄 라이선스

내부 프로젝트 — 별도 라이선스 미지정. 외부 배포 전 라이선스 결정 필요.
