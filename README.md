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
