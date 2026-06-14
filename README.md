# UAV AI SOC Platform

방산 UAV 보안 SaaS 플랫폼 — LangGraph 기반 멀티 에이전트 AI SOC 시스템

---

## 기술 스택

| 영역 | 기술 |
|---|---|
| AI Agent | LangGraph, LangChain, Azure OpenAI (GPT-4o) |
| 보안 분석 | Azure Sentinel, GraphRAG |
| Red Teaming | PyRIT, RAGAS |
| 언어 | Python 3.11+ |

---

## 온보딩 — 처음 세팅하는 경우

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

---

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

---

### 3. Azure 인증 세팅

```bash
# Service Principal로 인증
az login --service-principal \
  --username $AZURE_CLIENT_ID \
  --password $AZURE_CLIENT_SECRET \
  --tenant $AZURE_TENANT_ID

```

---

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

## 브랜치 전략

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

## 커밋 컨벤션

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

## 보안 자동화 (CI/CD)

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

## 코딩 컨벤션

상세 규칙 → `.claude/rules/python-conventions.md`

**요약**
- 타입 힌트 필수 (모든 public 함수)
- Google 스타일 독스트링 필수
- `Any` 타입 금지
- `print()` 금지 → `get_logger()` 사용
- 하드코딩 금지 → `pydantic-settings` + `.env`
- `bare except:` 금지

---

## 자주 쓰는 명령어

```bash
# 전체 검사
black . && ruff check . && mypy . && pytest

# 특정 Agent만 테스트
pytest tests/__tests__/test_triage_agent.py -v

# pre-commit 전체 파일 수동 실행
pre-commit run --all-files

# 의존성 취약점 확인
pip-audit

# Claude Code 시작
claude
```

---

## 프로젝트 구조

```
pollack-ai/
├── agents/                  # {role}_agent.py
│   ├── base.py              # BaseSOCAgent
│   ├── triage_agent.py
│   ├── investigation_agent.py
│   └── response_agent.py
├── tools/                   # {service}_tool.py
│   ├── sentinel_tool.py
│   ├── ti_tool.py
│   ├── sandbox_tool.py
│   └── graphrag_tool.py
├── core/
│   ├── models.py            # AgentState, TriageResult 등
│   ├── exceptions.py        # 커스텀 예외 계층
│   └── settings.py          # pydantic-settings
├── prompts/                 # {role}_v{n}.yaml
├── tests/
│   └── __tests__/
├── .github/
│   └── workflows/
│       └── ci.yml
├── .claude/
│   └── rules/
│       └── python-conventions.md
├── CLAUDE.md
├── pyproject.toml
├── .env.example
├── .gitignore
└── .pre-commit-config.yaml
```
