# 환경 설정 및 규칙

> Notion 미러 — 자동 추출. 원본: LIG D&A Hackathon

- 하다 보면 아래 내용 바뀔 수도 있음. 아래 내용은 참고로만 활용하며, 깃헙 레포의 [README.md](http://readme.md/) 의 내용을 최우선적으로 반영함
- link_preview: https://github.com/s1ns3nz0/pollack-ai

### 하네스 엔지니어링 참고

[https://github.com/revfactory/harness-100/blob/main/README_ko.md](https://github.com/revfactory/harness-100/blob/main/README_ko.md)
- 지금 레포에 올라가 있는 [CLAUDE.md](http://claude.md/) 파일은 코딩 컨벤션, 시큐어 코딩 관련된 규칙을 정리해서 넣은 부분이므로 하네스 엔지니어링으로 바이브 코딩 시 본인이 쓸 파일(위 하네스100 참고)에 프로젝트의 CLAUDE.md 관련 내용을 반영할 수 있도록 수정이 필요

## 프로젝트 구조

프로젝트 루트/
├── [CLAUDE.md](http://claude.md/)                          ← Claude Code 규칙 (git 커밋 O)
├── pyproject.toml                     ← 의존성 + 도구 설정 (git 커밋 O)
├── .env.example                       ← 환경변수 템플릿 (git 커밋 O)
├── .env                               ← 실제 키값 (git 커밋 X)
├── .gitignore                         ← git 제외 목록 (git 커밋 O)
├── .pre-commit-config.yaml            ← 커밋 전 자동 검사 (git 커밋 O)
└── .claude/
└── rules/
└── [python-conventions.md](http://python-conventions.md/)      ← 상세 컨벤션 (git 커밋 O)

## 온 보딩 순서

cp .env.example .env          # 1. 환경변수 복사 후 값 채우기
pip install -e ".[dev]"       # 2. 의존성 설치
pre-commit install            # 3. git hook 등록 (이후 커밋마다 자동 실행)

### 1. Coding Convention

### 📄 python-conventions.md

# Python 코딩 컨벤션 상세 규칙

PEP 8 / PEP 257 / PEP 484 기반. 이 규칙이 CLAUDE.md보다 우선함.

---

## 1. 타입 힌트 (PEP 484)

### 기본 규칙

```python
# ✅ 올바른 예
async def analyze_alert(
    alert_id: str,
    confidence_threshold: float = 0.8,
    context: dict | None = None,        # Python 3.10+ union 표기
) -> TriageResult:
    ...

# ❌ 금지
def analyze(id, threshold, ctx):        # 타입 힌트 없음
    ...

def process(data: Any) -> Any:          # Any 사용 금지
    ...
```

### 컬렉션 타입

```python
# ✅ Python 3.9+ 내장 타입 사용
def get_alerts() -> list[dict[str, str]]:
    ...

def map_ttp(ttps: list[str]) -> dict[str, list[str]]:
    ...

# ❌ 구식 표기 금지
from typing import List, Dict           # 사용 금지
def get_alerts() -> List[Dict]:
    ...
```

### Unknown + 타입 가드 패턴 (Any 대체)

```python
import json
from typing import TypeGuard

def is_alert_dict(val: object) -> TypeGuard[dict[str, str]]:
    return isinstance(val, dict) and all(isinstance(k, str) for k in val)

def parse_sentinel_response(raw: unknown) -> dict[str, str]:
    data = json.loads(raw)
    if not is_alert_dict(data):
        raise SentinelAPIError(f"예상치 못한 응답 형식: {type(data)}")
    return data
```

---

## 2. 독스트링 (PEP 257 — Google 스타일)

### 멀티라인 (public 함수/클래스 필수)

```python
async def run_pyrit_scenario(
    scenarios: list[PyRITScenario],
    max_iterations: int = 50,
) -> list[FailedTTP]:
    """PyRIT 시나리오를 실행하고 탐지 실패한 TTP를 반환.

    Args:
        scenarios: MITRE TTP 기반으로 생성된 공격 시나리오 목록.
        max_iterations: 비용 제한을 위한 최대 반복 횟수.

    Returns:
        탐지에 실패한 TTP 목록. 빈 리스트면 전부 탐지 성공.

    Raises:
        PyRITConnectionError: PyRIT 오케스트레이터 연결 실패 시.
        IterationLimitError: max_iterations 초과 시.
    """
```

### 한 줄 독스트링 (간단한 내부 함수)

```python
def _to_sigma_filename(ttp_id: str) -> str:
    """TTP ID를 Sigma Rule 파일명으로 변환."""
    return f"detection-rules/{ttp_id.lower()}.yml"
```

### 금지 패턴

```python
# ❌ 독스트링 없는 public 함수
def run_triage(alert_id: str) -> TriageResult:
    result = _call_llm(alert_id)
    return result

# ❌ 의미없는 독스트링
def run_triage(alert_id: str) -> TriageResult:
    """run_triage 함수."""       # 함수명 반복 금지
    ...
```

---

## 3. 임포트

### 순서 (isort 자동 처리)

```python
# 1. 표준 라이브러리
import asyncio
import json
from pathlib import Path
from typing import TypeGuard

# 2. 서드파티
from langchain.tools import BaseTool
from langchain_core.messages import HumanMessage
from langgraph.graph import END, StateGraph
import httpx
from pydantic import BaseModel
from pydantic_settings import BaseSettings

# 3. 로컬 모듈
from agents.base import BaseSOCAgent
from core.exceptions import SentinelAPIError, TriageError
from core.models import AgentState, TriageResult
from tools.sentinel import SentinelQueryTool
```

### 금지

```python
from langchain import *          # 와일드카드 금지
import agents, tools, core       # 한 줄 다중 임포트 금지 (표준 라이브러리 예외)
```

---

## 4. 클래스 구조

### Agent 클래스

```python
from abc import ABC, abstractmethod

class BaseSOCAgent(ABC):
    """모든 SOC Agent의 베이스 클래스."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._logger = get_logger(self.__class__.__name__)

    @abstractmethod
    async def run(self, state: AgentState) -> AgentState:
        """에이전트 메인 실행 로직."""
        ...

class TriageAgent(BaseSOCAgent):
    """알림 트리아지 판정 Agent."""

    async def run(self, state: AgentState) -> AgentState:
        """트리아지 판정 실행.

        Args:
            state: 현재 LangGraph 상태 (alert_id, context 포함).

        Returns:
            판정 결과가 추가된 업데이트된 상태.
        """
        ...
```

### 설정 클래스

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """애플리케이션 전역 설정. 환경변수 또는 .env 파일에서 로드."""

    # Azure OpenAI
    azure_openai_key: str
    azure_openai_endpoint: str
    azure_openai_deployment: str = "gpt-4o"

    # Azure Sentinel
    sentinel_workspace_id: str
    sentinel_resource_group: str

    # PyRIT
    max_pyrit_iterations: int = 50

    # RAGAS
    ragas_faithfulness_threshold: float = 0.8
    ragas_relevancy_threshold: float = 0.8

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# 싱글톤 — 모듈 임포트 시 한 번만 생성
settings = Settings()
```

---

## 5. 예외 처리

### 커스텀 예외 계층

```python
# core/exceptions.py

class SOCPlatformError(Exception):
    """플랫폼 전체 베이스 예외."""

class SentinelAPIError(SOCPlatformError):
    """Azure Sentinel API 연동 오류."""

class TriageError(SOCPlatformError):
    """트리아지 판정 오류."""

class PyRITConnectionError(SOCPlatformError):
    """PyRIT 오케스트레이터 연결 오류."""

class SigmaRuleValidationError(SOCPlatformError):
    """Sigma Rule 검증 실패."""

class GraphRAGQueryError(SOCPlatformError):
    """GraphRAG 쿼리 오류."""
```

### 예외 처리 패턴

```python
# ✅ 구체적인 예외 + 컨텍스트 보존
async def query_sentinel(kql: str) -> list[dict]:
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                url=settings.sentinel_endpoint,
                json={"query": kql},
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException as e:
        raise SentinelAPIError(f"Sentinel 쿼리 타임아웃: {kql[:50]}") from e
    except httpx.HTTPStatusError as e:
        raise SentinelAPIError(
            f"Sentinel HTTP 오류 {e.response.status_code}"
        ) from e

# ❌ 금지
try:
    result = await query_sentinel(kql)
except:                                  # bare except 금지
    pass                                 # 예외 무시 금지

try:
    result = await query_sentinel(kql)
except Exception:
    logger.error("오류 발생")            # 컨텍스트 없는 로깅 금지
```

---

## 6. 비동기 패턴

```python
# ✅ async/await 일관 사용
async def investigate_alert(alert_id: str) -> InvestigationResult:
    # 병렬 실행 가능한 작업은 gather 사용
    history, ti_result, sandbox_result = await asyncio.gather(
        _fetch_alert_history(alert_id),
        _query_threat_intelligence(alert_id),
        _run_sandbox_analysis(alert_id),
    )
    return _merge_results(history, ti_result, sandbox_result)

# ❌ 비동기 컨텍스트에서 동기 블로킹 호출 금지
async def bad_example():
    result = requests.get(url)           # 동기 requests 금지 → httpx 사용
    time.sleep(1)                        # sleep 금지 → asyncio.sleep 사용
```

---

## 7. 로깅

```python
# utils/logging.py
import logging

def get_logger(name: str) -> logging.Logger:
    """표준 로거 반환."""
    return logging.getLogger(f"soc.{name}")

# 사용
class TriageAgent(BaseSOCAgent):
    def __init__(self, settings: Settings) -> None:
        self._logger = get_logger("triage")

    async def run(self, state: AgentState) -> AgentState:
        self._logger.info("트리아지 시작: alert_id=%s", state.alert_id)

        # ❌ print 금지
        # print(f"트리아지 시작: {state.alert_id}")

        # ✅ 구조화된 로깅 (보안: 민감 데이터 마스킹)
        self._logger.debug(
            "LLM 호출: model=%s, tokens=%d",
            self._settings.azure_openai_deployment,
            token_count,
        )
```

---

## 8. 테스트 규칙

```python
# tests/__tests__/test_triage_agent.py
import pytest
from unittest.mock import AsyncMock, patch

class TestTriageAgent:
    """TriageAgent 단위 테스트."""

    @pytest.fixture
    def agent(self, mock_settings: Settings) -> TriageAgent:
        return TriageAgent(settings=mock_settings)

    @pytest.mark.asyncio
    async def test_run_returns_triage_result(
        self,
        agent: TriageAgent,
        sample_alert_state: AgentState,
    ) -> None:
        """정상 알림 처리 시 TriageResult 반환 확인."""
        with patch.object(agent, "_call_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = sample_llm_response()

            result = await agent.run(sample_alert_state)

            assert result.triage_result is not None
            assert result.triage_result.confidence >= 0.0
            mock_llm.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_sentinel_error_raises_triage_error(
        self,
        agent: TriageAgent,
        sample_alert_state: AgentState,
    ) -> None:
        """Sentinel 오류 시 TriageError 발생 확인."""
        with patch.object(agent, "_query_sentinel", side_effect=SentinelAPIError("연결 실패")):
            with pytest.raises(TriageError):
                await agent.run(sample_alert_state)
```

**테스트 원칙:**
- 파일 위치: 소스와 동일 경로의 `__tests__/` 폴더
- 함수명: `test_{상황}_{기대결과}` 패턴
- 외부 API는 반드시 mock 처리
- LLM 호출 테스트 시 실제 Azure OpenAI 호출 금지

### 📄 CLAUDE.md

# UAV AI SOC Platform — Claude Code 설정

## 프로젝트 개요

방산 UAV 보안 SaaS 플랫폼. LangGraph 기반 멀티 에이전트 + Azure Sentinel 연동 AI SOC 시스템.
**핵심 기술 스택:** Python 3.11+, LangGraph, Azure OpenAI, Azure Sentinel, GraphRAG, kagent (AKS)

---

## 코딩 컨벤션 (상세 규칙 → `.claude/rules/python-conventions.md`)

### 네이밍

- 함수/변수: `snake_case` | 클래스: `PascalCase` | 상수: `UPPER_SNAKE_CASE`
- 약어 클래스는 대문자 유지: `SOCAgent`, `UAVTriageAgent`
- 파일명: `{role}_agent.py`, `{service}_tool.py`

### 타입 힌트 & 독스트링

- 모든 public 함수/메서드에 타입 힌트 **필수**
- Google 스타일 독스트링 **필수** (Args / Returns / Raises)
- `Any` 타입 사용 금지 → `Unknown` + 타입 가드 사용

### 포매팅

- 들여쓰기: 공백 4칸 (탭 금지)
- 최대 줄 길이: 88자 (black 기본값)
- 문자열: 큰따옴표 통일
- f-string 권장, `%` 포맷 금지

### 임포트 순서 (isort)

1. 표준 라이브러리
1. 서드파티 (langchain, langgraph, httpx ...)
1. 로컬 모듈
와일드카드 임포트 금지 (`from x import *`)

---

## 프로젝트 구조 규칙

```
agents/          # {role}_agent.py — BaseSOCAgent 상속 필수
tools/           # {service}_tool.py — BaseTool 상속 필수
core/            # 공유 모델, 상태, 예외 클래스
prompts/         # {role}_v{n}.yaml — 버전 관리
tests/           # 소스 파일과 동일 경로에 __tests__/
```

---

## 보안 규칙 (절대 금지)

- **하드코딩 금지:** API 키, 엔드포인트, 시크릿 → 반드시 `pydantic-settings` + `.env`
- **`print()`**** 금지:** 로깅은 `get_logger()` 사용
- **bare ****`except:`**** 금지:** 반드시 구체적인 예외 타입 명시
- **미검증 외부 입력 금지:** Sentinel/TI API 응답은 반드시 파싱 후 검증

---

## 자동화 도구

코드 작성 후 반드시 순서대로 실행:

```bash
black .          # 포매터
ruff check .     # 린터
mypy .           # 타입 검사
pytest           # 테스트
```

pre-commit이 설정되어 있으면 커밋 전 자동 실행됨.

---

## Agent 작성 규칙

```python
# 모든 Agent는 이 구조를 따를 것
class FooAgent(BaseSOCAgent):
    """한 줄 설명."""

    async def run(self, state: AgentState) -> AgentState:
        """실행 로직. Args/Returns 독스트링 필수."""
        ...
```

- `async/await` 일관 사용 (동기 함수 혼용 금지)
- 커스텀 예외는 `SOCPlatformError` 하위로 정의
- LLM 호출은 반드시 `try/except` 래핑

---

## Git 커밋 규칙

```
feat: 새 기능
fix: 버그 수정
refactor: 리팩토링
test: 테스트 추가/수정
docs: 문서
chore: 빌드/설정
```

브랜치명: `feat/<역할>-<설명>` (예: `feat/triage-agent-graphrag`)

---

## 참조

- 상세 Python 컨벤션 → `.claude/rules/python-conventions.md`
- 아키텍처 결정 기록 → `docs/adr/`
- 환경변수 목록 → `.env.example`
[python-conventions.md](http://python-conventions.md/) 파일 기준으로 코딩할 때 저 규칙대로 설정, [CLAUDE.md](http://claude.md/) 파일은 저 코딩 컨벤션을 하네스 엔지니어링할 때 사용할만한 파일 예시

### 2. pyproject.toml

```javascript
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

# ─────────────────────────────────────────
# 프로젝트 메타데이터
# ─────────────────────────────────────────
[project]
name = "uav-soc-platform"
version = "0.1.0"
description = "방산 UAV 보안 SaaS 플랫폼 — LangGraph 기반 AI SOC"
requires-python = ">=3.11"

dependencies = [
    # LangGraph / LangChain
    "langgraph>=0.2.0",
    "langchain>=0.3.0",
    "langchain-openai>=0.2.0",

    # Azure
    "azure-identity>=1.17.0",
    "azure-monitor-query>=1.4.0",

    # HTTP / 비동기
    "httpx>=0.27.0",

    # 설정 관리
    "pydantic>=2.7.0",
    "pydantic-settings>=2.3.0",

    # 그래프 RAG
    "graphrag>=0.3.0",
]

[project.optional-dependencies]
dev = [
    "black>=24.0.0",
    "ruff>=0.4.0",
    "mypy>=1.10.0",
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "pre-commit>=3.7.0",
]
eval = [
    "ragas>=0.1.0",
    "pyrit>=0.4.0",
]

# ─────────────────────────────────────────
# black — 포매터
# ─────────────────────────────────────────
[tool.black]
line-length = 88
target-version = ["py311"]
# 큰따옴표 통일 (기본값)

# ─────────────────────────────────────────
# ruff — 린터 + isort
# ─────────────────────────────────────────
[tool.ruff]
line-length = 88
target-version = "py311"

[tool.ruff.lint]
select = [
    "E",   # pycodestyle 오류
    "W",   # pycodestyle 경고
    "F",   # pyflakes (미사용 임포트 등)
    "I",   # isort (임포트 순서)
    "B",   # flake8-bugbear (잠재적 버그)
    "UP",  # pyupgrade (구식 문법 자동 업그레이드)
    "S",   # flake8-bandit (보안 이슈)
    "ANN", # flake8-annotations (타입 힌트 누락)
]
ignore = [
    "ANN101", # self 타입 힌트 생략 허용
    "ANN102", # cls 타입 힌트 생략 허용
    "S101",   # assert 허용 (테스트 코드)
]

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["ANN", "S"]   # 테스트 파일은 타입힌트·보안 룰 완화
"scripts/**" = ["ANN", "S"]

[tool.ruff.lint.isort]
known-first-party = ["agents", "tools", "core", "utils"]
force-sort-within-sections = true

# ─────────────────────────────────────────
# mypy — 타입 검사
# ─────────────────────────────────────────
[tool.mypy]
python_version = "3.11"
strict = true                    # 모든 strict 옵션 활성화

# strict 세부 항목 (strict = true 와 동일하지만 명시)
disallow_any_generics = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_return_any = true

# 서드파티 타입 스텁 없는 패키지 허용
[[tool.mypy.overrides]]
module = [
    "graphrag.*",
    "pyrit.*",
    "ragas.*",
]
ignore_missing_imports = true

# ─────────────────────────────────────────
# pytest
# ─────────────────────────────────────────
[tool.pytest.ini_options]
asyncio_mode = "auto"            # pytest-asyncio 자동 모드
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = [
    "--strict-markers",
    "-v",
]
```

### 3. gitignore

```javascript
# ─────────────────────────────────────────
# UAV AI SOC Platform — .gitignore
# ─────────────────────────────────────────

# ── 보안 (절대 커밋 금지) ─────────────────
.env
.env.local
.env.*.local
*.pem
*.key
*.p12
*.pfx

# ── Python ────────────────────────────────
__pycache__/
*.py[cod]
*.pyo
*.pyd
.Python
*.egg-info/
dist/
build/
*.egg
.eggs/

# ── 가상환경 ──────────────────────────────
.venv/
venv/
env/
ENV/

# ── 테스트 / 커버리지 ─────────────────────
.pytest_cache/
.coverage
coverage.xml
htmlcov/

# ── mypy ──────────────────────────────────
.mypy_cache/
.dmypy.json

# ── ruff ──────────────────────────────────
.ruff_cache/

# ── IDE ───────────────────────────────────
.vscode/
.idea/
*.swp
*.swo
.DS_Store

# ── GraphRAG 출력물 ───────────────────────
output/
graphrag/cache/
graphrag/output/

# ── PyRIT 결과 (민감 데이터 포함 가능) ────
pyrit_results/
*.pyrit

# ── 로그 ──────────────────────────────────
*.log
logs/

# ── 기타 ──────────────────────────────────
*.tmp
*.bak
```

### 4. precommit config

```javascript
# ─────────────────────────────────────────
# UAV AI SOC Platform — pre-commit 설정
# ─────────────────────────────────────────
# 설치: pre-commit install
# 수동 실행: pre-commit run --all-files
# ─────────────────────────────────────────

repos:
  # ── 기본 검사 ───────────────────────────
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace        # 후행 공백 제거
      - id: end-of-file-fixer          # 파일 끝 개행 보장
      - id: check-yaml                 # YAML 문법 검사 (Sigma Rules 포함)
      - id: check-toml                 # TOML 문법 검사
      - id: check-json                 # JSON 문법 검사
      - id: check-merge-conflict       # 머지 충돌 마커 검사
      - id: detect-private-key         # 개인키 커밋 방지
      - id: check-added-large-files    # 대용량 파일 커밋 방지
        args: ["--maxkb=1000"]

  # ── 보안: 시크릿 탐지 ───────────────────
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks                   # API 키, 토큰 커밋 방지

  # ── black — 포매터 ──────────────────────
  - repo: https://github.com/psf/black
    rev: 24.4.2
    hooks:
      - id: black
        language_version: python3.11

  # ── ruff — 린터 + isort ─────────────────
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.9
    hooks:
      - id: ruff
        args: ["--fix"]                # 자동 수정 가능한 건 자동 수정
      - id: ruff-format

  # ── mypy — 타입 검사 ────────────────────
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        additional_dependencies:
          - pydantic>=2.7.0
          - pydantic-settings>=2.3.0
          - types-httpx
```

### 5. .env.example

```javascript
# ─────────────────────────────────────────
# UAV AI SOC Platform — 환경변수 템플릿
# ─────────────────────────────────────────
# 이 파일을 복사해서 .env로 만들고 실제 값을 채워넣을 것
# cp .env.example .env
#
# ❌ .env는 절대 git에 커밋하지 말 것 (.gitignore에 포함됨)
# ✅ 이 파일(.env.example)은 git에 커밋해도 됨 (실제 값 없음)
# ─────────────────────────────────────────

# ── Azure OpenAI ──────────────────────────
AZURE_OPENAI_KEY=
AZURE_OPENAI_ENDPOINT=https://<your-resource>.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_API_VERSION=2024-02-01

# ── Azure Sentinel ────────────────────────
SENTINEL_WORKSPACE_ID=
SENTINEL_RESOURCE_GROUP=
SENTINEL_SUBSCRIPTION_ID=
SENTINEL_TENANT_ID=

# ── Azure 인증 (Service Principal) ────────
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_TENANT_ID=

# ── GraphRAG ──────────────────────────────
GRAPHRAG_STORAGE_ACCOUNT=
GRAPHRAG_CONTAINER_NAME=uav-knowledge-base

# ── PyRIT (Red Teaming) ───────────────────
MAX_PYRIT_ITERATIONS=50

# ── RAGAS (평가) ──────────────────────────
RAGAS_FAITHFULNESS_THRESHOLD=0.8
RAGAS_RELEVANCY_THRESHOLD=0.8
RAGAS_CONTEXT_PRECISION_THRESHOLD=0.8

# ── 로깅 ──────────────────────────────────
LOG_LEVEL=INFO

```
