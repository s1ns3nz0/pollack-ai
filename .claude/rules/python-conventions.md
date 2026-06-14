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
