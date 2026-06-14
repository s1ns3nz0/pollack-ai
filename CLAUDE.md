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
2. 서드파티 (langchain, langgraph, httpx ...)
3. 로컬 모듈

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
- **`print()` 금지:** 로깅은 `get_logger()` 사용
- **bare `except:` 금지:** 반드시 구체적인 예외 타입 명시
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
