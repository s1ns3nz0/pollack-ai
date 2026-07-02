# Auto KQL Rule Suggester — 신규 technique → KQL draft PR (A-2)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-02 |
| 상태 | Approved (브레인스토밍 완료, 구현 단계) |
| 작성자 | s1ns3nz0 |
| 자매 spec | T1 Threat Landscape Agent, A-1 OutcomeProbe |
| 후속 | learning.py 자동 통합, Sigma 룰 병행 생성, 룰 성능 검증 |

## 1. 배경 & 동기

T1 (`ThreatLandscapeAgent`) 이 ATT&CK/ATLAS 신규 technique 을 자동 감지·적재한다.
하지만 *탐지 룰* 은 여전히 수동 작성. 본선 자동화 점수를 위해:

- 신규 technique → LLM 이 KQL draft → `dah-sentinel-content` PR (운영자 검토 후 머지).
- 자동 머지 없음 — LLM 인젝션 표면 차단 위해 항상 사람 검토.
- KQL 문법 스켈레톤 + 위험 함수 블랙리스트로 최소 검증.

## 2. 목표 / 비목표

### 2.1 목표
- `AutoKqlRuleAgent(BaseWorkerAgent)` — 신규 technique 목록을 받아 KQL draft PR 생성.
- `KqlValidator` — 최소 문법 스켈레톤 + 위험 함수 블랙리스트 (external_table/http_get 등).
- LLM 응답 파싱 = 정규식 코드블록 추출 (structured JSON schema 미의존).
- `RulePublisher` 재사용 — `RulePullRequest` 페이로드 형식.
- 사이클당 상한 `max_techniques` (spam 방지).
- 자동 머지 없음 — 항상 PR 검토 필수.

### 2.2 비목표
- 자동 머지.
- 룰 성능 검증 (dry-run in test workspace).
- 다중 LLM ensemble.
- Sigma 룰 병행 생성.
- learning.py 자동 통합 (본 spec 은 agent + validator 만; 호출자 명시 호출).

## 3. 결정 요약

| # | 결정 | 근거 |
|---|---|---|
| D1 | 별도 `AutoKqlRuleAgent` (T1 확장 X) | 실패 격리, 재사용, T1 무영향 |
| D2 | 입력 = T1 `LandscapeDiff.added` 목록 | T1 결과 활용, 명시 파라미터 |
| D3 | LLM 프롬프트 = 결정론 + 코드블록 파싱 | JSON schema 라이브러리 회귀 표면 제거 |
| D4 | 검증 = 화이트리스트 스켈레톤 + 위험 함수 블랙리스트 | LLM 인젝션 → 악성 KQL 삽입 차단 |
| D5 | PR 저장 = `Analytics/{tid}.kql` | `dah-sentinel-content` 컨벤션 (assumption) |
| D6 | 자동 머지 X — 항상 사람 검토 | 방산 원칙, KQL 회귀 위험 |

## 4. Architecture

```text
[T1 사이클 완료 → LandscapeDiff.added]
        │  list[str]  신규 technique IDs
        ▼
AutoKqlRuleAgent.run_for(added_techs)
        │
        ├── 각 technique 별:
        │     LLM.acomplete(_SYS, _user(tid))
        │     → parse_kql (```kql ... ``` 코드블록 추출)
        │     → KqlValidator.check (스켈레톤 + 블랙리스트)
        │     → 실패 시 skip + errors 기록
        │     → 성공 시 RulePullRequest 페이로드 빌드
        │
        └── RulePublisher.apublish (미주입 시 proposed)
        │
        ▼
WorkerReport(auto_applied, pr_urls, errors)
```

## 5. Components

### 신규
| 경로 | 책임 |
|---|---|
| `core/kql_validator.py` | 최소 KQL 문법 스켈레톤 + 위험 함수 블랙리스트 |
| `agents/auto_kql_rule_agent.py` | `AutoKqlRuleAgent(BaseWorkerAgent)` + `parse_kql` 헬퍼 |
| `tests/__tests__/test_auto_kql_rule.py` | validator 8 + agent 5 |

### 수정
| 경로 | 변경 |
|---|---|
| `core/settings.py` | `auto_kql_enabled: bool = False`, `auto_kql_max_techniques: int = 5` |

## 6. KQL Validator

```python
_BLOCKED_FNS = frozenset({
    "external_table", "externaldata", "http_get", "http_request",
    "invoke_", "cluster(", "database(",
})


class KqlValidator:
    """최소 KQL 스켈레톤 + 위험 함수 블랙리스트 검증."""

    def __init__(self, max_length: int = 8000) -> None:
        self._max_length = max_length

    def check(self, kql: str) -> tuple[bool, str]:
        text = kql.strip()
        if not text:
            return False, "empty"
        if len(text) > self._max_length:
            return False, "too_long"
        if "|" not in text:
            return False, "no_pipe"
        low = text.lower()
        for fn in _BLOCKED_FNS:
            if fn in low:
                return False, f"blocked_fn: {fn}"
        return True, "ok"
```

## 7. LLM 프롬프트

```python
_SYS = (
    "당신은 Azure Sentinel KQL 룰 저자다. 주어진 MITRE ATT&CK technique 에"
    " 매칭되는 KQL 탐지 룰 draft 를 작성하라. 반드시 아래 형식만 출력:\n"
    "```kql\n<KQL 룰 본문>\n```\n"
    "external_table/externaldata/http_get 함수 사용 금지."
    " SecurityEvent · Syslog · SigninLogs 등 표준 테이블만 참조."
)

_RE = re.compile(r"```(?:kql)?\s*\n(.*?)\n```", re.DOTALL)


def parse_kql(text: str) -> str | None:
    m = _RE.search(text)
    return m.group(1).strip() if m else None
```

## 8. AutoKqlRuleAgent

```python
class AutoKqlRuleAgent(BaseWorkerAgent):
    def __init__(
        self,
        settings: Settings,
        llm: LLMClient,
        validator: KqlValidator | None = None,
        publisher: RulePublisher | None = None,
        max_techniques: int | None = None,
    ) -> None: ...

    async def run(self) -> WorkerReport:
        """no-op — 호출자가 run_for(added_techs) 를 직접 사용."""
        return WorkerReport(cycle_at=_now_iso())

    async def run_for(self, added_techs: list[str]) -> WorkerReport:
        applied = 0
        errors: list[str] = []
        pr_urls: list[str] = []
        for tid in added_techs[: self._max_techniques]:
            raw = await self._call_llm(tid, errors)
            if raw is None:
                continue
            kql = parse_kql(raw)
            if kql is None:
                errors.append(f"{tid} 파싱 실패")
                continue
            ok, reason = self._validator.check(kql)
            if not ok:
                errors.append(f"{tid} 검증 실패: {reason}")
                continue
            pr = self._build_pr(tid, kql)
            if self._publisher is not None:
                try:
                    pr = await self._publisher.apublish(pr)
                    if pr.url:
                        pr_urls.append(pr.url)
                except SOCPlatformError as exc:
                    errors.append(f"{tid} PR 실패: {exc}")
                    continue
            applied += 1
        return WorkerReport(
            cycle_at=_now_iso(),
            auto_applied=applied,
            pr_urls=pr_urls,
            errors=errors,
        )
```

## 9. 인젝션 방어

| 위협 | 방어 |
|---|---|
| LLM 이 악성 KQL 삽입 (external_table 데이터 유출) | KqlValidator 블랙리스트 |
| LLM 이 코드블록 밖 텍스트 삽입 | 정규식 파싱 — 코드블록만 |
| 대량 PR 폭주 | `max_techniques` 상한 |
| KQL 문법 완전 붕괴 | 최소 pipe 검증 |
| PR 자동 머지 | X — 항상 사람 검토 (본 spec 원칙) |
| PR body 인젝션 | body 는 정형 템플릿 + KQL 만 삽입 (직접 사용자 입력 X) |

## 10. Error Handling

| 시나리오 | 처리 |
|---|---|
| LLM 미주입 | 생성자 검증 → LLM 필수 |
| LLM 호출 실패 | errors 기록, 다음 technique 계속 |
| 파싱 실패 | errors 기록, skip |
| Validator 거부 | errors 기록, skip |
| PR 발행 실패 | errors 기록, skip |

## 11. Testing 매트릭스

| 테스트 | 케이스 |
|---|---|
| `test_parse_kql_valid_block` | 정상 ```kql``` 코드블록 추출 |
| `test_parse_kql_no_block_returns_none` | 코드블록 없음 → None |
| `test_validator_accepts_minimal` | `SecurityEvent \| where ...` → OK |
| `test_validator_rejects_empty` | `""` → empty |
| `test_validator_rejects_too_long` | length 초과 → too_long |
| `test_validator_rejects_no_pipe` | pipe 없음 → no_pipe |
| `test_validator_rejects_external_table` | `external_table(...)` → blocked_fn |
| `test_validator_rejects_httpget` | `http_get(...)` → blocked_fn |
| `test_agent_processes_techniques` | mock LLM 3 tech → 3 PR |
| `test_agent_respects_max_techniques` | 10 tech + max=3 → 3만 처리 |
| `test_agent_llm_failure_records_error_continues` | 예외 → errors, 나머지 계속 |
| `test_agent_validation_failure_skips` | 블랙리스트 → skip, errors |
| `test_agent_publisher_none_proposed` | publisher 미주입 → pr_urls 빈 목록 (applied 만 증가) |

## 12. Settings

```bash
AUTO_KQL_ENABLED=false
AUTO_KQL_MAX_TECHNIQUES=5
```

## 13. YAGNI

- ❌ 자동 머지
- ❌ 룰 성능 예측 / dry-run
- ❌ 다중 LLM ensemble
- ❌ Structured JSON schema
- ❌ Sigma 룰 병행
- ❌ learning.py 자동 통합 (호출자 명시)

## 14. 마이그레이션

- `auto_kql_enabled=False` 디폴트 — agent 자동 배선 skip
- 신규 파일 추가 + settings 확장만
- 기존 코드 무영향

## 15. 후속

- `learning.py` 통합 (T1 사이클 → `run_for(diff.added)` 자동 호출)
- Sigma 룰 병행 생성
- 룰 성능 검증 (test workspace 에 dry-run)
- 다중 LLM ensemble

## 16. 참조

- `tools/graph_yaml_patch.py:GraphYamlPatchTool.compute_diff` — LandscapeDiff 원천
- `tools/rule_publisher.py:RulePublisher` — PR 발행 계약
- `agents/base.py:BaseWorkerAgent` — 사이클 패턴
- `agents/threat_landscape_agent.py` — 유사 BaseWorkerAgent 사례
