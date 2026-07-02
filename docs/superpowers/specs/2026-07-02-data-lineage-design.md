# Data Lineage + 재현성 — 방산 컴플라이언스 자동 증거화 (D-1)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-02 |
| 상태 | Approved (브레인스토밍 완료, 구현 단계) |
| 작성자 | s1ns3nz0 |
| 관련 컨트롤 | NIST SP 800-53 AU-2 · AU-3 · CM-8 · SI-4 (감사·구성·모니터링) |
| 후속 | 풀 재현 스크립트, 원격 라인리지 저장소, RAG 쿼리 상세 캡처 |

## 1. 배경 & 동기

방산 SOC 는 **모든 결정의 재현 가능성** 이 요구된다 (감사 추적). 현재 `OscalEvidence`
는 alert/verdict/investigation 만 잡음 — 사용된 *모델 버전 / 정책 버전 / 코드
버전 / 설정* 을 잡지 않아 시간이 지나면 재현 불가.

본 spec 은 **Report 노드가 일괄 수집** 하는 `LineageSnapshot` 을 `OscalEvidence`
에 임베드한다. MVP — 모델/정책/코드 버전 + 타임스태프만.

## 2. 목표 / 비목표

### 2.1 목표
- LLM 모델·프로바이더 기록.
- Policy yaml(severity/asset-tiers/causal-rules) SHA-256 hash 기록.
- Git commit SHA (subprocess, graceful).
- Settings fingerprint (비밀 마스킹 후 SHA-256).
- Ensemble weights (B1 있으면).
- Node latencies 요약 (총합 + 노드당 max).
- Report 노드가 일괄 수집 → `OscalEvidence.lineage` 임베드.
- opt-in (`lineage_enabled`).
- 시크릿 노출 방지 (`SecretStr` 마스킹).

### 2.2 비목표
- 풀 라인리지 (RAG 쿼리 전문 저장).
- 원격 라인리지 서버.
- 재현 스크립트 (별도 후속).
- ADR 자동 링크.
- 코드 커버리지 측정.

## 3. 결정 요약

| # | 결정 | 근거 |
|---|---|---|
| D1 | scope = 모델/정책/코드 + 타임스태프 (MVP) | 방산 컴플라이언스 최소 |
| D2 | 캐프처 = Report 노드 일괄 | node_timings 이미 존재, 단순 |
| D3 | 저장 = `OscalEvidence.lineage` 확장 | 기존 evidence 통로 재사용 |
| D4 | git SHA = subprocess + timeout | Optional, graceful |
| D5 | settings fingerprint = SecretStr 자동 마스킹 후 SHA | 시크릿 노출 방지 |

## 4. Architecture

```text
Report 노드 → build_evidence()
        │
        ├── LineageCollector.snapshot(state)
        │     ├── captured_at (now iso)
        │     ├── code_version (git rev-parse HEAD | "unknown")
        │     ├── llm_provider, llm_model (settings)
        │     ├── policy_hashes: dict[str, str]
        │     ├── settings_fingerprint (SecretStr 마스킹 후 SHA)
        │     ├── ensemble_weights (state.ensemble 있으면)
        │     ├── total_latency_ms (node_timings 합)
        │     └── node_latencies (노드당 max)
        │
        ▼
OscalEvidence.lineage = LineageSnapshot
```

## 5. Components

### 신규
| 경로 | 책임 |
|---|---|
| `core/lineage.py` | `LineageCollector.snapshot()` + 헬퍼(git SHA, policy hash, settings fingerprint) |
| `tests/__tests__/test_lineage.py` | 8 케이스 (snapshot + Report 통합) |

### 수정
| 경로 | 변경 |
|---|---|
| `core/models.py` | 신규 `LineageSnapshot`. `OscalEvidence.lineage: LineageSnapshot \| None = None` |
| `agents/report_agent.py` | 생성자 `lineage: LineageCollector \| None`. run() 에 evidence.lineage 임베드 |
| `agents/graph.py` | `_default_lineage(settings)` factory + `build_soc_graph(lineage=)` |
| `core/settings.py` | `lineage_enabled: bool = False` |

## 6. Data Model

```python
class LineageSnapshot(BaseModel):
    """방산 재현성 라인리지 스냅샷(spec D-1)."""

    captured_at: str
    code_version: str = "unknown"
    llm_provider: str = ""
    llm_model: str = ""
    policy_hashes: dict[str, str] = Field(default_factory=dict)
    settings_fingerprint: str = ""
    ensemble_weights: dict[str, float] = Field(default_factory=dict)
    total_latency_ms: float = Field(default=0.0, ge=0.0)
    node_latencies: dict[str, float] = Field(default_factory=dict)


class OscalEvidence(BaseModel):
    # 기존 ...
    lineage: LineageSnapshot | None = None
```

## 7. LineageCollector

```python
_POLICY_FILES = ("severity-policy.yaml", "asset-tiers.yaml", "causal-rules.yaml")


class LineageCollector:
    def __init__(
        self,
        settings: Settings,
        git_sha_provider: Callable[[], str] | None = None,
    ) -> None:
        self._settings = settings
        self._git_sha_provider = git_sha_provider or _git_sha_default

    def snapshot(self, state: SOCState) -> LineageSnapshot:
        return LineageSnapshot(
            captured_at=_now_iso(),
            code_version=self._git_sha_provider(),
            llm_provider=self._settings.llm_provider,
            llm_model=self._settings.ollama_chat_model,
            policy_hashes=self._policy_hashes(),
            settings_fingerprint=self._settings_fp(),
            ensemble_weights=self._weights(state),
            total_latency_ms=self._total_latency(state),
            node_latencies=self._node_latencies(state),
        )

    def _policy_hashes(self) -> dict[str, str]: ...
    def _settings_fp(self) -> str: ...
    def _weights(self, state: SOCState) -> dict[str, float]: ...
    def _total_latency(self, state: SOCState) -> float: ...
    def _node_latencies(self, state: SOCState) -> dict[str, float]: ...


def _git_sha_default() -> str:
    """subprocess timeout 2초. 실패 시 "unknown"."""
    try:
        import subprocess
        r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=2.0,
        )
        return r.stdout.strip() if r.returncode == 0 else "unknown"
    except Exception:                          # noqa: BLE001 — 어떤 실패든 graceful
        return "unknown"
```

## 8. Report 통합

```python
class ReportAgent:
    def __init__(
        self, settings, engine, reasoner=None, actor_read=None,
        lineage: LineageCollector | None = None,
    ) -> None:
        ...
        self._lineage = lineage

    async def run(self, state):
        # ... 기존 report 조립 ...
        evidence = oscal.build_evidence(state, evidence_level)
        if report.causal_summary is not None:
            evidence.causal_chain = report.causal_summary
        if self._lineage is not None:
            evidence.lineage = self._lineage.snapshot(state)
        return {...}
```

`_default_lineage` factory 는 `lineage_enabled=True` 일 때만 자동 배선.

## 9. 보안 방어

| 위협 | 방어 |
|---|---|
| Settings 에 API 키 포함 → fingerprint 로 노출 | pydantic `SecretStr` 는 `model_dump(mode="json")` 시 `'**********'` 로 자동 마스킹. fingerprint 는 마스킹된 값 해싱 |
| git subprocess hang | `timeout=2.0`, 예외 시 `"unknown"` |
| policy 파일 미존재 | 해당 항목 skip (dict 에 미포함) |
| 대량 node_timings | 노드당 max 만 (총합 별도) — evidence 폭발 방지 |
| 실행 환경 정보 노출 (전체 env) | fingerprint 만 저장 (원본 X) |

## 10. Testing 매트릭스

| 테스트 | 케이스 |
|---|---|
| `test_snapshot_captures_llm_model` | ollama qwen 확인 |
| `test_snapshot_policy_hashes_present` | severity-policy.yaml sha256 존재 |
| `test_snapshot_settings_fingerprint_masks_secrets` | SecretStr 값이 fingerprint 에 노출 안 됨 (동일 마스킹으로 동일 fingerprint) |
| `test_snapshot_git_sha_or_unknown` | provider mock 성공/실패 둘 다 처리 |
| `test_snapshot_total_latency_sums` | node_timings 합계 정확 |
| `test_snapshot_node_latencies_max` | 노드당 max 확인 |
| `test_snapshot_ensemble_weights_optional` | state.ensemble 미존재 → 빈 dict |
| `test_report_lineage_embedded` | Report 통합 — evidence.lineage 채워짐 |
| `test_no_collector_lineage_none` | 미주입 → lineage None |

## 11. Settings

```bash
LINEAGE_ENABLED=false
```

## 12. YAGNI

- ❌ 풀 라인리지 (RAG 쿼리 저장)
- ❌ 원격 라인리지 서버
- ❌ ADR 자동 링크
- ❌ 코드 커버리지 측정
- ❌ 재현 스크립트 (본 spec 은 데이터만)

## 13. 마이그레이션

- `lineage_enabled=False` 디폴트 — 기존 거동 보존
- `OscalEvidence.lineage` Optional — 기존 evidence 파일 호환
- LineageCollector 미주입 시 Report 무영향

## 14. 후속

- 풀 재현 스크립트 (`scripts/reproduce_alert.py`)
- 원격 라인리지 저장 (S3/Azure blob)
- ADR 자동 인용
- 코드 커버리지 게이지

## 15. 참조

- `core/oscal.py:build_evidence` — 확장 지점
- `core/models.py:OscalEvidence` — 확장 대상
- `agents/report_agent.py` — 통합 지점
- NIST SP 800-53 AU/CM/SI 컨트롤
