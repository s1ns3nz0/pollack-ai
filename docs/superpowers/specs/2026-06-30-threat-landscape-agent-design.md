# Threat Landscape Agent — 위협 피드 지속 반영 + Graph yaml 자동 관리

| 항목 | 값 |
|---|---|
| 작성일 | 2026-06-30 |
| 상태 | Approved (브레인스토밍 완료, 구현 계획 작성 단계) |
| 작성자 | s1ns3nz0 |
| 자매 spec | #1 Airspace/GNSS, #2 Attacker Profile, B1 Multi-Judge, D1 RAGAS, C1 Sequence Pred, A1 Causal |
| 후속 | 자동 시나리오/KQL 후보 생성, 방산 특화 피드 통합, 회귀 게이트 자동 머지 |

## 1. 배경 & 동기

- `data/mitre_attack_graph.yaml` 정적 — 신규 ATT&CK technique 반영 수동
- `tools/coverage.py` 정적 — 갭 자동 감지 X
- ATT&CK / ATLAS / EMB3D / CISA KEV 갱신 운영 부담 + 누락 위험
- 본선 AI 공방전 — ATLAS 기법 빈번히 갱신 (AI 위협 진화 속도 빠름)

→ **위협 인텔리전스 *적재 자동화*** 가 필요. Deployment B 의 새 사이클로 도입.

## 2. 목표 / 비목표

### 2.1 목표
- ATT&CK / ATLAS / EMB3D / CISA KEV 4 피드를 *주기* 가져옴 (디폴트 1d).
- `data/mitre_attack_graph.yaml` 와 비교 → diff 생성.
- **신규 추가는 자동 패치**, **변경·삭제는 PR 검토** (회귀 위험 차단).
- KEV 신규 CVE → `vuln_tool` 캐시 무효화 신호.
- 갱신 후 `coverage.py` 재계산 + Prometheus 게이지 갱신.
- 한 피드 장애가 다른 피드/사이클을 막지 않음.

### 2.2 비목표
- 피드 자체 서명 검증 (HTTPS 만 — 피드에 서명 없음).
- 자동 시나리오 생성 (갭 → 시나리오 후보).
- 자동 KQL 룰 생성 (사람 검토 필요).
- 자동 PR 머지 (회귀 게이트 통과 무관, 항상 사람 검토).
- 실시간 갱신 (24h 만).
- `SeverityEngine` / `signal_judge` / `severity-policy.yaml` 자동 변경.

## 3. 결정 요약 (브레인스토밍 결과)

| # | 결정 | 근거 |
|---|---|---|
| D1 | Deployment B (learning worker) 새 사이클 | 핫패스 영향 0, ADR 0002 D6 일치 |
| D2 | 피드 4종 (ATT&CK + ATLAS + EMB3D + KEV) | 본선 + UAV 도메인 + CVE 보강 |
| D3 | 신규 추가 자동 / 변경·삭제 PR | 누락 위험 ↓ + 회귀 위험 ↓ |
| D4 | 주기 1d (cron) | 외부 피드 release 주기와 일치 |
| D5 | 신규 `BaseWorkerAgent` | `BaseSOCAgent.run(state)` 시그너처와 분리 — alert 무관 |

## 4. Architecture

```text
Deployment B (learning worker, 1d cron)
   │
   ▼
ThreatLandscapeAgent.run() — BaseWorkerAgent 패턴
   │
   ├── MitreStixFeedTool   ─ ATT&CK STIX/TAXII
   ├── AtlasFeedTool       ─ MITRE ATLAS raw yaml
   ├── Embed3dFeedTool     ─ MITRE EMB3D yaml
   └── CisaKevFeedTool     ─ CISA KEV JSON
   │
   ▼
LandscapeDiff = 현재 yaml vs 최신 피드
   │
   ├── added            → graph yaml / atlas yaml 자동 패치
   ├── changed/removed  → GraphYamlPatchTool 가 PR 발행 (RulePublisher 재사용)
   └── kev_new          → vuln_tool 캐시 무효화 (다음 alert 부터 신선)
   │
   ▼
coverage.py 재계산 → Prometheus 게이지 갱신
   │
   ▼
WorkerReport (적립 + Grafana 표시 + 운영자 알림)
```

## 5. Components

### 5.1 신규
| 경로 | 책임 |
|---|---|
| `agents/base.py` | `BaseWorkerAgent` 추가 — `async run() -> WorkerReport` |
| `agents/threat_landscape_agent.py` | `ThreatLandscapeAgent(BaseWorkerAgent)` |
| `tools/feed_base.py` | `FeedTool` Protocol + 공통 HTTP 헬퍼(`fetch_with_retry`) |
| `tools/mitre_stix_feed.py` | ATT&CK STIX/TAXII 2.1 (`mitreattack-python` 가능 시, 아니면 raw STIX json) |
| `tools/atlas_feed.py` | github raw `mitre-atlas/atlas-data` yaml |
| `tools/embed3d_feed.py` | github raw `mitre/emb3d` yaml |
| `tools/cisa_kev_feed.py` | CISA KEV JSON `known_exploited_vulnerabilities.json` |
| `tools/graph_yaml_patch.py` | `mitre_attack_graph.yaml` diff/patch + PR 페이로드 빌드 (`RulePublisher` 와 한 패키지) |
| `tests/__tests__/test_feed_base.py` | retry / TLS / hash |
| `tests/__tests__/test_mitre_stix_feed.py` | STIX mock → technique 파싱 |
| `tests/__tests__/test_atlas_feed.py` | yaml mock |
| `tests/__tests__/test_embed3d_feed.py` | yaml mock |
| `tests/__tests__/test_cisa_kev_feed.py` | JSON mock |
| `tests/__tests__/test_graph_yaml_patch.py` | added 자동 / changed PR / 100건 상한 |
| `tests/__tests__/test_threat_landscape_agent.py` | end-to-end 4 feed mock + 부분 장애 |

### 5.2 수정
| 경로 | 변경 |
|---|---|
| `core/models.py` | 신규 `FeedSnapshot`, `LandscapeDiff`, `WorkerReport` |
| `app/learning.py` | `run_cycle` 에 `threat_landscape` 단계 추가 + `_should_refresh()` 게이트 |
| `tools/coverage.py` | `CoverageMatrix.reload()` 클래스 메서드 추가 (yaml 재로드) |
| `app/metrics.py` | "ATT&CK 커버리지 증감" 게이지 갱신 hook |
| `core/settings.py` | `feed_refresh_hours: int = 24`, 4개 endpoint URL, `feed_user_agent`, `feed_added_cap: int = 100`, `sentinel_content_repo` 재사용 |
| `pyproject.toml` | 선택 의존 `mitreattack-python` (또는 `taxii2-client` + `stix2`) — `feeds` extra |
| `deploy/monitoring/grafana-dashboard.yaml` | 패널 "ATT&CK 커버리지 변화" + "KEV 신규 카운터" |

## 6. Data Model

```python
class FeedSnapshot(BaseModel):
    source: Literal["attack", "atlas", "embed3d", "kev"]
    version: str                              # 피드 자체 version 또는 fetched_at
    techniques: list[str] = Field(default_factory=list)   # T-id 목록
    cves: list[str] = Field(default_factory=list)         # KEV 만 비어있지 않음
    fetched_at: str                           # ISO8601
    raw_hash: str                             # SHA-256 — 변경 추적

class LandscapeDiff(BaseModel):
    source: str
    added: list[str] = Field(default_factory=list)
    changed: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    kev_new: list[str] = Field(default_factory=list)

class WorkerReport(BaseModel):
    cycle_at: str
    diffs: list[LandscapeDiff]
    auto_applied: int
    pr_urls: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
```

## 7. BaseWorkerAgent

```python
# agents/base.py
class BaseWorkerAgent(ABC):
    """Deployment B (learning worker) 사이클 노드의 공통 베이스.

    `BaseSOCAgent` 와 분리한다 — alert state 무관, 주기 트리거.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._logger = get_logger(self.__class__.__name__)

    @abstractmethod
    async def run(self) -> WorkerReport:
        """주기 실행. 사이클 결과를 보고서로 반환."""
        ...
```

## 8. ThreatLandscapeAgent 로직

```python
class ThreatLandscapeAgent(BaseWorkerAgent):
    def __init__(self, settings, feeds: list[FeedTool],
                 patcher: GraphYamlPatchTool,
                 publisher: RulePublisher | None = None,
                 vuln_cache_invalidator: Callable[[list[str]], Coroutine] | None = None,
                 added_cap: int = 100) -> None:
        super().__init__(settings)
        self._feeds = feeds
        self._patcher = patcher
        self._publisher = publisher
        self._invalidate = vuln_cache_invalidator
        self._added_cap = added_cap

    async def run(self) -> WorkerReport:
        diffs: list[LandscapeDiff] = []
        errors: list[str] = []
        for feed in self._feeds:
            try:
                snap = await feed.afetch()
                diff = self._patcher.compute_diff(snap)
                diffs.append(diff)
            except SOCPlatformError as exc:
                errors.append(f"{feed.source}: {exc}")
                self._logger.warning("feed 실패: %s", exc)
        auto = 0
        pr_urls: list[str] = []
        for diff in diffs:
            if diff.added:
                if len(diff.added) > self._added_cap:
                    pr = self._patcher.build_pr(diff, reason="added_cap_exceeded")
                    if self._publisher: pr = await self._publisher.apublish(pr)
                    pr_urls.append(pr.url)
                else:
                    self._patcher.apply_added(diff)
                    auto += len(diff.added)
            if diff.changed or diff.removed:
                pr = self._patcher.build_pr(diff)
                if self._publisher: pr = await self._publisher.apublish(pr)
                pr_urls.append(pr.url)
            if diff.kev_new and self._invalidate is not None:
                try:
                    await self._invalidate(diff.kev_new)
                except SOCPlatformError as exc:
                    errors.append(f"kev_invalidate: {exc}")
        from tools.coverage import CoverageMatrix
        CoverageMatrix.reload()
        return WorkerReport(
            cycle_at=_now_iso(), diffs=diffs, auto_applied=auto,
            pr_urls=pr_urls, errors=errors,
        )
```

## 9. Learning Worker 통합

```python
# app/learning.py
async def run_cycle(self) -> None:
    # 기존 exp / actor 적립 단계 ...
    if self._threat_landscape is not None and self._should_refresh_landscape():
        try:
            report = await self._threat_landscape.run()
            self._last_landscape_refresh = time.time()
            self._logger.info(
                "threat_landscape: applied=%d prs=%d errors=%d",
                report.auto_applied, len(report.pr_urls), len(report.errors),
            )
        except Exception as exc:                          # noqa: BLE001
            self._logger.warning("threat_landscape 실패(계속): %s", exc)

def _should_refresh_landscape(self) -> bool:
    return (time.time() - self._last_landscape_refresh)/3600 >= self._refresh_hours
```

## 10. Feed 어댑터 — 인터페이스

```python
class FeedTool(Protocol):
    source: str
    async def afetch(self) -> FeedSnapshot: ...

# tools/feed_base.py — 공통 HTTP 헬퍼
async def fetch_with_retry(
    url: str, *, timeout: float = 60.0, retries: int = 2,
    user_agent: str = "pollack-ai/1.0",
) -> tuple[bytes, str]:
    """return (body, sha256_hex). HTTPS only. 5xx → 지수 backoff retry."""
```

## 11. 포이즈닝 / 회귀 방어

| 위협 | 방어 |
|---|---|
| 외부 피드 변조 (DNS / MITM) | HTTPS only + 고정 `User-Agent` + `raw_hash` 기록 (변경 추적) |
| 신규 기법 대량 추가로 graph 폭발 | `added` ≤ `feed_added_cap` 만 자동, 초과 시 PR 강제 |
| 기존 기법 의미 변경 (rename) | 항상 PR — 자동 적용 X. 회귀 게이트(`benchmarks/`) 통과 후 머지 |
| KEV 캐시 무효화 폭주 | 새 KEV 만 무효화 (전체 무효화 X) |
| 한 피드 장애 → 사이클 중단 | feed 별 독립 try/except — 나머지 피드 계속 |
| graph yaml 직접 변조 | 패치는 `GraphYamlPatchTool` 만 수행. apply_added 가 backup 생성 + lockfile 사용 |

## 12. Error Handling

| 시나리오 | 처리 |
|---|---|
| 피드 HTTP 5xx / 타임아웃 | `SOCPlatformError` → errors 에 기록 |
| 파싱 실패 | 동일 |
| 의존 라이브러리 미설치 | 어댑터 미생성 (factory None — feed 빠진 채 사이클 진행) |
| graph yaml 쓰기 실패 | `SOCPlatformError` → errors, 다음 피드 계속 |
| PR 발행 실패 | `pr.status="failed"` 보고서 — 차후 수동 |
| `coverage.reload()` 실패 | warning + 기존 매트릭스 유지 |

## 13. Testing 매트릭스

| 테스트 | 케이스 |
|---|---|
| `test_feed_base` | retry / TLS 강제 / hash 일관 |
| `test_mitre_stix_feed` | STIX mock → technique / 5xx → 에러 |
| `test_atlas_feed`, `test_embed3d_feed`, `test_cisa_kev_feed` | 각 mock 응답 파싱 + 형식 오류 처리 |
| `test_graph_yaml_patch` | added → 자동 / changed → PR / 100건 초과 → PR |
| `test_threat_landscape_agent` | 4 feed mock → 보고서 / 한 피드 장애 → 나머지 진행 |
| `test_learning_cycle_landscape` | should_refresh 24h 게이트 / 미주입 시 거동 보존 |
| `test_coverage_reload` | yaml 갱신 후 재로드 → 매트릭스 갱신 |

## 14. Settings

```bash
FEED_REFRESH_HOURS=24
FEED_USER_AGENT=pollack-ai-threat-landscape/1.0
FEED_ADDED_CAP=100

ATTACK_FEED_URL=https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
ATLAS_FEED_URL=https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml
EMBED3D_FEED_URL=https://raw.githubusercontent.com/mitre/emb3d/main/emb3d.yaml
KEV_FEED_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

(정확한 ATT&CK STIX endpoint 는 구현 단계에서 확정 — `mitreattack-python` 사용 시 라이브러리 디폴트.)

## 15. YAGNI

- ❌ 피드 자체 서명 검증 (TLS 만)
- ❌ 자동 시나리오 생성
- ❌ 자동 KQL 룰 생성
- ❌ 자동 PR 머지
- ❌ 한국어/방산 특화 피드 (KISA/NCSC — 별도)
- ❌ 실시간 갱신 (24h 만)
- ❌ 다중 git branch 동시 PR

## 16. 마이그레이션

- `threat_landscape` 미주입 시 learning worker 거동 보존
- 신규 `BaseWorkerAgent` 는 `BaseSOCAgent` 와 분리 — 기존 6 에이전트 무영향
- graph yaml 변경 → 다음 hotpath 사이클부터 자동 반영 (`_default_retriever` lazy)
- pr_publisher 미주입 시 PR `proposed` 상태로만 보고

## 17. 후속

- **자동 시나리오 후보 생성** — 갭 → `benchmarks/` 시나리오 후보 PR
- **자동 KQL 룰 후보 생성** — 신규 technique → KQL draft → `dah-sentinel-content` PR
- **방산 특화 피드** — KISA / NCSC / 국가정보원 위협 정보 통합
- **회귀 게이트 통과 자동 머지** — benchmarks 통과 시 자동 (지금은 항상 사람 검토)

## 18. 참조

- `docs/adr/0002-autonomous-self-improving-blue-soc.md` — Deployment A/B 분리
- `tools/coverage.py` — ATT&CK 커버리지 매트릭스
- `tools/rule_publisher.py` — PR 발행 패턴 (재사용)
- `data/mitre_attack_graph.yaml` — 패치 대상
- MITRE CTI: <https://github.com/mitre/cti>
- ATLAS: <https://github.com/mitre-atlas/atlas-data>
- EMB3D: <https://github.com/mitre/emb3d>
- CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
