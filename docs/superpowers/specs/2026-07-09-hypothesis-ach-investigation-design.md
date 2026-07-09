# 가설 기반 조사 — ACH 경쟁가설 층 (design)

**날짜**: 2026-07-09
**작성**: 황준식 (analysis lane)
**상태**: design (Codex 설계리뷰 반영 — High1·Med7·Low4 전건)

## 1. 목적 / intent

Investigation agent 는 현재 11단계 enrichment 파이프라인(RAG 신뢰필터 → sandbox → TI →
CVE/KEV → 경험/억제 대조 → GNSS → 공역 → actor TTP → 예측)으로 증거 신호 7종+를
수집하지만, 신호가 **평평하게 나열**될 뿐 "무슨 공격 가설을 지지/반증하는가"의 구조가
없다. 이 기능은 **ACH(Analysis of Competing Hypotheses)** 층을 얹어, 수집된 신호를
경쟁가설별 지지/반증 매트릭스로 재구조화하고 순위·증거원장을 산출한다.

**설계 원칙 (grill 확정):**

| 포크 | 결정 |
|---|---|
| 증거 범위 | **기존 신호 재평가만** — 이미 수집된 11단계 산출물을 증거항목으로 정규화. 능동 수집(추가 KQL 조회)·LLM 서사 없음. 순수 결정론, 신규 IO 없음(정책 YAML 로드 제외) |
| 판정 영향 | **비권위 참고정보** — `InvestigationResult.hypothesis_assessments` additive 필드만. confidence 산식·validation 라우팅·기존 필드 전부 불변(PR#67 env-verdict 비권위 선례). 판정 영향은 실측 후 별도 PR |
| 가설 소스 | **정책 YAML 카탈로그**(`core/policy/hypothesis-catalog.yaml`) — severity/cacao 정책 관례. UAV 도메인 경쟁가설 + **귀무가설(오탐/환경요인) 필수** |
| 충돌 회피 | 옆 세션(response/cacao lane)과 병렬 — 신규 2파일 + models.py additive + investigation 말미 1블록 + exceptions.py 중간 삽입 1클래스. cacao·response_agent·correlation 불가침 |

## 2. ACH 방법론 적용

Heuer 의 ACH 핵심: **가설은 지지 증거의 양이 아니라 반증 증거의 부재로 선별**한다.

- 1차 정렬: `inconsistency_score` 오름차순 (반증 최소가 승자)
- 2차 정렬: `consistency_score` 내림차순
- 동률: 가설 id 사전순 (결정론 tie-break). 점수는 **소수 4자리 반올림 후** 비교
  (float 누적 오차로 인한 근소 차이 순위 요동 방지 — Codex M 반영)
- 반환 리스트 순서 자체도 결정론 보장: rank 오름차순(동률 tie-break 반영),
  전 가설 rank=None(증거 0건)이면 카탈로그 선언 순 (Codex L 반영)
- **Diagnosticity**: 활성 가설 전부에 **같은 방향으로만**(전부 consistent 또는 전부
  inconsistent) 걸리는 증거는 변별력 0 — 원장에 `diagnostic: false` 표기.
  공통 반증도 비변별 (Codex M 반영 — ACH 변별증거 원칙)
- **증거 0건 → leading 없음** (침묵). 근거 없는 가설 순위는 정직성 불변식 위반
- 귀무가설 `HYP-BENIGN-ENV` 는 카탈로그 스키마 차원에서 존재 강제 — 경쟁 구도 없는
  ACH 는 확증편향 재생산

## 3. 변경 상세

### 3.1 core/policy/hypothesis-catalog.yaml — 경쟁가설 카탈로그

UAV 도메인 가설 6개 + 귀무가설 1개:

- `HYP-GNSS-SPOOF` GNSS 스푸핑/재밍 · `HYP-C2-HIJACK` C2 링크 탈취 ·
  `HYP-DATALINK-INTERCEPT` 데이터링크 감청 · `HYP-SUPPLY-CHAIN` 공급망/펌웨어 침해 ·
  `HYP-RECON-TRACK` 정찰/추적 · `HYP-INSIDER` 내부자 · `HYP-BENIGN-ENV` 오탐/환경요인(필수)

가설 항목 스키마:

```yaml
hypotheses:
  - id: HYP-GNSS-SPOOF          # ^HYP-[A-Z0-9-]+$
    name: "GNSS 스푸핑/재밍"
    mitre: ["T1600"]             # 참고 태그 (스코어 미사용)
    evidence:
      "gnss_jam_level>=2":  {consistent: 0.9}
      "airspace_hostile":   {consistent: 0.4}
      "sandbox_malicious":  {inconsistent: 0.3}
  - id: HYP-BENIGN-ENV
    name: "오탐/환경요인"
    evidence:
      "suppression_corroboration>0": {consistent: 0.8}
      "ti_malicious_count>0":        {inconsistent: 0.9}
```

- 조건식 미니 DSL **3형태만**: `key` (truthy) / `key>0` / `key>=n` (n 은 음이 아닌
  **십진수 — int 또는 float**, 예: `prediction_probability>=0.6`; Codex M 반영).
  그 외 문법·미지 키는 로드 시 스키마 검증에서 거부 (fail-fast)
- 룰당 `consistent` **또는** `inconsistent` 정확히 하나, 가중치 0.0<w<=1.0
- 가설 id **중복 금지** — 중복 시 로드 실패 (Codex M 반영)
- 귀무가설 부재 시 로드 실패

### 3.2 core/hypothesis.py — 정규화 + 로더 + AchEvaluator (신규)

- `EVIDENCE_KEYS`: 허용 증거 키의 닫힌 집합(frozenset) — 카탈로그 검증과 정규화가
  동일 집합 공유. 키: `ti_malicious_count, sandbox_malicious, kev_present,
  gnss_jam_level, airspace_hostile, actor_ttp_overlap, prediction_match,
  experience_corroboration, suppression_corroboration, trusted_chunk_coverage,
  decoy_hit, key_terrain, kill_chain_advanced, prediction_probability`
- `extract_evidence(result: InvestigationResult, alert: Alert) -> dict[str, float]`:
  11단계 산출물 + alert 플래그(decoy_hit·key_terrain·kill_chain_advanced 등)를
  수치로 정규화. bool → 0.0/1.0, count/level → float 그대로
- `load_hypothesis_catalog(path: Path) -> list[HypothesisDef]`:
  스키마 검증(id 패턴·DSL 문법·키 화이트리스트·가중치 범위·귀무가설 존재).
  위반 → `HypothesisCatalogError`
- `AchEvaluator.evaluate(evidence: dict[str, float]) -> list[HypothesisAssessment]`:
  - 조건 매칭된 룰만 원장 기입: `consistency += w * min(1.0, 강도)` 또는
    `inconsistency += w * min(1.0, 강도)` (강도 = 정규화 값, bool 계열은 1.0)
  - diagnosticity 계산 → 순위 부여 → 전 가설 반환 (탈락 가설도 원장 포함,
    분석가가 기각 근거를 볼 수 있어야 함)
  - **가설 단위 격리**: 개별 가설 평가 예외 시 해당 가설만 결과에서 제외 +
    경고 로그 — 한 가설 오류로 ACH 전체 소실 금지 (Codex M 반영)
  - 매칭 증거 총 0건이면 전 가설 rank=None, leading 없음
- 카탈로그는 Settings 경유 없이 `POLICY_DIR` 상수 사용 (severity 관례 동일)

### 3.3 core/models.py — additive 전용

```python
class EvidenceEntry(BaseModel):
    key: str                      # 증거 키
    value: float                  # 정규화 값
    direction: str                # "consistent" | "inconsistent"
    weight: float
    diagnostic: bool = True       # 변별력 여부

class HypothesisAssessment(BaseModel):
    hypothesis_id: str
    name: str
    consistency: float = 0.0
    inconsistency: float = 0.0
    rank: int | None = None       # 증거 0건이면 None
    ledger: list[EvidenceEntry] = Field(default_factory=list)
```

`InvestigationResult.hypothesis_assessments: list[HypothesisAssessment] =
Field(default_factory=list)` 추가 (리포 컬렉션 기본값 관례 — Codex L 반영).
기존 필드 순서·기본값 불변.

### 3.4 agents/investigation_agent.py — 말미 1블록

run() 에서 신호 수집 완료 직후(RAGAS fire-and-forget 앞)에 호출:

```python
try:
    evidence = extract_evidence(result, alert)
    result.hypothesis_assessments = self._ach.evaluate(evidence)
except Exception:  # noqa: BLE001 — 비권위 부가층 광역 격리 지점 (bare except 아님)
    self._logger.warning("ACH 평가 실패 — 가설 없이 진행", exc_info=True)
```

- evaluator 는 `__init__` 에서 카탈로그 로드 (기동 시 fail-fast)
- 런타임 평가 예외는 **`Exception` 광역 격리** — `SOCPlatformError` 한정이면
  extract/evaluator 버그(KeyError 등)가 조사 전체를 죽임 (Codex High 반영).
  비권위 참고정보 층이므로 어떤 예외도 조사 실패로 승격 금지

### 3.5 core/exceptions.py — 1클래스

`HypothesisCatalogError(SOCPlatformError)`. **파일 말단이 아니라
`GraphRAGQueryError` 인접 중간에 삽입** — 옆 세션이 말단 append 중이므로
same-hunk 충돌 회피.

## 4. 비변경 (불가침 목록)

- `core/cacao.py` · `core/policy/cacao-playbooks.yaml` · `core/policy/recovery-matrix.yaml`
- `agents/response_agent.py` · `core/correlation.py`
- confidence 산식(`_confidence`) · validation 라우팅 · 기존 InvestigationResult 필드
- `agents/graph.py` (배선 불필요 — investigation 내부 완결)

## 5. 테스트 (`tests/__tests__/test_hypothesis.py` + 통합)

| 케이스 | 검증 |
|---|---|
| 카탈로그 스키마 | 잘못된 DSL·미지 키·가중치 범위 밖·귀무가설 부재·**id 중복** → `HypothesisCatalogError` |
| DSL 파싱 | `key`/`key>0`/`key>=n` 3형태 (n float 포함) + 거부 문법 |
| ACH 순위 | 반증 최소 승자 (지지 많아도 반증 있으면 패배 케이스 포함) |
| 귀무가설 승리 | suppression_corroboration 높고 TI 청정 시 HYP-BENIGN-ENV leading |
| diagnosticity | 전 가설 공통 지지 → diagnostic=False + **공통 반증도 diagnostic=False** |
| tie-break | 동률 시 id 사전순 + **4자리 라운딩 경계 근소차 케이스** 반복 실행 결정론 |
| 증거 0건 | 전 가설 rank=None, leading 없음, 카탈로그 선언 순 반환 |
| 예외 격리 | evaluator 광역 예외(비SOC 포함) 시 조사 결과 정상 + 빈 리스트, 가설 단위 격리 |
| **비권위 불변** | 가설 결과 유무와 무관하게 confidence 값·validation 라우팅 결과 byte-동일 |
| 통합 | investigation run() 후 신규 필드 채움 + 기존 필드 불변 |

## 6. 후속 (본 PR 스코프 밖)

- report_agent 가설 원장 표기 (BLUF 연계)
- 능동 증거 수집 (가설이 요구하는 추가 KQL 조회)
- 반증 압도 시 escalate-only 응집 경보 (PR#66 패턴)
- 카탈로그 가중치 KPI 오프라인 벤치 튜닝
