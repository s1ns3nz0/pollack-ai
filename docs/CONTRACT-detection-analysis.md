# Detection ↔ Analysis 계약 (contract)

두 개발자가 **detection**(센티넬 룰·워치리스트)과 **analysis**(에이전트)를 나눠
개발할 때의 인터페이스. 이 문서 = 단일 진실. 계약 변경은 **양측 승인 + 이 문서 갱신**.

## 레포 경계 (충돌면 최소화의 핵심)
- **Detection** — 실 KQL 분석룰·워치리스트 = 별 레포 **`s1ns3nz0/dah-sentinel-content`**.
  동료가 거기서 개발. 이 레포(pollack-ai)의 `sentinel/` 은 seed·데모·스키마 참조본.
- **Analysis** — 이 레포 `agents/`·`core/`·`app/`. 내가 개발.
- **결론**: 두 레인은 **대부분 다른 레포** → 충돌 거의 없음. 이 레포에서 겹치는 유일
  표면 = 아래 **계약 파일**. 그것만 조율하면 된다.

## 계약 표면 (양측이 의존 — 함부로 바꾸지 말 것)

### 1. Alert — detection이 산출, analysis가 소비 (wire 스키마)
**`core/alert.py`**(계약 파일 — models.py 에서 분리, 양측 리뷰). `UntrustedAlertPayload`
(외부 유입 형태) → `Alert`. 공유 원시타입(Severity/Verdict/SbomComponent)은
`core/primitives.py`. `from core.models import Alert` 는 하위호환 re-export 로 그대로
동작. detection이 채우는 **wire 필드(15)**만 신뢰 입력이다:
```
id, scenario_id, title, asset_id, asset_tier, mission_phase, severity_baseline,
mitre(dict), signals(list), iocs(list), cves(list), sbom_components(list),
llm_suggested_severity, lat, lon
```
- `_INTERNAL_ONLY_FIELDS`(12개: enrich·dynamics·actor_id·ground_truth 등)는 detection이
  **채울 수 없다**(위조 불가 — 트러스트 경계). 이 목록은 analysis 전용.
- **계약 규칙**: detection이 새 신호 필드가 필요하면 → wire 필드 추가는 **양측 조율**
  (Alert + UntrustedAlertPayload + drift-guard 테스트 동시 수정). analysis 내부 enrich
  필드는 detection과 무관(자유).

### 2. Scenario 카탈로그 — **단일작성자**(`core/policy/bas-scenarios.yaml`)
**mara89ma(detection) 단독 소유·쓰기. s1ns3nz0(analysis) 는 읽기만** → 동시-쓰기 충돌 0
(CODEOWNERS 강제). analysis가 signals/tactic 의미를 바꿔야 하면 mara89ma에게 요청.
scenario_id → 어떤 룰이 탐지하고 analysis가 어떤 신호를 기대하는지. 엔트리 스키마:
```yaml
- id: S1-GNSS-SPOOF          # scenario_id (Alert.scenario_id 와 일치)
  name: GPS/GNSS 스푸핑
  signals: ["GNSS-INS 잔차 급증", ...]   # analysis 기대 신호(Alert.signals)
  detection_rule: S1_GNSS_Spoofing.json  # dah-sentinel-content 의 룰 파일명("" = 갭)
  tactic: Collection                      # attack_coverage 매트릭스와 정합
  stride: [S, T]
  campaign: [C2]                          # 캠페인 체인 id
```
- **detection 소유**: `detection_rule` 값(룰 파일명), 신규 scenario 추가.
- **analysis 소유**: `signals`·`tactic`·`stride`·`campaign` 의미(분석이 소비).
- **계약 규칙**: 새 scenario 추가는 detection 주도 + analysis가 signals/tactic 확인.
  `detection_rule: ""` = 탐지 갭(정직 표기 — analysis가 커버리지로 노출).

### 3. Coverage 매트릭스 (`data/attack_coverage.yaml`)
technique → covered/planned/uncovered. detection이 룰을 만들면 covered 로 승격.
`tools/coverage.py CoverageMatrix` 가 소비(analysis KPI·killweb·brief). **양측 조율**.

### 4. Watchlist 스키마 (`sentinel/Watchlists/*.csv` + `core/models.py WatchlistUpdate`)
analysis→detection **역방향** 피드백(FP 개선). `WatchlistUpdate.search_key` 는 워치리스트
JSON의 `itemsSearchKey`(단일 진실)와 일치해야 함(`tools/rule_publisher.py` 검증).
- detection 소유: 워치리스트 컬럼 스키마·SearchKey.
- analysis 소유: `RulePullRequest`(룰/워치리스트 draft PR 생성 로직).

### 5. 골든 픽스처 (`benchmarks/eval_scenarios/S*.yaml`)
구체 Alert 인스턴스 = 회귀 게이트. detection·analysis **둘 다 깨면 안 됨**. 변경 조율.

## 변경 절차 (protocol)
1. 계약 파일(위 1~5) 변경 = PR 에서 **양측 리뷰 필수**(CODEOWNERS 강제). 이 문서 갱신.
2. detection 주 작업은 `dah-sentinel-content` 레포에서 → pollack-ai PR 불필요(충돌 0).
3. detection→analysis 신규 scenario: bas-scenarios.yaml 에 엔트리 추가(양측 확인).
4. analysis→detection 피드백: RulePullRequest/WatchlistUpdate 로 draft PR(자동 머지 금지).

## 충돌 다발 파일 (choke) — 규율
`core/models.py`·`agents/graph.py`·`agents/report_agent.py`·`app/metrics.py` 는 analysis
전용이나 **모든 analysis 기능이 건드림**. 동료(detection)는 이 레포에서 거의 안 만짐
→ 우리 사이 충돌 없음. 단 analysis 내부 다인 개발 대비 규율:
- **append-only**: 모델·카운터·필드는 **끝에 추가**(재정렬·중간삽입 금지 → 3-way merge 유리).
- 기능 1개 = 파일 최소 편집(별 assessor 모듈 + SOCReport 필드 1 + 배선 1줄).
- (선택 후속) 중앙 배선(report_agent가 모든 assessor 생성)을 **registry/plugin** 으로
  바꾸면 choke 해소 — 지금은 수동 중앙배선(등록 패턴 없음).

## 요약
- 두 레인 = 다른 레포 → 구조적으로 충돌 최소. **CODEOWNERS + 이 계약 파일 5종만 조율**.
- detection: dah-sentinel-content(룰) + 여기 bas-scenarios `detection_rule`·sentinel/seed.
- analysis: agents/·core/ 엔진. Alert(입력)·SOCReport(출력) 사이 전부 우리 영역.
