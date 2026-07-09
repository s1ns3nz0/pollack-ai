# Active Hunt Agent — 예측/역추적 KQL 조회 기반 능동 헌팅

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-09 |
| 상태 | Draft (grill-me/brainstorming 합의) |
| 작성자 | s1ns3nz0 |
| 근거 | 기존 `HuntPlanner` 는 hunt 가설만 만들고, 실제 Sentinel 조회 루프는 없음 |
| 선행 | `SequencePredictor`, `HuntPlanner`, `CoverageMatrix`, CPCON posture, MBCRA mission risk |

## 1. 배경

현재 analysis lane 은 actor kill-chain 기반 다음 기법 예측과 Tier3 hunt hypothesis 생성을
이미 제공한다. 다만 "무엇을 찾아야 하나"까지만 산출하고, 실제 Log Analytics/Sentinel 에
읽기전용 KQL 을 실행해 예측 흔적이나 이전 침투 흔적을 확인하는 능동 헌팅 루프는 없다.

Response lane 이 고도화되는 동안 analysis lane 은 대응 전후의 근거 품질을 높여야 한다.
Active Hunt Agent 는 예측된 다음 공격과, 이미 깊숙한 단계까지 진행된 공격의 이전 단계
흔적을 bounded KQL 로 확인해 report evidence 로 남긴다.

## 2. 목표

- 별도 `ActiveHuntAgent` 를 LangGraph opt-in 노드로 추가한다.
- 기본값은 비활성(`ACTIVE_HUNT_ENABLED=false`)로 두어 기존 hot path SLO 를 보존한다.
- `investigation` 이후, `validation` 이전에 실행한다.
- forward hunt: actor 예측/campaign 기반 다음 technique 흔적을 조회한다.
- backward hunt: 후반 단계 alert 에서 이전 kill-chain 단계 흔적을 역추적한다.
- KQL 은 LLM 즉석 생성이 아니라 정책 YAML 에 등록된 template 만 실행한다.
- 결과는 `ActiveHuntFinding` 으로 별도 상태와 report 에 노출한다.
- 1차 버전에서 validation verdict/confidence 는 바꾸지 않는다.

## 3. 비목표

- 자동 대응 실행.
- 자동 룰 수정 또는 AutoKQL PR 생성.
- LLM 이 런타임에 KQL 을 생성하는 경로.
- 전체 로그 덤프 또는 장기 포렌식 수집.
- active hunt 결과를 validation 판정권으로 사용하는 것.

## 4. 그래프 배치

추천 배치는 opt-in LangGraph 노드다.

```text
triage
  -> investigation
  -> active_hunt   # ACTIVE_HUNT_ENABLED=true 일 때만
  -> validation
  -> response | rule_update
  -> report
```

이 배치는 alert context, actor profile, predictions 를 사용할 수 있고, 조회 결과를 report
evidence 로 전달할 수 있다. Sentinel 조회 실패나 timeout 은 빈 finding 또는 error finding
으로 degrade 하며 파이프라인을 중단하지 않는다.

## 5. 정책 파일

신규 정책 파일은 `core/policy/active-hunt.yaml` 로 둔다. 임계치와 query template 을 코드가
아닌 정책으로 관리해 analysis/detection 조율면을 명확히 한다.

```yaml
version: 0.1

limits:
  max_queries_per_alert: 5
  row_limit: 20
  query_timeout_seconds: 8
  max_lookback_hours: 72

windows:
  forward_default_minutes: 30
  backward_default_hours: 24
  backward_force_hours: 72

backward_policy:
  force_tactics: [Exfiltration, Impact]
  cpcon_thresholds:
    5: CommandAndControl
    4: CommandAndControl
    3: LateralMovement
    2: Discovery
    1: InitialAccess
  key_terrain_order_delta: -2
  high_mission_risk_order_delta: -2
  high_mission_risk_score: 8

queries:
  T1133_external_remote_service:
    technique: T1133
    tactic: InitialAccess
    direction: backward
    table: UAVGcsAccess_CL
    kql: |
      UAVGcsAccess_CL
      | where TimeGenerated between (datetime({start}) .. datetime({end}))
      | where ClientIp !startswith "10."
      | take {row_limit}
```

## 6. Backward Hunt 임계 정책

고정 order 값(예: CommandAndControl=11)을 코드에 박지 않는다. "깊숙하게 들어왔다"는
현재 작전 상황에 따라 달라지므로 CPCON/INFOCON 성격의 전역 태세, 임무위험, 핵심지형을
함께 반영한다.

결정 함수:

```text
threshold = tactic_order(cpcon_thresholds[cpcon_level])
if alert.key_terrain:
    threshold += key_terrain_order_delta
if mission_risk.score >= high_mission_risk_score:
    threshold += high_mission_risk_order_delta

should_backward_hunt =
    current_or_actor_max_order >= threshold
    or current_tactic in force_tactics
```

`force_tactics` 인 `Exfiltration`, `Impact` 는 태세와 무관하게 backward hunt 를 실행한다.
임계치 보정 후 최소/최대 order 는 `CoverageMatrix` 범위 안으로 clamp 한다.

## 7. Query 생성

1차 버전은 template-only 다.

- technique/tactic 에 매칭되는 `queries` 항목만 실행한다.
- 등록된 template 이 없으면 `query_unavailable` finding 을 남긴다.
- `{start}`, `{end}`, `{row_limit}` 같은 제한된 placeholder 만 허용한다.
- 외부 입력을 KQL 식별자나 table name 으로 삽입하지 않는다.
- table/schema 는 정책에 명시된 값만 사용한다.

LLM 기반 KQL 생성은 AutoKQL lane 의 후속 기능으로 분리한다.

## 8. 시간창과 비용 제한

- forward hunt: alert 이후 기본 30분.
- backward hunt: alert 이전 기본 24시간.
- `Exfiltration`/`Impact` backward hunt: 72시간.
- 전역 hard cap: 72시간.
- query별 row limit: 20.
- alert당 최대 query 수: 5.
- query timeout: 8초.

Active hunt 의 목적은 "증거 존재 여부 확인"이지 로그 수집이 아니다. 따라서 count 와 작은
sample 만 report 에 남긴다.

## 9. Sentinel 조회 어댑터

`tools/sentinel_query_tool.py` 에 얇은 조회 경계를 둔다.

```python
class SentinelQueryClient(Protocol):
    async def aquery(
        self, kql: str, timeout_seconds: float
    ) -> SentinelQueryResult:
        ...
```

운영 구현은 `azure-monitor-query` 와 `azure-identity` 를 사용한다. 두 의존성은 이미
`pyproject.toml` 에 있다. `SENTINEL_WORKSPACE_ID` 등 설정이 없으면 active hunt 는 자동
비활성화한다. 테스트는 fake client 를 주입해 네트워크 없이 검증한다.

## 10. 데이터 모델

`core.models` 에 append-only 모델을 추가한다.

```python
class ActiveHuntFinding(BaseModel):
    direction: str  # "forward" | "backward"
    technique: str
    tactic: str = ""
    query_id: str
    matched: bool = False
    row_count: int = 0
    time_window: str = ""
    rationale: str = ""
    sample: list[dict[str, str]] = Field(default_factory=list)
    error: str = ""
```

`SOCState` 에 `active_hunt_findings` 를 추가하고, `SOCReport` 에 같은 필드를 노출한다.
`InvestigationResult` 에 섞지 않는다. Investigation 은 현재 alert 근거 상관이고,
active hunt 는 예측/역추적 기반 추가 조회 결과라 의미가 다르다.

## 11. 판정권

1차 버전에서 active hunt 결과는 validation verdict/confidence 를 변경하지 않는다.

`matched=True` finding 은 report, OSCAL evidence, commander brief 에 정황 근거로 드러낸다.
추후 로그 품질과 template 안정성이 검증되면, 정책 기반 confidence 가산을 별도 설계한다.

## 12. 오류 처리

| 상황 | 처리 |
|---|---|
| active hunt 비활성 | 노드 미배선 또는 no-op |
| Sentinel 설정 없음 | no-op, guardrail flag 선택 |
| 정책 파일 부재/오류 | no-op, warning |
| query template 없음 | `query_unavailable` finding |
| Sentinel timeout/API 오류 | error finding, 파이프라인 계속 |
| KQL 결과 row 가 많음 | count + sample `row_limit` 만 보존 |

## 13. 테스트

- `ActiveHuntPolicy` 가 CPCON/mission risk/key terrain 으로 backward threshold 를 계산한다.
- `force_tactics` 는 threshold 와 무관하게 backward hunt 를 켠다.
- forward hunt 는 predictions 기반 query 후보를 만든다.
- backward hunt 는 현재/actor max order 기준 이전 단계 query 후보를 만든다.
- `max_queries_per_alert`, `row_limit`, `max_lookback_hours` 가 적용된다.
- template 이 없는 technique 은 `query_unavailable` finding 을 만든다.
- fake Sentinel client 로 matched/error/no-result finding 을 검증한다.
- graph 에서 `ACTIVE_HUNT_ENABLED=false` 는 기존 노드 순서를 유지한다.
- graph 에서 opt-in 시 `active_hunt` trace 와 report field 가 채워진다.

## 14. 롤아웃

1. 정책/모델/순수 planner 부터 추가한다.
2. fake client 기반 `ActiveHuntAgent` 단위 테스트를 작성한다.
3. Azure SDK client 를 얇게 추가하되 설정 없으면 비활성화한다.
4. graph opt-in 배선을 추가한다.
5. report/OSCAL/commander brief 노출을 붙인다.

첫 구현 PR 은 읽기전용 evidence-only 로 끝낸다. validation 영향, AutoKQL 연계, 배치
active hunt 는 후속 PR 로 분리한다.
