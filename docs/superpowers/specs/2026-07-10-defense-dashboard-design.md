# 사이버 작전 참모 방어 대시보드 — Story-first 상황도

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-10 |
| 상태 | 설계(사용자 승인, 구현 계획 대기) |
| 근거 | 예선 심사 임팩트 우선 + 탐지/판정 품질 보조 |
| 선행 | SOCState, SOCReport.commander_brief, campaign_matches, CACAO/HITL, degradation, attack_coverage |

## 목표
사이버 작전 참모가 지휘관에게 바로 조언할 수 있는 **decision-first 방어 상황도**를
제공한다. 1급 단위는 alert 가 아니라 **story(actor/campaign 단위)**다. 화면은 "누가,
어떤 자산을, 어떤 공격 흐름으로, 임무에 어떤 영향을 주는가"를 먼저 보여주고, alert 는
그 story 의 증거로 드릴다운한다.

대시보드는 신규 판정 엔진이 아니다. 기존 `SOCState`/`SOCReport`/`CommanderBrief`/
정책 YAML 을 렌더링하는 얇은 계층이다. 새 verdict, severity, CAT, mission impact 를
생성하지 않고 authoritative 필드를 재배치한다.

## 핵심 원칙
- **Decision-first, not alert-first**: 참모 화면은 "현재 결심이 필요한 적 행동"을 먼저
  보여준다. alert 목록은 story 카드 하위 증거다.
- **Snapshot JSON = wire format**: 리플레이는 파일을 읽고, 제출용 라이브는 같은 스키마를
  SSE 로 흘린다. UI 는 데이터 소스가 파일인지 스트림인지 모른다.
- **정직한 합성**: `commander_brief` caveat, provisional, unknown, degraded 표기는
  화면에서 숨기지 않는다. topology 와 navigator 는 보조 시각화일 뿐 판정을 바꾸지 않는다.

## 화면 구조
상단 상태 스트립, 좌측 story rail, 우측 ATT&CK navigator, 우측 하단 BLUF 카드, 하단
asset topology 로 구성한다.

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Top Strip                                                           │
│ Active Stories | Max Mission Impact | HITL Pending | Decision Margin │
├──────────────────────┬──────────────────────────────────────────────┤
│ Story Rail            │ UAV ATT&CK Navigator                         │
│ story cards           │ observed / current / predicted / gap          │
│ alert drilldown       ├──────────────────────────────────────────────┤
│                       │ BLUF Staff Advice                             │
│                       │ Situation / Mission Impact / Recommendation   │
├──────────────────────┴──────────────────────────────────────────────┤
│ Asset Topology                                                       │
│ uav-sim-env assets rendered as real UAS components                    │
└─────────────────────────────────────────────────────────────────────┘
```

다크 워룸 테마를 기본으로 한다. 정보 밀도가 높은 작전참모 화면이므로 마케팅형 hero,
장식 카드, 과도한 일러스트는 사용하지 않는다.

## Story Rail
좌측 rail 의 1급 카드 단위는 `story_id`다. story 는 같은 actor/campaign/cluster 로 묶인
alert 들의 작전 단위 표현이다.

카드 필드:
- `story_id`: 예: `RED-01`, `C2-CAMPAIGN-01`.
- actor 또는 actor 추정값: `alert.actor_id`, profile, incident_case 에서 가능한 값.
- campaign 진행도: `CampaignMatch.chain_id`, `matched`, `total`, `next_expected`.
- 표적 자산: story 내 대표 `alert.asset_id` 또는 mission_risk.asset_id.
- 임무 영향: `mission_continuity.level`, `mission_risk.score`, fallback 요약.
- HITL 상태: `ApprovalResult.required/approved`, `ResponseResult.hitl`.
- 하위 alert 목록: `alert_id`, `scenario_id`, tactic, time/order.

카드 클릭 시 해당 story 가 선택되고 navigator, BLUF, topology overlay 가 같은 story 기준으로
동기화된다. alert 를 직접 클릭하면 story 컨텍스트는 유지하고 current tactic 만 해당 alert 로
이동한다.

## UAV ATT&CK Navigator
우측 상단 navigator 는 `data/attack_coverage.yaml` 의 15개 tactic `order`를 권위 순서로
사용한다.

셀 상태:
- `observed`: 선택 story 에서 이미 관측된 tactic. 시간순 번호를 표시한다.
- `current`: 현재 선택 alert 의 tactic. observed 와 중첩 가능하다.
- `predicted`: `campaign_matches[].next_expected`, `hunt_candidates`, `staged_defenses`에서
  산출된 다음 수순 tactic.
- `gap`: `attack_coverage.yaml` 기준 uncovered 또는 planned 상태. covered 는 중립.

가장 중요한 데모 장면은 `predicted` 와 `gap`이 겹치는 셀이다. 이 경우 BLUF 카드에
"다음 예상 수순이 현재 미커버 전술이므로 선제 헌트 또는 룰 배치 가속 권고"를 표시한다.
이 문장은 새 판단이 아니라 `staged_defenses.status == "gap"|"accelerate"`와 coverage
정책의 결합 표현이다.

## BLUF Staff Advice
우측 하단 BLUF 카드는 `SOCReport.commander_brief`를 우선 사용한다. 없을 때만 report 의
authoritative 필드로 graceful fallback 을 구성한다.

고정 4행:
- 상황: actor/story, target asset, campaign 진행도, current tactic.
- 임무 영향: `mission_continuity.level`, capability_lost, fallback, mission_risk 핵심 근거.
- 권고: `coa_options[0..2]`, `response.cacao_steps[0..2]`, HITL 필요 여부 badge.
- 다음 수순: `next_expected`, predicted tactic, gap/accelerate 여부, 선제 조치.

카드는 지휘관에게 읽을 문장을 주기 위한 영역이다. navigator 셀 툴팁에 정보를 분산하지
않는다.

## Asset Topology
하단 topology 는 `s1ns3nz0/uav-sim-env` 최신 Helm `local-k8s/helm/uav-sim/values.yaml`을
권위 소스로 1회 추출한 `core/policy/asset-topology.yaml`을 사용한다. 대시보드 런타임이
`uav-sim-env`를 직접 의존하지 않는다.

추출 원칙:
- 노드: Helm values 의 enabled 자산. `air`, `link`, `ground`, `c4i`, `soc` plane 을 보존.
- 엣지: `avHost`, `gcsHost`, `tapHost`, stream/container 참조처럼 values 에 명시된 연결.
- 라벨: `docs/uas-mapping-summary.md`, `docs/components.md`의 실제 UAS 역할명을 보조로
  사용한다. Helm values 가 명명 권위이고 문서는 표시명 보조다.
- 환경 맥락: `avMuav.home` 좌표처럼 시뮬레이션 작전 맥락이 있는 값은 metadata 로 보존한다.

Topology node 는 컨테이너 이름을 그대로 강조하지 않고 실제 UAS 구성요소로 표시한다.
예를 들어 `av-muav`는 KUS-FS MUAV 편대/AV, `datalink-satcom`은 BLOS SATCOM 링크,
`gcs-qgc`는 GCS/MCE 로 렌더한다.

## Degradation 매핑
`core/policy/degradation-matrix.yaml`의 `asset_id`는 능력축이고, topology node 는 배포
자산이다. 따라서 `asset-topology.yaml` 안에 `degradation_asset_ids` 매핑을 둔다.

예시 매핑 방향:
- `GNSS`, `AUTOPILOT`, `PAYLOAD_EOIR` → AV 계열 node(`av-muav`, payload 관련 node).
- `C2_LINK`, `SATCOM`, `TELEMETRY` → data link/tap 계열 node.
- `GCS` → `gcs-qgc`.
- `AI_SOC` → SOC plane node.

story 의 `alert.asset_id`, `mission_risk.asset_id`, `mission_continuity.asset_id`를 이
매핑에 통과시켜 topology node 를 색칠한다. node 색은 continuity 등급을 표현한다:
`SUSTAINED`, `MINIMAL`, `ABORT`, `UNKNOWN`.

## Snapshot Schema
대시보드 입력은 단일 snapshot JSON 이다. 이 스키마가 파일 리플레이와 SSE 라이브의 공통
wire format 이다.

```json
{
  "schema_version": "dashboard.snapshot.v1",
  "step": 3,
  "mode": "replay",
  "generated_at": "2026-07-10T00:00:00Z",
  "summary": {
    "active_story_count": 1,
    "max_mission_impact": "MINIMAL",
    "hitl_pending_count": 1,
    "decision_advantage": "margin"
  },
  "stories": [],
  "selected_story_id": "RED-01",
  "navigator": [],
  "topology": {
    "nodes": [],
    "edges": []
  },
  "bluf": {},
  "source": {
    "alert_id": "SAMPLE",
    "scenario_id": "S24-DATALINK-C2-TAKEOVER",
    "trace": []
  }
}
```

`stories`, `navigator`, `topology`, `bluf`는 UI 전용 view model 이다. 원본 `SOCState` 전체를
브라우저로 보내지 않는다. 필요한 감사용 포인터만 `source`에 둔다.

## 서버와 전송
기술 스택은 FastAPI + 단일 HTML/JS/CSS 이다. 빌드 체인은 두지 않는다.

엔드포인트:
- `GET /`: 정적 대시보드 HTML.
- `GET /static/dashboard.css`, `GET /static/dashboard.js`: 정적 asset.
- `GET /api/snapshots`: 리플레이 snapshot 목록 또는 최신 snapshot.
- `GET /api/topology`: `asset-topology.yaml`을 UI view model 로 반환.
- `GET /events`: SSE. 각 event data 는 snapshot schema 와 동일.

리플레이 모드는 demo runner 가 생성한 snapshot 파일을 순서대로 읽는다. 라이브 모드는 같은
snapshot 을 SSE 로 push 한다. UI 는 source adapter 만 다르고 렌더 경로는 동일하다.

## v1 범위
포함:
- Story rail, alert drilldown.
- UAV ATT&CK navigator 15 tactic matrix.
- BLUF staff advice 카드.
- Asset topology minimap.
- Top strip 4개 지표.
- Replay step controls.
- SSE 라이브 수신 경로.
- `core/policy/asset-topology.yaml` 정적 정책.

제외:
- React/Next 등 별도 프론트엔드 빌드체인.
- 라이브 스트림 인증/권한.
- topology 자동 재추출 스크립트.
- 분석관 전용 alert-first 탭.
- KPI 상세 페이지.

## 오류와 degraded 동작
- snapshot 없음: 빈 대시보드 대신 "No replay snapshots loaded" 상태와 topology 만 표시.
- `commander_brief` 없음: report authoritative 필드로 4행 fallback, confidence 는 unknown.
- topology 매핑 없음: node 는 회색 unknown 으로 표시하고 BLUF 는 숨기지 않는다.
- coverage 로드 실패: navigator gap overlay 를 비활성화하고 degraded badge 표시.
- SSE 연결 끊김: 마지막 snapshot 을 유지하고 reconnect 상태를 상단에 표시.

모든 degraded 상태는 UI 에 표시한다. 조용히 정상처럼 보이게 하지 않는다.

## 테스트 전략
- Snapshot builder 단위 테스트: SOCState/report fixture → summary/story/navigator/bluf view
  model 결정론 검증.
- Topology policy 테스트: `asset-topology.yaml` schema, node id 중복 없음, edge endpoint 존재,
  degradation mapping 대상 존재.
- Coverage overlay 테스트: observed/current/predicted/gap 중첩 표현 우선순위 검증.
- FastAPI 테스트: `/`, `/api/snapshots`, `/api/topology`, `/events` smoke.
- UI smoke: 정적 HTML/JS가 fixture snapshot 을 렌더하고 story 선택 시 navigator/BLUF/topology가
  함께 갱신되는지 검증.

## 구현 순서 제약
1. `asset-topology.yaml`과 snapshot view model 계약을 먼저 만든다.
2. snapshot builder 를 테스트로 고정한다.
3. FastAPI 서버와 정적 UI 를 붙인다.
4. replay runner 를 demo.py 현대화와 연결한다.
5. SSE live adapter 를 같은 snapshot schema 로 추가한다.

이 순서를 지키면 제출용 라이브 배선은 리플레이 구현을 갈아엎지 않고 전송층만 교체한다.
