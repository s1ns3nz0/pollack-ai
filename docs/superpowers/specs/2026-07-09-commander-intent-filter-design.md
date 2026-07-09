# 임무형 지휘 — Commander's Intent 필터 (지휘관 결심우위 계층 PR1)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-09 |
| 상태 | 설계(Codex 교차검증 대기) |
| 근거 | DoD 임무형 지휘(Mission Command) — 분권 실행/의도 기반. 결심우위 정보 계층 5-PR 중 1 |
| 선행 | core/incident.py(IncidentCase cat/provisional), core/commander.py(HITL 게이트), asset-tiers.yaml |

## 목표
지휘관이 사전 선언한 **의도(intent)** 로 SOC 산출물을 우선순위화하고 "지휘관 결심 필요"
vs "SOC 위임 처리"를 자문 판정한다. 결정론·읽기전용·외향 없음. 지휘관=인간(외부),
SOC=정보기능(자문). 기존 트러스트 교리 100% 보존.

## 스코프(스파인+렌즈 중 렌즈 #1)
CommanderBrief(PR4) 이 소비할 **입력 필터**. 이 PR 은 IntentFilter assessor + 정책 +
SOCReport 배선까지. BLUF 합성은 PR4.

## 데이터 모델
`core/policy/commander-intent.yaml`(신규):
```yaml
# 지휘관이 사전 선언. 라이브 외부상태 아님(정적 교리 입력).
main_effort_assets: [SATCOM-link, ISR-payload]   # 주력 — 항상 지휘관 상승
protected_scenarios: [S9-SATCOM-DISABLE]          # scenario_id 매칭(Codex Low: 분리)
protected_mission_phases: [strike]                # mission_phase 매칭(분리)
risk_tolerance: low                               # low|medium|high (참고·rationale)
# CAT 은 서열 아님(CAT1 root/CAT4 DoS/CAT7 malware) → 임계 아닌 명시 집합.
surface_cats: [CAT1, CAT2, CAT4, CAT7]            # 지휘관 결심 상승 대상
delegate_cats: [CAT3, CAT6, CAT8]                 # (authoritative 확정 시) 통상 SOC 처리
```

정책 스키마 검증(Codex M2 — `CommanderIntent` pydantic 모델, 로드 시 강제):
- `surface_cats`·`delegate_cats` 는 알려진 CAT 어휘 `{CAT1,CAT2,CAT3,CAT4,CAT6,CAT7,
  CAT8}` 만 허용(미지 CAT → PolicyError). 중복 정규화(set).
- **surface_cats ∩ delegate_cats = ∅**(겹치면 PolicyError — 모순 게이팅 봉쇄).
- `risk_tolerance ∈ {low,medium,high}`(그 외 PolicyError).
- 파일/파싱/**의미(schema)** 실패 전부 = intent_available=False + 전부 surfaced
  (fail-safe, delegate 비활성). 공유 policy_loader.

`IntentAssessment`(core/models.py, SOCReport 필드):
- `priority: Literal["main_effort","routine"]` — 주력 자산/보호 임무 매칭 여부.
- `decision_class: Literal["commander_decision","routine_soc","surfaced"]` —
  상승 / 통상 SOC 가시성 / 기본노출. **셋 다 표현(presentation) 메타데이터일 뿐**.
- `matched: list[str]` — 매칭 근거(자산/임무/CAT — rationale·감사).
- `intent_available: bool` — 정책 로드 여부(degraded 관측).

**`routine_soc` 정규 규약(Codex M1 — 권한 creep 봉쇄):** "지휘관 결심 불요"를
뜻할 뿐 **억제 권한이 아니다**. 모든 항목은 SOCReport·감사 데이터에 **항상 존재**한다.
`routine_soc` 는 IncidentDirective.hitl_required·보고 의무·지휘관 full-view 를
**절대 override 하지 않는다**. 하위 소비자(PR4 BLUF 등)의 필터링은 가역적 표현
필터(commander 가 full-view 요청 시 전량 복원)만 허용 — 데이터 삭제·은폐 금지.

## 판정 로직 (비대칭 게이팅 — 핵심 불변식)
IntentFilter.assess(alert, case) → IntentAssessment:
1. **priority**: alert.asset_id ∈ main_effort_assets, 또는 alert.scenario_id ∈
   protected_scenarios, 또는 alert.mission_phase ∈ protected_mission_phases →
   "main_effort", else "routine". (전부 wire 필드지만 매칭은 가시성만 ↑ — 안전방향.)
2. **decision_class**(우선순위 순):
   - priority=="main_effort" → **commander_decision**(주력은 CAT 무관 항상 상승).
   - case.cat ∈ surface_cats → **commander_decision**(provisional∪authoritative 둘 다
     — fail-safe 가시성, 위조 신호도 상승).
   - case.cat ∈ delegate_cats **AND** case.provisional=False(authoritative 확정) →
     **routine_soc**(통상 SOC 가시성 — 은폐 아님). provisional 이면 routine_soc 안 됨.
   - 그 외 → **surfaced**(기본 노출 — 보수적).
3. case 없으면(무사건) priority만 산정, decision_class="surfaced".

## 트러스트 불변식
- **비대칭**: surface 는 provisional 로도 발동(가시성 fail-safe), delegate 는
  authoritative 확정에만(위조 provisional 저CAT 로 '알아서 처리' 위장→지휘관 시야에서
  은폐 차단). 기존 commander.py HITL 게이트(authoritative+HIGH_CAT)와 동일 교리.
- 결정론·읽기전용·total(예외 불가). 정책 로드 실패 → intent_available=False + 전부
  surfaced(fail-safe, 위임 비활성). 공유 policy_loader(graceful).
- IntentFilter 는 verdict/severity/CAT 을 **바꾸지 않음** — 순수 우선순위·노출 자문.

## 비목표
- BLUF 합성(PR4). 실제 상승/위임 실행(자문만 — 지휘관/운영자 행동). intent 동적 주입.
- IncidentDirective 대체(보완만 — Directive 는 CAT/티어, Intent 는 지휘관 우선순위).

## 배선
report_agent 가 case 산정 후 IntentFilter.assess → SOCReport.intent_assessment.
정책은 로드 시 1회 캐시(정적 교리). metric: soc_commander_decision_total(상승 건).
