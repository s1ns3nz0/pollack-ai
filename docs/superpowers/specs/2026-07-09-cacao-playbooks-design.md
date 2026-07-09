# CACAO 대응 플레이북 카탈로그 — 표준 기반 임무영향 중심 (design)

**날짜**: 2026-07-09
**작성**: 황준식 (analysis lane)
**상태**: design (Codex 교차검증 대기)

## 1. 목적 / intent

Response agent 는 현재 `alert.defense_playbook`(id/actions/failover, ad-hoc alert-임베디드)를
실행 표기한다. 표준 기반·기법 키잉·임무영향 게이팅된 **플레이북 카탈로그**가 없다. 이
기능이 **먼저 플레이북(카탈로그+스키마+검증)** 을 만든다(response agent 재배선은 후속).

**표준 7층 레이어링:**
| 층 | 표준 | 역할 |
|---|---|---|
| 스키마 | **OASIS CACAO 2.0** | playbook 객체·workflow step·external_references·labels |
| 통제 | **NIST SP 800-53 IR-1~9 + IR-4(11)**(IR-10 Rev5 폐지→IR-4(11) 흡수) | 스텝별 IR 통제 태그(추적성) |
| 생애주기 | **NIST SP 800-61**(r2 lifecycle — r3 대체됨, 호환 위해 r2 용어 유지 명시) | Contain·Eradicate·Recover 단계 |
| 복구방법론 | **NIST SP 800-184** | Recover 단계 = 전술복구(evict/restore) + **검증**(outcome_probe 재발) + 복구메트릭 |
| 회복탄력 | **NIST SP 800-160v2 R1** | 목표(Withstand=임무지속·Recover·**Adapt**) + 기법(Redundancy·Diversity·Deception·Segmentation·Non-Persistence) → **Adapt 단계** |
| 트리거 | **MITRE ATT&CK for UAV** | 전술 키잉 + step.external_references 로 기법 연결 |
| 게이팅 | **임무영향** (MissionRisk #66·degradation) | if-condition 분기 + HITL |

**phase 모델**: `Contain → Eradicate → Recover(800-184) → Adapt(800-160v2)`. Recover 는
축출·복원 후 outcome_probe 재발관측으로 **검증**(재발=축출실패→재발령). Adapt 는 회복탄력
기법으로 **재발방지 재구성**(예: nav 이중화 페일오버=Redundancy, C2 세그먼트화=Segmentation,
키회전=Non-Persistence, 미끼배치=Deception). Withstand(임무지속)는 degradation graceful-
degrade 로 이미 반영 — 임무영향 중심 = 사이버 회복탄력의 UAV 구현.

## 2. 결정된 설계 (grill 확정)

| 포크 | 결정 |
|---|---|
| CACAO 충실도 | **권고전용 정합** — CACAO command `type="manual"`(인간 실행) = 권고전용 그 자체. actuator/agent 자동 dispatch 없음. **서브셋 아닌 표준 완전 정합** |
| granularity | **전술별(15)** CACAO 플레이북. step.commands 를 coa-matrix(7D)·recovery-matrix 에서 소싱(기존 메뉴 통합). 기법은 step.external_references |
| 임무 게이트 | CACAO **if-condition 스텝**이 MissionRisk/degradation 으로 분기: 고-임무위험/민간 → HITL 보수변형(auto-RTB 금지, ROE failsafe); 저 → auto-적격 |
| 스코프 | 스키마/모델(core/cacao.py) + validator + UAV ATT&CK 15전술 CACAO 카탈로그 + 테스트 |

## 3. 변경 상세

### 3.1 core/cacao.py — CACAO 2.0 **완전정합** 모델 + validator (Codex High 반영)
- `CacaoExternalReference`: source_name(mitre-attack|nist-800-53|nist-800-61|nist-800-184|
  nist-800-160v2), external_id, url(**https 필수·표준도메인**), description(길이상한).
- `CacaoCommand`: type=**"manual" 고정**(CACAO 인간 실행). command(서술, 길이상한).
  **금지(Codex M3)**: `command_b64`·실행형 type(bash/http-api/openc2/…)·auth 자료·
  machine agent·live target — validator 가 거부(정적 권고 카탈로그 = 실행불가 보장).
- `CacaoStep`: type(**start|action|if-condition|end** — CACAO 정식 타입, `single` 아님).
  action step: name, description, commands(≥1 manual), agent(="uav-soc-analyst" 인간
  role), targets(생략/비실행), on_completion, external_references, labels(nist_ir·phase·
  resiliency_technique·**source_ref**). if-condition: condition(아래 계약), on_true/on_false.
  start/end: 필수 존재.
- `CacaoAgentDefinition`: type="individual"(인간 분석가 role) — machine/http agent 금지.
- `CacaoPlaybook`(CACAO 필수필드 완비): type="playbook", spec_version="cacao-2.0",
  id("playbook--{uuid}"), name, description, **created·modified**(ISO8601), created_by,
  **playbook_types**(CACAO vocab 예 ["mitigation","remediation"]), **playbook_activities**
  (vocab, 각 워크플로 step 반영 — Codex H2), tactic(카탈로그 키 — **coa/attack_coverage
  키와 정확 일치**, 예 `InhibitResponseFunction`), workflow(dict, **start·action·end 체인**),
  workflow_start(→start step), agent_definitions, external_references, labels.
- **mission-gate 평가계약(Codex M4 — 지금 정의)**: if-condition.condition 은 **결정론
  화이트리스트 미니-표현식**(eval/exec 절대금지). 허용 변수: `mission_risk.score`(int),
  `mission_risk.factors.civil_geo`(int), `mission_risk.is_key_terrain`(bool). 허용 연산:
  비교(>=,>,==)·and/or·정수리터럴. **AST 파싱 + 노드 whitelist**(core/cacao.py 파서).
  평가 주체 = 후속 response_agent(#66 MissionRisk 주입). 이 PR 은 **파싱·검증만**(평가 X).
- **validator** `validate_playbook(pb)`:
  1. CACAO 필수필드·start/end 존재·workflow_start→start·모든 on_*/분기 유효참조.
  2. playbook_types populated → playbook_activities ≥1 且 step 반영(H2).
  3. external_references **앵커 regex**: mitre-attack `^(AML\.)?T\d{4}(\.\d{3})?$`,
     nist-53 **화이트리스트**(IR-1..IR-9, IR-4(11)), url https·표준도메인, 길이상한.
  4. **no-exec 불변식**: 전 command.type=="manual" + 금지항목(M3) 부재.
  5. phase 커버: contain·eradicate·recover·adapt(recover 는 검증 step 포함, 800-184).
  6. 고-임팩트 전술 mission_gate if-condition ≥1 + condition AST whitelist 통과.
  7. IR 태그 필수(실행 step). **source_ref 해결**: 각 action 의 source_ref(예
     `coa:Impact:Deny`·`recovery:Impact:evict:0`)가 실제 coa/recovery 매트릭스 셀에
     존재(Codex M6 — 복사 아닌 단일출처 참조·drift 탐지).
  실패 시 `PlaybookError`(SOCPlatformError 하위).
- `load_playbooks(path=None)`: yaml.safe_load → Pydantic → 전 항목 validate.

### 3.2 core/policy/cacao-playbooks.yaml — exemplar 카탈로그
전술별 CACAO 플레이북. **exemplar 3전술**(고-임무영향):
- **Impact**(T0827 Loss of Control·T0831 Manipulation of Control·T0880 Loss of Safety·
  T1495 Firmware Corruption 등): contain(coa Deny/Disrupt) → **if mission_gate**(고위험·
  민간 → HITL failsafe/graceful-degrade[degradation-matrix]; else auto RTB) → eradicate
  (recovery evict) → recover(recovery restore/verify + **검증**: outcome_probe 재발관측
  [800-184]) → **adapt**(회복탄력 기법[800-160v2] — nav 이중화·C2 세그먼트·키회전·미끼).
- **ImpairProcessControl**(T0836 Modify Parameter·T0806 Brute Force I/O·T0855 Unauth
  Command 등): 파라미터 롤백·명령 인증 강화.
- **InhibitResponseFunction**(T0814 DoS·T0878/T0838 Alarm·T0816 Restart 등): 알람 무결성
  복원·이중화 페일오버. ⚠ recovery-matrix 에 `InhibitResponseFunction` entry **부재
  (Codex M6)** → exemplar 전 recovery-matrix 에 해당 tactic evict/restore/verify 추가.
- **tactic 키는 coa-matrix/attack_coverage 와 정확 일치**(InhibitResponseFunction·
  ImpairProcessControl·Impact — Low#7). 별칭 없음.
- 각 action step: external_references(ATT&CK 기법 + IR 통제 + 800-61 phase +
  800-184/160v2), labels(nist_ir·phase·resiliency_technique·source_ref), agent=인간role,
  manual commands(coa/recovery **source_ref 로 참조**). start→...→end 정합 체인.

### 3.3 트러스트 / 교리
- **권고전용**: 전 command `type="manual"` — validator 강제. 자동 actuator/hack-back 0.
  CACAO 표준의 manual step = 인간 실행이라 표준 위배 아님.
- **임무영향 중심**: if-condition mission_gate 가 고-임무위험/민간블라스트에서 auto 대응
  차단 → HITL failsafe(#66 HITL·MissionRisk 재사용). 저위험만 auto 적격.
- 카탈로그는 **정적 정책**(로드시 1회 validate). alert wire 무관 — 계약 파일 0개.
- 기존 coa/recovery-matrix 문구 재사용(중복 아님 — CACAO 실행포맷으로 통합).

## 4. 테스트 (`tests/__tests__/test_cacao.py`)
- `test_exemplars_load_and_validate`: 3 exemplar 로드 + validate 통과.
- `test_cacao_conformance`: 필수필드(created/modified/spec_version/playbook_activities)·
  start/action/end 타입·workflow_start→start(Codex H1/H2).
- `test_workflow_refs_resolve`: 모든 on_*/분기가 유효 step/end.
- `test_external_references_anchored`: ATT&CK/IR 앵커 regex·IR 화이트리스트(IR-10 거부)·
  url https(Codex M5/L8).
- `test_no_exec_invariant`: manual 아닌 type·command_b64·machine agent·live target →
  PlaybookError(Codex M3).
- `test_mission_gate_parser_whitelist`: 허용식 파싱 통과 + `__import__`/함수호출/미허용
  변수 → PlaybookError(eval 금지·AST whitelist, Codex M4).
- `test_phase_coverage`: contain/eradicate/recover/adapt 라벨 + recover 검증 step.
- `test_ir_control_tagged`: 실행 step nist_ir 라벨.
- `test_source_ref_resolves`: action.source_ref 가 coa/recovery 실 셀에 존재(Codex M6).
- `test_tactic_key_matches_matrix`: tactic 키가 coa-matrix 키와 일치(Codex L7).
- `test_invalid_playbook_raises`: 잘못된 참조/누락 → PlaybookError.

## 5. 미결 / 후속
- UAV ATT&CK 15전술 CACAO 플레이북 작성 완료.
- **response_agent 배선**: alert.defense_playbook 대신 카탈로그에서 tactic+mission 으로
  선택·표면(if-condition 평가 = MissionRisk). 별 PR.
- CACAO signatures/data-marking(coalition 공유) — 후속(releasability 연계).
- 게이트: 스펙→Codex 설계리뷰→반영→구현→black/ruff/mypy/pytest→clean-worktree→
  Codex diff 리뷰→커밋/PR/머지.
