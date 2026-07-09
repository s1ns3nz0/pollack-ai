# ResponseAgent CACAO 배선 — 카탈로그 선택 + 임무게이트 평가 (design)

**날짜**: 2026-07-09
**작성**: 황준식 (analysis lane)
**상태**: design (Codex 교차검증 대기) · **의존: CACAO 카탈로그 PR 머지 후**

## 1. 목적 / intent

ResponseAgent 는 현재 `alert.defense_playbook`(ad-hoc alert-임베디드)를 실행 표기한다.
CACAO 카탈로그(별 PR — core/cacao.py 모델·validator + cacao-playbooks.yaml)를 **실제
응답에 연결**: alert 의 tactic 으로 카탈로그 플레이북 선택 + **mission-gate if-condition
평가**(#66 MissionRisk)로 임무-분기 resolve → 권고전용 표면. 카탈로그가 LIVE 화된다.

## 2. 결정된 설계 (grill 확정)

| 포크 | 결정 |
|---|---|
| 선택 | `alert.scenario_id` → bas-scenarios tactic → `catalog[tactic]`. 미커버 tactic → `alert.defense_playbook` **폴백**(하위호환). taxonomy 정렬(coa=bas=catalog) — 별칭맵 불요 |
| 평가 | **결정론 AST-evaluator** `evaluate_condition(expr, mission_risk)` + CACAO **workflow 워크**(start→contain→if-condition 평가→분기→eradicate→recover→adapt→end). eval/LLM 금지 |
| 폴백/자율 | mission_risk None → **보수 on_true(HITL) 분기**(fail-safe). on_false(auto-적격) = **라벨만** — 실행은 기존 severity level_meta + approval 게이트 유지. 권고전용 불변(actuator 0) |

## 3. 변경 상세

### 3.1 core/cacao.py (카탈로그 PR 확장)
- `evaluate_condition(expr: str, mission_risk: MissionRisk) -> bool` — `validate_condition`
  과 **동일 AST whitelist** 를 실제 값으로 평가(결정론). 허용 변수만 바인딩:
  `mission_risk.score`, `mission_risk.factors.get(<검증된 임의 키>, 0)`(결측 키 0 —
  crash 방지, civil_geo 는 대표 예), `mission_risk.is_key_terrain`.
  파싱은 validate 가 이미 보장 → 여기선 whitelisted 노드만 평가(Call/Import 없음).
- `select_playbook(tactic, catalog) -> CacaoPlaybook | None`.
- `resolve_playbook(pb, mission_risk | None) -> ResolvedPlan` — workflow 를 start 부터
  워크: action step 은 commands 수집, if-condition 은 `evaluate_condition`(mission_risk
  None → **on_true 보수분기**), on_*/분기 따라 진행, end 까지. 반환 `ResolvedPlan`:
  `playbook_id`, `steps`(순서 action + phase + commands), `mission_branch`
  ("conservative"|"auto"), `hitl_required`(보수분기 시 True).
- 무한루프 방지: 방문 step set(카탈로그는 validator 가 DAG-유효 보장하나 런타임 방어).

### 3.2 scenario_id → tactic 맵
- `core/cacao.py`(또는 bas 재사용): `scenario_tactic_map()` — bas-scenarios 로드,
  `{scenario_id: tactic}`. BASScenario.id/tactic 재사용. 로드 실패 → 빈 맵(폴백 유도).

### 3.3 agents/response_agent.py
- 생성자에 `playbooks: list[CacaoPlaybook] | None`, `scenario_tactic: dict[str,str] | None`
  주입(graph 배선; 로드 실패 → None → 현행 defense_playbook 경로).
- `run()`:
  1. tactic = scenario_tactic.get(alert.scenario_id) (있으면).
  2. pb = select_playbook(tactic, playbooks) (tactic·카탈로그 있으면).
  3. pb 있으면: `plan = resolve_playbook(pb, state.get("mission_risk"))`
     (malformed 워크 → PlaybookError → **defense_playbook 폴백**, Codex M) →
     ResponseResult 에 `cacao_playbook_id`, `cacao_steps`(권고 행동 순서), `mission_branch`.
     **HITL(Codex High 정직화)**: plan.hitl_required 는 **권고 표면**(mr_note). 실제 HITL
     **강제**는 approval 노드(`severity==h` OR `mission_risk.score≥임계`, #66)가 처리하며
     conservative 조건(score≥임계)과 **정렬** → score 기반은 이미 강제됨. `mission_risk
     None` 케이스의 approval 강제는 **후속**(그래프 라우팅 — cacao_hitl_required 를 state
     로 approval 전달). 여기선 권고 표기까지.
     **auto_response**: 기존 severity level_meta + approval 게이트 그대로(분기는 라벨만).
  4. pb 없으면(미커버/로드실패): **현행 defense_playbook 경로**(불변 — 회귀 안전).
- 권고전용: cacao_steps = manual command 서술 표면. actuator 호출 0(카탈로그가 이미
  no-exec 강제, 배선도 실행 안 함).

### 3.4 core/models.py
- `ResponseResult` append-only: `cacao_playbook_id: str | None`,
  `cacao_steps: list[dict[str,object]] | None`(순서 action: phase/commands/nist_ir),
  `mission_branch: str | None`.

### 3.5 graph 배선
- build_soc_graph: `load_playbooks()`(try/except PlaybookError → None) +
  `scenario_tactic_map()` → ResponseAgent 주입. 실패 시 None → 현행 경로.

## 4. 트러스트
- **권고전용 불변**: cacao_steps 는 manual 서술. auto-분기 선택돼도 실행은 severity+
  approval 게이트(#66 HITL). actuator/hack-back 0.
- **fail-safe**: mission_risk 부재 → 보수 HITL 분기(불명=고위험 가정, escalate-only).
- **위조 저항**: forged scenario_id → 오-tactic → 오-플레이북(권고전용·HITL 로 바운드,
  억제 아님). mission-gate 는 #66 MissionRisk(wire 파생이나 escalate-only) 재사용.
- **계약**: bas-scenarios **읽기만**(tactic = analysis 소유 필드). 카탈로그=정적 정책.

## 5. 테스트
- `test_tactic_selects_catalog_playbook`: scenario→tactic→catalog 선택.
- `test_uncovered_tactic_falls_back`: 미커버 → defense_playbook 경로.
- `test_high_mission_takes_conservative_branch`: mission_risk 高 → on_true(HITL).
- `test_low_mission_takes_auto_branch`: 低 → on_false(auto-적격 라벨).
- `test_none_mission_defaults_conservative`: None → 보수 HITL(fail-safe).
- `test_auto_branch_still_severity_gated`: auto-분기여도 approval 거부 시 보류(권고전용).
- `test_evaluate_condition_deterministic`: AST 평가 결정론 + eval 미사용.
- `test_resolve_walks_phases`: contain→recover→adapt step 순서 수집.

## 6. 미결 / 후속
- **CACAO HITL approval 강제(Codex High)**: mission_risk None 시 conservative 분기의
  HITL 을 approval 노드가 강제하려면 CACAO resolve 를 approval 전(前)에 수행하거나
  cacao_hitl_required 를 state 로 approval 에 전달. 별 PR(그래프 라우팅). 현재는 score≥
  임계 정렬로 강제되고 None 은 권고 표기.
- 전체 15전술 카탈로그(별 작업) — 미커버는 폴백.
- 다중-tactic scenario(현 bas 1-tactic) — 확장 시 우선순위.
- 게이트: **카탈로그 PR 머지 후** → Codex 설계리뷰→구현→black/ruff/mypy/pytest→
  clean-worktree→Codex diff→PR/머지.
