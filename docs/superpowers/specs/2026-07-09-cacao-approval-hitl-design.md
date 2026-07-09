# CACAO 보수분기 HITL approval 강제 (design)

**날짜**: 2026-07-09 · **작성**: 황준식 (analysis lane) · **상태**: design

## 1. 목적
PR#76 후속(Codex High): ResponseAgent 의 CACAO 보수분기 HITL(특히 mission_risk None
fail-safe)이 **approval 노드 뒤**라 실제 interrupt 로 강제되지 않았다. approval 노드가
CACAO 보수분기를 **직접 게이트**하게 해 fail-safe HITL 을 실효화한다.

## 2. 설계
- **core/cacao.py**: `playbook_requires_hitl(pb, mission_risk | None) -> bool` —
  `resolve_playbook(pb, mr).hitl_required`. PlaybookError(malformed) → **True**(fail-safe,
  불명=인간). mission_risk None → resolve 가 보수분기 → True.
- **agents/approval_agent.py**: 생성자에 `playbooks`·`scenario_tactic` 주입(옵션, None →
  현행). run() 인터럽트 조건 확장:
  `force_cacao` = 카탈로그 있고 alert 전술 플레이북 있으면 `playbook_requires_hitl`.
  `if not (force_high or force_mission or force_cacao): auto-approve`. reason 에 cacao 표기.
- **agents/graph.py**: ApprovalAgent 에 이미 로드한 `_playbooks` + `scenario_tactic_map()`
  주입(ResponseAgent 와 동일 인스턴스/맵 — 이중 로드 없음).

## 3. 트러스트
- **escalate-only**: CACAO 보수분기 → **interrupt 추가**(강제만, 제거 없음). mission_risk
  None → fail-safe interrupt(불명=고위험 가정). malformed 플레이북 → interrupt(안전).
- score≥임계는 기존 force_mission 과 정렬(중복 무해). 미커버 전술/미주입 → 현행 불변(회귀).
- 위조 scenario→전술→플레이북은 과-게이트(권고전용·안전) 방향.

## 4. 테스트
- `test_cacao_conservative_forces_interrupt`: mission_risk None + Impact 전술 → interrupt.
- `test_cacao_auto_branch_no_force`: 低 임무위험(auto 분기) + severity<h → 자동승인.
- `test_malformed_playbook_forces_interrupt`: resolve 실패 → interrupt(fail-safe).
- `test_uncovered_tactic_uses_existing_gates`: 미커버 → 기존 severity/score 게이트만.
- 기존 approval 테스트(severity h·score 임계) 회귀 불변.

## 5. 후속
- 15전술 확장 시 자동 적용. 게이트: 구현→black/ruff/mypy/pytest→clean-worktree→Codex diff.
