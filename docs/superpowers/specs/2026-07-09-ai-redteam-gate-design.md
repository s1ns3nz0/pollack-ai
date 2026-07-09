# AI 레드팀 결정론 회귀 게이트 — 인젝션 가드 상시 검증

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-09 |
| 상태 | 구현 완료(Codex diff 검증) |
| 근거 | MITRE ATLAS AML.T0051, BAS(Breach & Attack Simulation) 교리의 AI 확장 |
| 선행 | core/prompt_guard.py(인젝션 가드), core/bas.py(방어 상시검증 미러) |

## 목표
프롬프트 인젝션 가드(#40~49)가 **실제 공격을 표식하고 정상 SOC 문구를 무탐(FP 없음)**
하는지 결정론 시나리오로 상시 검증(BAS 의 AI 버전). 가드 회귀(패턴 약화/FP 증가) 시 이
게이트가 실패 → CI 에서 잡는다. 자문·읽기전용·결정론(외향 없음).

- `core/ai_redteam.py`: AiRedTeamRunner(cases, guard) → AiRedTeamReport(passed/failures/
  by_expect). expect: high(high_confidence)|detected(detected)|benign(무탐).
- 정책 `ai-redteam-scenarios.yaml`: active(score강제/fence breakout)·detected(ignore/role/exfil)·
  benign(정상 GNSS/ML score/공격묘사) 케이스. 공유 policy_loader(graceful).
- 테스트가 CI 게이트 — 기본 가드가 전 케이스 통과(회귀 0) 강제. degraded 가드는 실패로 노출.

## 비목표
- 실 LLM 공격(PyRIT/Garak 오케스트레이션 — 별). 가드 자동 개선. report 배선(standalone 게이트).

## 트러스트
- 결정론·읽기전용. guard 주입(기본 정책). 정책 실패 → PolicyError(graceful).
