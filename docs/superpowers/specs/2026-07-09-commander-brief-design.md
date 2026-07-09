# 정보 산출물 — Commander Brief (BLUF 스파인, 결심우위 계층 PR4)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-09 |
| 상태 | 설계(Codex 교차검증 대기) |
| 근거 | Information 기능 — 사이버 정보 산출물을 지휘관에게 제공. 5-PR 스파인 |
| 선행 | PR1 intent_assessment, PR2 decision_advantage, PR3 kill_web_resilience, 기존 report |

## 목표
평판 필드-백(SOCReport)을 **지휘관 결심용 단일 정보 산출물(BLUF)**로 합성. **결정론
템플릿**(LLM 무관 — 환각/인젝션 차단, 재현·감사가능). O/O/D/A 구조 + 결심필요/통상 분리
+ 정직성 전파(각 렌즈의 provisional·unknown·degraded·과장금지 주석을 BLUF 로 승계).
읽기전용·자문. SOC=정보기능(지휘관=인간 외부).

## 데이터 모델
`CommanderBrief`(core/models.py, SOCReport 필드):
- `bluf: str` — Bottom Line Up Front(임무영향 + 확신도 + 권고결심, 결정론 조립).
- `decision_required: list[str]` — intent decision_class=commander_decision 항목·사유.
- `routine: list[str]` — routine_soc 항목(통상 SOC 가시성 — 은폐 아님).
- `ooda: dict[str,list[str]]` — decision_advantage.ooda 승계(브리핑 구조).
- `key_facts: list[str]` — severity/CAT/verdict/campaign/breadth/blind 등 핵심.
- `confidence: Literal["provisional","authoritative","mixed","unknown"]` — 확신도.
- `caveats: list[str]` — 렌즈 정직성 주석 승계(tempo unknown·기법수≠센서·의도 degraded 등).

## 합성 로직 (결정론 템플릿·순수)
`CommanderBriefBuilder.build(report, alert) → CommanderBrief`:
- confidence(정밀): case 없음 → unknown, case.provisional is True → provisional,
  case.provisional is False → authoritative. (mixed 제거 — 단일 case 단일 플래그.)
- bluf: 템플릿 조립 — "[priority] [asset] [verdict/severity] — 임무 [continuity.level],
  [decision_advantage.verdict], 권고: [top COA action]". provisional 이면 "(미확증)"
  명시. 각 조각은 존재하는 필드에서만 **고정 순서**로(graceful — 없으면 생략).
- decision_required/routine(**fail-safe 분기**, Codex High): intent_assessment 가 None
  **또는 intent_available=False** → 전부 decision_required(degraded 도 보수적 상승).
  intent_available 且 decision_class=="routine_soc" → routine. 그 외(commander_decision·
  surfaced) → decision_required(surfaced 도 보수적으로 지휘관 노출).
- ooda: report.decision_advantage.ooda(없으면 빈 맵).
- key_facts: 존재 필드 요약을 **고정 순서**로(verdict/severity/CAT → mission_continuity
  → campaign → kill_web breadth → ground blind → kill_chain). 리스트는 소스 순서 보존,
  set 반복 없음(결정론·감사, Codex Medium).
- caveats: decision_advantage.basis(unknown 사유) + kill_web.rationale(기법수≠센서) +
  intent degraded + provisional 경고 승계.

## 트러스트
- **결정론 템플릿(LLM 무관)** — 지휘관 결심 입력에 환각·인젝션 유입 차단. 재현·감사.
- **합성일 뿐 새 주장 없음** — 기존 authoritative 필드만 재조립. verdict/severity/CAT 불변.
- **정직성 전파(핵심)**: provisional 을 confirmed 로 표기 금지, decision_advantage
  unknown 을 margin 으로 위장 금지, kill_web breadth 를 SPOF-free 로 위장 금지 —
  각 렌즈 caveat 를 BLUF 로 그대로 승계. decision_required 는 표현일 뿐(은폐 아님 —
  routine 도 리포트에 항상 존재).

## 비목표
- LLM 서술(선택 가독요약은 별 — 권위 BLUF 는 결정론). 새 분석(합성만). 자동 대응.

## 배선
CommanderBriefBuilder.build(report, alert)는 **순수 함수**(report 를 읽기만, 변이 없음)
— CommanderBrief 를 반환. report_agent 가 report.commander_brief 단일 필드에만 대입
(다른 필드 무변경, Codex Medium). metric 없음(합성 뷰). BLUF 는 산출물 자체.
