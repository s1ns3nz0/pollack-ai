# CISA CIRCIA 72시간 연방 보고

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-09 |
| 상태 | Draft (Codex 설계검증 대기) |
| 근거 | CIRCIA(Cyber Incident Reporting for Critical Infrastructure Act) — covered entity 의 covered cyber incident 72시간 CISA 보고 |
| 선행 | Incident 보고 SLA(CJCSM 6510, report_due_at) — CIRCIA 는 별 연방 경로 |
| base | main(CI green) |

## 1. 배경 & 동기
기존 IncidentReportingSla 는 **상급 지휘체계**(CJCSM 6510 CAT별 분 SLA) 보고다. CIRCIA 는
**연방(CISA)** 별도 의무 — critical infrastructure(방산 UAV) covered entity 는 covered cyber
incident 를 **72시간** 내 CISA 보고해야 한다. 두 경로 병존(상급 ≠ 연방).

## 2. 목표 / 비목표
### 목표
- `core/incident.py`:
  - `_CISA_REPORTABLE_CATS = {"CAT1","CAT4","CAT7"}` — covered cyber incident(root 침해/DoS/악성로직).
  - `is_cisa_reportable(case) -> bool` — **권위**(provisional=False) 중대 CAT 만(트러스트 정합 —
    provisional CAT6/8 은 대상 아님. CJCSM 권위 CAT 과 동일 트러스트 게이팅).
  - `cisa_report_due(case) -> str` — opened_at + 72h(ISO). 파싱실패 빈값(graceful).
  - `is_cisa_overdue(case, now) -> bool` — 72h 시한 초과(결정론·읽기전용, now 주입).
- `IncidentDirective` +`cisa_reportable: bool` +`cisa_report_overdue: bool` → Commander.direct 가
  산출(report 노출·rationale). 자문 — 자동 보고 발송 없음(외향 금지, COA 교리).
### 비목표
- 실제 CISA 제출(외향 — 운영자/별 시스템). ransomware payment 24h 보고(범위 밖).
- covered entity 판정(방산 = covered 가정).

## 3. 트러스트/견고성
- **권위만**: is_cisa_reportable 은 provisional=False + 중대 CAT — untrusted/미확증 case 는 연방
  보고 유발 못함(오보 방지, CJCSM SLA 와 동일 트러스트).
- 결정론·읽기전용·자문. 72h 계산 파싱실패 → graceful(빈값/False). state 불변.

## 4. 설계
- 72h = 4320분. cisa_report_due = _report_due(opened_at, 4320)(기존 헬퍼 재사용).
- Commander.direct: cisa_reportable = is_cisa_reportable(case); cisa_report_overdue =
  is_cisa_overdue(case, now). rationale 추가(reportable/overdue 시).

## 5. 테스트
- 권위 CAT1/4/7 → cisa_reportable True. provisional/그 외 CAT → False.
- 72h 초과 case + now → overdue True. now="" → False.
- Commander directive 에 필드 노출 + rationale.

## 6. 롤아웃
1. incident.py CIRCIA 함수 + IncidentDirective 필드 + Commander 배선 + 테스트.
2. Codex(설계→diff) → 게이트. 브랜치 feat/incident-circia-reporting.
