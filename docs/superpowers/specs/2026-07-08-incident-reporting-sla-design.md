# 인시던트 보고시한 SLA — CJCSM 6510 상급 보고 데드라인

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (Codex 설계검증 → 구현) |
| 작성자 | s1ns3nz0 |
| 근거 | CJCSM 6510.01B 사이버 인시던트 보고 시한(CAT 별 보고 데드라인) |
| 선행 | Incident Case + CAT 분류(#29/#30/#32) |
| base | `feat/incident-recidivism-cat`(스택 최상단) |

## 1. 배경 & 동기
CJCSM 6510 은 CAT 분류에 **상급 보고 시한**을 건다(CAT1/2/4/7=1시간, 정찰 등=24시간).
우리 Case 는 CAT 를 산정하나 **보고 데드라인·초과 추적**이 없다. CAT 에 SLA 를 매달아
"이 사건 언제까지 보고해야 하나 / 초과했나" 를 결정론 산출한다.

## 2. 목표 / 비목표
### 목표
- `core/policy/incident-reporting-sla.yaml`: CAT → 보고 SLA(분) + 기본값.
- `IncidentCase.report_due_at`(ISO 데드라인) + `report_sla_min`.
- Case CAT 산정 시(observe_alert 잠정 / observe_outcome 권위) **opened_at + SLA(cat)** 로
  데드라인 세팅·재계산(CAT 강화 시 시한 단축).
- `is_case_overdue(case, now)` 결정론 초과 판정 헬퍼.
### 비목표(후속)
- 초과 자동 알림/에스컬레이션 발송(외향 행동 — 운영자·별 모니터링).
- 실 US-CERT/JFHQ-DODIN 제출 커넥터.

## 3. 설계
- `IncidentReportingSla.from_yaml()` — CAT→분 매핑(graceful, 미가용 시 기본만).
- `_report_due(opened_at, cat, sla)` → opened_at(ISO strptime) + timedelta(min) → ISO.
- CaseManager: SLA 정책 보유. observe_alert(잠정 CAT8) + observe_outcome(권위 CAT) 에서
  CAT 세팅 직후 report_due_at/report_sla_min 갱신.
- `is_case_overdue(case, now_iso)`: now > report_due_at(빈값이면 False).
- SLA 기본표(분): CAT1/2/4/7=60, CAT3/6/8=1440(24h). 정책으로 튜닝.

## 4. 트러스트/견고성
- 결정론·읽기전용 산출(데드라인 계산). now 는 호출자 주입(_now_iso). CAT 은 이미
  트러스트 게이팅(권위 CAT=CONFIRMED_TP). 시한은 *제시*지 자동 제출 아님.
- opened_at 파싱 실패/빈값 → report_due_at 빈값(graceful). 정책 미가용 → 기본표.

## 5. 테스트 (`tests/__tests__/test_incident_sla.py`)
- CAT1(권위) → due = opened+60분. CAT8(잠정) → opened+1440분. CAT 강화(8→1) 시 시한 단축.
- is_case_overdue: now>due→True, now<due→False, 빈 due→False.
- 정책 로딩·미가용 graceful.

## 5.1 Codex 설계검증 반영
- **Medium 공유 로더**: IncidentReportingSla.from_yaml 이 `load_policy_mapping`+`require_mapping`
  사용 → malformed-yaml 크래시류 구조적 방지(정책로더 규약 준수).
- **Low 시간포맷/파싱**: `_TS_FMT` 상수 고정(_now_iso 동일 UTC Z), strptime ValueError/TypeError
  → 빈 문자열(graceful). `_int_or` 로 정책 값 안전 변환.
- Info: `_report_due` 순수함수(now 미참조), is_case_overdue 만 now 주입. opened_at 앵커(드리프트 없음). advisory·읽기전용(자동제출 없음).

## 5.2 Codex diff 재검증
Req 2-6 PASS(순수함수·시간포맷·opened_at 앵커·_int_or bool거부·UTC 일관). Medium Req1 부분:
require_mapping(None)→{} 라 **필수 섹션 누락이 조용히 기본값 강등** → `if not sla/mapping:
raise PolicyError` 추가(cato/campaign "비어있음" 규약). _set_report_due 가 SOCPlatformError
catch 해 기본 SLA fallback — config 오류 표면화하되 매니저 레벨 graceful 유지.

## 6. 롤아웃
1. incident-reporting-sla.yaml + IncidentReportingSla + IncidentCase 필드.
2. CaseManager SLA 세팅 + is_case_overdue.
3. Codex 검증(설계→diff) → 게이트.
4. 브랜치 `feat/incident-reporting-sla`, 커밋 `feat(incident): CJCSM 6510 보고시한 SLA(CAT별 데드라인+초과판정)`.
