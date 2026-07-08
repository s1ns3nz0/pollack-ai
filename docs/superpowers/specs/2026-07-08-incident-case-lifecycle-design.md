# Incident Case 생명주기 — alert-driven → case-driven (DoD SOC 정렬)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (grill 완료, Codex 설계검증 → 구현) |
| 작성자 | s1ns3nz0 |
| 근거 | DoD CSSP tiered SOC, NIST 800-61 인시던트 생명주기, CJCSM 6510.01B CAT 분류 |
| 선행 | actor 프로필([[attacker-profile-store]]), CorrelatedIncident, campaign, kill chain |
| base | `feat/observability-new-signals`(스택 최상단) |

## 1. 배경 & 동기
DoD SOC 는 **case-driven** — 흩어진 이벤트를 하나의 관리 Incident Case 로 봉합해
상태(NEW→…→CLOSED)로 진행시키고 CAT 분류 + 보고시한을 건다. 우리는 **alert-driven
선형 파이프라인**(per-alert Report 로 끝)이라 Case 엔티티가 없다. Tier3 헌팅·Incident
Commander·CAT 보고가 전부 Case 위에 얹히므로 Case 가 정렬의 심장.

## 2. 목표 / 비목표 (MVP) — Codex 설계검증 반영(트러스트 재정렬)
**핵심 재조정**: report 노드(hotpath)는 **PROVISIONAL 상태만** 다룬다. in-pipeline verdict
는 default_judge 가 `ground_truth`(기본 TP) 반환이라 위생처리 alert 도 자기확증 TP 가
되므로(Codex C1), **CONTAINMENT·권위적 CAT(1/2/7)는 report 에서 금지**하고 신뢰관측
(OutcomeProbe CONFIRMED_TP)으로만 도달(후속). alert 필드가 CAT/severity 조작(C2)도 차단.

### 목표
- **actor-centric 봉합** — `resolve_actor_id(alert)`(빈 fp 제외). report 의 actor_id-only
  recall 아님(위생 alert 은 fingerprint, Codex M7).
- **PROVISIONAL 상태머신**: NEW→ANALYSIS (report 최대). 명시 전이표(허용 edge), 단조.
- **잠정 CAT**: 정찰(order≤2)→CAT6, 그 외→CAT8(investigating). 권위 CAT1/2/7 은 후속.
- **모듈 싱글톤 store + 하드캡 + LRU**(그래프 매요청 재생성 회피, DoS 봉인, Codex H3/H4).
- `core/incident.py` + `SOCReport.incident_case`.
### 비목표(후속)
- **CONTAINMENT→ERADICATION→RECOVERY→CLOSED 및 권위 CAT** — OutcomeProbe 신뢰관측 채널.
- CLOSED 재개방(재범), incident 메트릭, 서명, Incident Commander, 보고시한 SLA.
- CorrelatedIncident/campaign 흡수·대체 금지 — 참조만(Codex L8).

## 3. 설계
```
core/incident.py:
  IncidentState(StrEnum): NEW/ANALYSIS/CONTAINMENT/ERADICATION/RECOVERY/CLOSED
  IncidentCase(BaseModel): case_id, actor_id, state, cat, severity_peak,
                           kill_chain_stage, member_alert_ids, opened_at, updated_at,
                           provisional: bool  (report 산 = True; 신뢰확증 전)
  IncidentStore(Protocol) + InMemoryIncidentStore(cap+LRU)
  _STORE = InMemoryIncidentStore()  # 모듈 싱글톤(그래프 매요청 재생성 무관)
  incident_store() -> IncidentStore
  CaseManager: observe_alert(alert, severity) -> IncidentCase | None
```
- **봉합**: `resolve_actor_id(alert)` → 빈 fp 면 None(미개설). report 노드 recall 패턴 금지.
- **전이표(허용 edge만)**: NONE→NEW, NEW→ANALYSIS. **report 는 ANALYSIS 최대**. 단조(`_STATE_ORDER` max, 후퇴 불가). CONTAINMENT+ 는 report 에서 도달 불가(전이표에 edge 없음).
- **잠정 CAT 순서 결정표**(precedence, 첫 매치): recon(order≤2)→CAT6, 그 외→CAT8. 권위
  CAT1/2/7 은 신뢰확증 후속에서만.
- **severity_peak/member/kill_chain_stage** 누적(provisional — informational).

## 4. 트러스트/견고성 (Codex 반영)
- **C1/C2/M5**: report 노드는 CONTAINMENT·권위 CAT 절대 불가. in-pipeline verdict(자기확증
  TP 가능)로 격상 안 함. 신뢰확증(CONFIRMED_TP)은 후속 OutcomeProbe 채널 전담.
- **H3 DoS**: fingerprint 차원(mitre/signals/ioc) 변조로 무한 fp 생성 가능 → **하드캡
  (기본 1000) + LRU eviction** 을 store 에서 강제. 빈 fp 미개설. (per-tenant 는 후속.)
- **H4 싱글톤**: build_soc_graph 가 매요청 호출되므로 store 는 **모듈 싱글톤**(_STORE).
  그래프가 만드는 게 아니라 `incident_store()` 참조.
- **단조 전진** — 전이표 + state order max.

## 5. 배선
- graph: `CaseManager(incident_store())` → ReportAgent 주입(싱글톤 store 참조).
- ReportAgent.run: `case = self._case_mgr.observe_alert(alert, severity)` → `SOCReport.incident_case`(provisional).
- 미주입/빈 fp → None(무영향).

## 6. 테스트 (`tests/__tests__/test_incident.py`)
- 봉합: 동일 actor 다수 alert → 한 Case, member 누적.
- 상태: open→NEW, ANALYSIS, TP→CONTAINMENT, 단조(FP 후 재 alert 후퇴 안 함).
- CAT: kill_chain_advanced→CAT1, FP→CAT3, recon→CAT6.
- 빈 fp → Case 미개설(None). DoS: 위조 폭주가 자기 fp 한 case.
- graph end-to-end → report.incident_case 노출.

## 6.1 Codex 설계검증 반영
| 지적 | 반영 |
|---|---|
| C1 hotpath verdict 자기확증→CONTAINMENT | 전이표에서 CONTAINMENT edge 제거 — report 는 NEW→ANALYSIS 최대 |
| C2 untrusted 필드가 CAT/severity 조작 | 잠정 CAT(6/8)만·provisional 플래그. 권위 CAT1/2/7 은 후속 신뢰확증 |
| H3 fingerprint DoS 무한 | store 하드캡(1000)+LRU eviction + 빈 fp 미개설 |
| H4 그래프 매요청 재생성→store 리셋 | 모듈 싱글톤 `_STORE`/`incident_store()` |
| M5 상태 스킵 | 전이표(허용 edge) + state order max 단조 |
| M6 CAT 중첩/precedence | 순서 결정표 첫매치(recon→CAT6, else CAT8) |
| M7 report recall 패턴 | `resolve_actor_id` 봉합(actor_id-only recall 아님) |
| L8 CorrelatedIncident 중복 | 흡수 안 함 — 별개 유지(후속 참조) |

## 6.2 Codex diff 재검증(구현 후) 반영
원 이슈 6개 중 1·3·4·5·6 FIXED 확인. 신규/잔여:
- Medium: `incident_case: object` → **IncidentCase/IncidentState 를 models.py 로 이동** →
  `IncidentCase | None` 정타입(순환 해소, pydantic 검증 복원).
- Medium: 공백 explicit actor_id("   ") 우회 → guard `not actor_id or is_empty_fingerprint`.
- Low: CAT6 도달불가(_alert_stage 이진) → **CoverageMatrix 로 실제 order** 산정(정찰→CAT6).
- C2-residual(severity_peak): provisional·informational, baseline=탐지소스 필드(inbound
  경계 결정과 동일 부류, 권위 판정 비구동) → 주석 명확화 + provisional 표식. 수용.

## 7. 롤아웃
1. core/incident.py + SOCReport.incident_case.
2. report 봉합 + graph 배선.
3. Codex 검증(설계→diff) → black/ruff/mypy/pytest.
4. 브랜치 `feat/incident-case-lifecycle`, 커밋 `feat(incident): actor-centric Incident Case 생명주기 MVP(NIST 800-61 + CJCSM 6510 CAT)`.
