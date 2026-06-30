# 에이전트별 KPI 정리

- **Status**: Done
- **담당자**: 김수지
- **우선순위**: High
- **마감일**: 2026-06-21
- **URL**: https://app.notion.com/p/37ff5e835bb4812c9075f893975bd8e4

---

| **에이전트** | **핵심 역할** | **핵심 KPI (성과 지표)** |
|---|---|---|
| **Triage Agent** | 유입된 이벤트의 우선순위 분류 | **초기 대응 시간 (Mean Time to Triage)** — 유입된 위협을 얼마나 빠르게 우선순위 분류했는가 |
| **Investigation Agent** | 공격 패턴 심층 분석 및 문맥 파악 | **분석 정확도 (Confidence Score)** — AI 분석 결과가 얼마나 높은 신뢰도를 갖는가 |
| **Validation Agent** | 정탐/오탐 최종 판별 | **오탐율 (False Positive Rate)** — 정탐과 오탐을 얼마나 정확히 구분했는가 |
| **Rule Update Agent** | 오탐 시 룰셋 최적화 및 수정 | **룰 수정 반영 속도 (Rule Deployment Time)** — 기존 룰의 빈틈을 얼마나 선제적으로 보완했는가? 기존 시나리오를 바탕으로 몇 개의 시나리오를 추가적으로 만들었는가?, 해당 룰의 정오탐률은? |
| **Response Agent** | 정탐 시 자동 대응 실행 | **공격 차단 및 복구에 걸린 시간** |
| **Report Agent** | OSCAL 기반 결과 아카이빙 | **보고서 작성 자동화 시간 (Report Latency)** — OSCAL 기반의 결과 보고서 작성 자동화 시간 |

---

참고: [AI SOC정의, 구성 요소 및 아키텍처](https://stellarcyber.ai/ko/learn/what-is-ai-soc/)

## 갱신본 — 측정 가능 KPI (방어 전략 25점 / AI 에이전트 25점 대응)
> 정성 서술 → 지표명 + 정의 + 측정식 형태로 구체화. 심사 기준 "실현 가능성" 방어용.

| **에이전트** | **핵심 역할** | **핵심 KPI (지표명 · 정의 · 측정)** |
|---|---|---|
| **Triage Agent** | 유입 이벤트 우선순위 분류 | **MTTT (Mean Time To Triage)**: Alert 생성 → 우선순위(H/M/L/I) 부여까지 소요 시간 / 측정: `IncidentTriagedTime - AlertGeneratedTime` 평균. **Triage 정확도**: 부여 우선순위가 최종 판정과 일치한 비율 |
| **Investigation Agent** | 공격 패턴 심층 분석·문맥 파악 | **Confidence Score**: 분석 결론 신뢰도(0~1), 근거 아티팩트 수·TI 매칭률 기반. **Context Completeness**: 수집 엔티티 / 필요 엔티티(자산·계정·IoC) |
| **Validation Agent** | 정탐/오탐 최종 판별 | **FPR (False Positive Rate)**: FP / (FP+TP). **FNR (False Negative Rate)**: 미탐 비율 = 레드팀 주입 공격 대비 미탐지율. Precision·Recall 동시 추적 (오탐만 줄이면 미탐 증가) |
| **Rule Update Agent** | 오탐 시 룰셋 최적화·신규 룰 생성 | **MTTR-Rule**: 오탐 확인 → PR 머지·배포까지 시간. **Rule Effectiveness**: 배포 전후 FPR 델타 (동일 패턴 재오탐 감소율). **Coverage Gain**: 신규 룰이 커버한 MITRE TTP 수 |
| **Response Agent** | 정탐 시 자동 대응 실행 | **MTTC (Mean Time To Contain)**: 정탐 확정 → 차단/격리 완료까지 시간. **Playbook Success Rate**: 성공 실행 / 전체 (실패 시 Human 에스컬레이션 비율 병기) |
| **Report Agent** | OSCAL 기반 결과 아카이빙 | **Report Latency**: 사건 종결 → OSCAL 보고서 생성까지 시간. **Evidence Completeness**: 매핑 통제 / 요구 통제 |

## KPI 검증 출처 (Ground Truth)
> 객관적(타임스탬프·로그) vs LLM 자체평가 구분. 심사 "이 점수 믿을 만한가" 질문 대비.

| **에이전트** | **KPI** | **측정식** | **검증 출처** |
|---|---|---|---|
| Triage | MTTT | `TriagedTime − AlertGeneratedTime` | Sentinel Incident 타임스탬프 (객관적) |
| Triage | Triage 정확도 | 일치 우선순위 / 전체 | Validation Agent 최종 판정 라벨 |
| Investigation | Confidence Score | 근거 아티팩트·TI 매칭 (0~1) | ⚠ LLM 자체평가 → 레드팀 ground truth 라벨과 대조 |
| Investigation | Context Completeness | 수집 엔티티 / 필요 엔티티 | 시나리오별 필수 엔티티 체크리스트 (사전 정의) |
| Validation | FPR | FP / (FP+TP) | 레드팀(김동언) 주입 공격 = 정답 라벨 |
| Validation | FNR | 미탐 / 전체 정탐 | 레드팀 공격 주입 로그 |
| Rule Update | MTTR-Rule | PR 머지·배포 − 오탐 확인 | GitHub PR 타임스탬프 (객관적) |
| Rule Update | Rule Effectiveness | 배포 전후 FPR 델타 | 재실행 시 동일 패턴 재오탐 수 |
| Rule Update | Coverage Gain | 신규 룰 커버 TTP 수 | MITRE ATT&CK for ICS 매핑 |
| Response | MTTC | `ContainedTime − ValidatedTime` | Sentinel/플레이북 실행 로그 (객관적) |
| Response | Playbook Success Rate | 성공 실행 / 전체 | Automation Rule 실행 결과 코드 |
| Report | Report Latency | OSCAL 생성 − 사건 종결 | 파이프라인 로그 (객관적) |
| Report | Evidence Completeness | 매핑 통제 / 요구 통제 | OSCAL 카탈로그 (NIST 등 사전 정의) |

> **의존 구조 메모**: 레드팀 주입 로그가 블루팀 KPI 전체의 정답지. FPR·FNR·Triage 정확도·Confidence 검증이 전부 "김동언이 무슨 공격을 언제 넣었는지"에 묶임 → 레드팀↔블루팀 공격 주입 로그 공유가 KPI 측정의 전제 조건. (팀 시너지 10점 항목에도 연결)
