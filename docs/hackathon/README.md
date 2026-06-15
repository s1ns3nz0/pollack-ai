# LIG D&A Hackathon — 자료 모음 (Notion 미러)

> Notion 페이지 전체를 markdown으로 미러링한 모음입니다. 회사 PC에서 Notion 접근이 막혀 있어 이 폴더로 옮겼어요.

## 하위 문서

- [환경 설정 및 규칙](setup-rules.md)
- [대회 개요](overview.md)
- [(Todo) 예선전 정보](todo-preliminary-info.md)
- [DAH 2026 Kick-off 미팅 아젠다](kickoff-agenda.md)
- [1차 미팅 회의록](meeting-1-notes.md)
- [A. AI 보안 표준 · 프레임워크 · 컴플라이언스](A-standards.md)
- [B. UAV · 드론 · 국방 도메인](B-uav-domain.md)
- [C. AI 에이전트 설계 · 멀티에이전트](C-ai-agent.md)
- [D. AI Red Team](D-red-team.md)
- [E. AI Blue Team ](E-blue-team.md)
- [F. 공급망 보안 · AppSec · SBOM](F-supply-chain.md)
- [양진수 셀프 브레인 스토밍 내용](brainstorm-yangjinsu.md)
- [김수지 — 할 일](todo-kimsuji.md)
- [황준식 과업 (진행 상황)](hwang-junsik-status.md)

## 페이지 본문

### 온보딩 (필독)

### Azure 

[https://portal.azure.com/850b9f0b-8517-4266-adf5-e8aa2d9aa48c](https://portal.azure.com/850b9f0b-8517-4266-adf5-e8aa2d9aa48c)
- 초대 메일 못 받았으면, 위에 링크 눌러서 해당 메일로 로그인

# 1. 대회 관련 정보

### 연락처

- 양진수 : [s1ns3nz0@gmail.com](mailto:s1ns3nz0@gmail.com)
- 황준식 : [junsik6771@gmail.com](mailto:junsik6771@gmail.com)
- 김수지 : [mara89mashang@gmail.com](mailto:mara89mashang@gmail.com) 
- 김동언 : [7un4@sch.ac.kr](mailto:7un4@sch.ac.kr)

# 2. 정기 미팅

# 3. 자료 공유

# 4. 개인별 페이지

## 🗂️ Kanban Board (칸반)

### S1~S6 공격 시나리오 기반 Sigma 분석룰 작성
- 상태: To Do · 우선순위: High · 담당: 김수지 · 마감: 2026-06-17

황준식 과업 페이지의 UAV 공격 시나리오(S1~S6) 기반으로, 시나리오별 Sigma 분석룰(yaml) 작성. 시나리오별 상세는 아래 섹션 참고, 실제 yaml 파일 작성은 시나리오별로 체크.

---

## S1 GNSS 스푸핑

- **자산(Tier)**: GNSS (T1)
- **공격 흐름**: 정찰 → EW 위치선점 → 위조 GNSS 신호 주입 → 위치 drift → 항로 이탈
- **MITRE 매핑**: ICS T0830·T0856·T0831·T0815 / EMB3D 센서변조(verify)
- **탐지 신호 → Sigma 룰**: GNSS-INS 잔차 급증 + C/N0 비정상 상승 → `uav_gps_spoof_residual.yml`
- **심각도**: h
- **방어 플레이북 / 레드팀**: PB-NAV-RTB-01 (INS 페일오버·RTB) / 레드팀 SEV-DOWNGRADE-01
- [ ] uav_gps_spoof_residual.yml 작성

## S2 C2 재밍·하이재킹

- **자산(Tier)**: C2_LINK (T1)
- **공격 흐름**: 정찰 → C2 재밍 → 세션 하이재킹 → 위조 명령 주입 → 통제권 탈취
- **MITRE 매핑**: ICS T0814·T0855·T0831·T0813 / EMB3D 약한인증(verify)
- **탐지 신호 → Sigma 룰**: 지상국 미발신 명령 수신 / 명령 시퀀스 불연속 → `uav_c2_unauthorized_cmd.yml`
- **심각도**: h
- **방어 플레이북 / 레드팀**: PB-C2-FAILSAFE-02 (명령인증·대체링크·페일세이프) / 레드팀 SEV-DOWNGRADE-01
- [ ] uav_c2_unauthorized_cmd.yml 작성

## S3 SATCOM MITM

- **자산(Tier)**: SATCOM (T2)
- **공격 흐름**: 정찰 → SATCOM 가로채기 → MITM 위치선점 → 데이터 변조·유출
- **MITRE 매핑**: ICS T0830·T0856·T0832
- **탐지 신호 → Sigma 룰**: MAC 검증 실패율 ↑ / 페이로드 체크섬 불일치 → `uav_satcom_integrity_fail.yml`
- **심각도**: m (방첩 태세 상향 시 h)
- **방어 플레이북 / 레드팀**: PB-LINK-INTEG-03 (무결성 격리·키 롤오버·대체링크) / 레드팀 FP-FORCE-02
- [ ] uav_satcom_integrity_fail.yml 작성

## S4 펌웨어·공급망 변조

- **자산(Tier)**: AUTOPILOT (T1)
- **공격 흐름**: 공급망 임플란트 → 펌웨어 변조 → 배포 → 트리거 → 제어로직 변조
- **MITRE 매핑**: ICS T0862·T0857·T0843·T0889 / EMB3D 펌웨어변조·시큐어부트부재(verify)
- **탐지 신호 → Sigma 룰**: 서명·해시 불일치 / SBOM 미등록 컴포넌트 → `uav_fw_signature_mismatch.yml`
- **심각도**: h
- **방어 플레이북 / 레드팀**: PB-FW-INTEG-04 (비행금지 게이트·재이미징·SBOM 재검증) / 레드팀 SEV-DOWNGRADE-01
- [ ] uav_fw_signature_mismatch.yml 작성

## S5 RAG 포이즈닝

- **자산(Tier)**: AI_SOC (T0) — ⚠️ 제안 시나리오 (메타위협)
- **공격 흐름**: KB 접근 → 오염 문서 주입 → 검색 트리거 → 심각도 오판 → 대응 무력화
- **MITRE 매핑**: ATLAS AML.T0051.001 · T0020 · RAGPoison · T0054
- **탐지 신호 → Sigma 룰**: 정책 기대등급 vs 에이전트 판정 괴리 / 미서명 컨텍스트 검색 → `aisoc_severity_anomaly.yml`
- **심각도**: h (메타위협·항상 유지)
- **방어 플레이북 / 레드팀**: PB-AISOC-GUARD-05 (출처검증·정책 하한·HITL) / 레드팀 핵심 표적
- [ ] aisoc_severity_anomaly.yml 작성

## S6 GCS 침해·횡적확산

- **자산(Tier)**: GCS (T1)
- **공격 흐름**: 초기침투 → 유효계정 탈취 → GCS 장악 → 다수기체 재지정 → 횡적확산
- **MITRE 매핑**: ICS T0822·T0859·T0855·T0866·T0867
- **탐지 신호 → Sigma 룰**: 비정상 로그인 / 단시간 다수기체 재지정 / 내부망 횡적연결 → `gcs_mass_retasking.yml`
- **심각도**: h
- **방어 플레이북 / 레드팀**: PB-GCS-CONTAIN-06 (세션격리·2차승인·자격증명 회전) / 레드팀 PLAYBOOK-MISFIRE-03
- [ ] gcs_mass_retasking.yml 작성

### 📄 S1 GNSS 스푸핑 → uav_gps_spoof_residual.yml 분석룰 구성

---

### 공격 시나리오 상세 (황준식 과업 페이지 참고)

- **자산(Tier)**: GNSS (T1)
- **공격 흐름(kill chain)**: 정찰 → EW 위치선점 → 위조 GNSS 신호 주입 → 위치 drift → 항로 이탈
- **MITRE 매핑**: ICS T0830·T0856·T0831·T0815 / EMB3D 센서변조(verify)
- **탐지 신호 → Sigma 룰**: GNSS-INS 잔차 급증 + C/N0 비정상 상승 → `uav_gps_spoof_residual.yml`
- **심각도**: h (임무 실패·기체 통제권 상실급)
- **방어 플레이북 / 레드팀**: PB-NAV-RTB-01 (INS 페일오버·RTB) / 레드팀 SEV-DOWNGRADE-01

### 📄 S2 C2 재밍·하이재킹 → uav_c2_unauthorized_cmd.yml 분석룰 구성

---

### 공격 시나리오 상세 (황준식 과업 페이지 참고)

- **자산(Tier)**: C2_LINK (T1)
- **공격 흐름(kill chain)**: 정찰 → C2 재밍 → 세션 하이재킹 → 위조 명령 주입 → 통제권 탈취
- **MITRE 매핑**: ICS T0814·T0855·T0831·T0813 / EMB3D 약한인증(verify)
- **탐지 신호 → Sigma 룰**: 지상국 미발신 명령 수신 / 명령 시퀀스 불연속 → `uav_c2_unauthorized_cmd.yml`
- **심각도**: h (임무 실패·기체 통제권 상실급)
- **방어 플레이북 / 레드팀**: PB-C2-FAILSAFE-02 (명령인증·대체링크·페일세이프) / 레드팀 SEV-DOWNGRADE-01

### 📄 S3 SATCOM MITM → uav_satcom_integrity_fail.yml 분석룰 구성

---

### 공격 시나리오 상세 (황준식 과업 페이지 참고)

- **자산(Tier)**: SATCOM (T2)
- **공격 흐름(kill chain)**: 정찰 → SATCOM 가로채기 → MITM 위치선점 → 데이터 변조·유출
- **MITRE 매핑**: ICS T0830·T0856·T0832
- **탐지 신호 → Sigma 룰**: MAC 검증 실패율 ↑ / 페이로드 체크섬 불일치 → `uav_satcom_integrity_fail.yml`
- **심각도**: m (방첩 태세 상향 시 h로 동적 조정)
- **방어 플레이북 / 레드팀**: PB-LINK-INTEG-03 (무결성 격리·키 롤오버·대체링크) / 레드팀 FP-FORCE-02

### 📄 S4 펌웨어·공급망 변조 → uav_fw_signature_mismatch.yml 분석룰 구성

---

### 공격 시나리오 상세 (황준식 과업 페이지 참고)

- **자산(Tier)**: AUTOPILOT (T1)
- **공격 흐름(kill chain)**: 공급망 임플란트 → 펌웨어 변조 → 배포 → 트리거 → 제어로직 변조
- **MITRE 매핑**: ICS T0862·T0857·T0843·T0889 / EMB3D 펌웨어변조·시큐어부트부재(verify)
- **탐지 신호 → Sigma 룰**: 서명·해시 불일치 / SBOM 미등록 컴포넌트 → `uav_fw_signature_mismatch.yml`
- **심각도**: h (임무 실패·기체 통제권 상실급)
- **방어 플레이북 / 레드팀**: PB-FW-INTEG-04 (비행금지 게이트·재이미징·SBOM 재검증) / 레드팀 SEV-DOWNGRADE-01

### 📄 S5 RAG 포이즈닝 → aisoc_severity_anomaly.yml 분석룰 구성

---

### 공격 시나리오 상세 (황준식 과업 페이지 참고)

- **자산(Tier)**: AI_SOC (T0) — ⚠️ 제안 시나리오 (메타위협)
- **공격 흐름(kill chain)**: KB 접근 → 오염 문서 주입 → 검색 트리거 → 심각도 오판 → 대응 무력화
- **MITRE 매핑**: ATLAS AML.T0051.001 · T0020 · RAGPoison · T0054
- **탐지 신호 → Sigma 룰**: 정책 기대등급 vs 에이전트 판정 괴리 / 미서명 컨텍스트 검색 → `aisoc_severity_anomaly.yml`
- **심각도**: h (메타위협·항상 유지 — 정책 하한으로 임의 하향 방지)
- **방어 플레이북 / 레드팀**: PB-AISOC-GUARD-05 (출처검증·정책 하한·HITL) / 레드팀 핵심 표적

### 📄 S6 GCS 침해·횡적확산 → gcs_mass_retasking.yml 분석룰 구성

---

### 공격 시나리오 상세 (황준식 과업 페이지 참고)

- **자산(Tier)**: GCS (T1)
- **공격 흐름(kill chain)**: 초기침투 → 유효계정 탈취 → GCS 장악 → 다수기체 재지정 → 횡적확산
- **MITRE 매핑**: ICS T0822·T0859·T0855·T0866·T0867
- **탐지 신호 → Sigma 룰**: 비정상 로그인 / 단시간 다수기체 재지정 / 내부망 횡적연결 → `gcs_mass_retasking.yml`
- **심각도**: h (임무 실패·기체 통제권 상실급)
- **방어 플레이북 / 레드팀**: PB-GCS-CONTAIN-06 (세션격리·2차승인·자격증명 회전) / 레드팀 PLAYBOOK-MISFIRE-03

### 에이전트별 KPI 정리
- 상태: Backlog · 우선순위: High · 담당: 김수지 · 마감: 2026-06-17

### Sentinel 설정 ↔ IaC 코드화 가능 여부 확인
- 상태: Done · 우선순위: Medium · 담당: 김수지 · 마감: 2026-06-14

# Sentinel 설정 → IaC 코드화 워크플로우

## 핵심 결론

Azure Portal에서 Sentinel을 UI로 세팅한 후, CLI 도구(`aztfexport`)로 Terraform 코드로 추출 가능하다. 예선에서 세팅한 환경을 본선에서 그대로 재현할 수 있다.

---

## 역할 분리

| 담당 | 할 일 |
|---|---|
| 김수지 | Azure Portal에서 Sentinel UI 세팅, 탐지 룰 작성, Data Connector 연결 |
| 양진수 | `aztfexport`로 .tf 파일 추출, GitHub 커밋, 본선 때 `terraform apply` |

김수지는 세팅 완료 후 양진수에게 **리소스 그룹 이름**과 **구독 ID**만 공유하면 됨.

---

## Sentinel IaC 구성 요소

Sentinel은 단독 리소스가 아니라 스택으로 묶여 있어 전부 함께 선언해야 함.

```javascript
Log Analytics Workspace        ← 모든 것의 기반
└── Microsoft Sentinel          ← Workspace 위에 올라가는 솔루션
    ├── Data Connector          ← 로그 수집 소스
    ├── Analytic Rule           ← 탐지 룰
    ├── Automation Rule         ← 알림 → 에이전트 트리거
    └── Playbook (Logic App)    ← 실제 대응 액션
```

> ⚠️ 의존성 순서 중요: Workspace → Sentinel → Data Connector → Analytic Rule → Automation Rule

---

## aztfexport 사용법

`aztfexport`는 **CLI 도구**임. Azure Portal UI 기능이 아님.

```bash
# 설치
brew install aztfexport       # Mac
winget install aztfexport     # Windows

# Azure 로그인 (Portal과 동일 계정)
az login

# 리소스 그룹 전체를 Terraform 코드로 추출
aztfexport resource-group dah-rg
```

실행하면 현재 폴더에 `main.tf`, `variables.tf` 등이 자동 생성됨.

---

## Terraform 리소스 선언 순서

```hcl
# 1. Log Analytics Workspace (기반)
resource "azurerm_log_analytics_workspace" "main" {
  name              = "dah-law"
  sku               = "PerGB2018"
  retention_in_days = 30
}

# 2. Sentinel 활성화
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "main" {
  workspace_id = azurerm_log_analytics_workspace.main.id
}

# 3. Data Connector
resource "azurerm_sentinel_data_connector_microsoft_defender_advanced_threat_protection" "main" {
  workspace_id = azurerm_log_analytics_workspace.main.id
}

# 4. Analytic Rule (탐지 룰)
resource "azurerm_sentinel_alert_rule_scheduled" "uav_anomaly" {
  workspace_id = azurerm_log_analytics_workspace.main.id
  query        = "SecurityEvent | where ..."
}
```

---

## 예선 → 본선 환경 이전 흐름

```javascript
예선 Azure 구독에서 UI로 세팅
        ↓
aztfexport로 .tf 파일 추출
        ↓
GitHub에 코드 커밋
        ↓
본선 Azure 구독에서 terraform apply
        ↓
동일 환경 재현 완료
```

---

## DAH 예선 활용 포인트

- 보고서에 IaC 코드 스니펫 포함 → 문서 완성도 + 아키텍처 구체성 점수 향상
- "Detection as Code 자동화 파이프라인" 다이어그램으로 표현 가능
- Terraform 코드는 `azurerm_sentinel_*` prefix로 [Terraform Registry](https://registry.terraform.io/)에 공식 문서화되어 있음

### 팀원 계정 Azure 구독 초대 + MCA 크레딧 소진 시 카드 추가결제 가능 여부 확인
- 상태: Backlog · 우선순위: Medium · 담당: 김수지 · 마감: 2026-06-15

### (제목 없음)
- 상태: In Progress

### (제목 없음)

## 🗂️ 주요 일정 (칸반)

### D4D

### 2차 미팅

위치: 
시간:
