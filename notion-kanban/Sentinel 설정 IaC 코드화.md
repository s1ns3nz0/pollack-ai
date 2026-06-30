# Sentinel 설정 ↔ IaC 코드화 가능 여부 확인

- **Status**: Done
- **담당자**: 김수지
- **우선순위**: Medium
- **마감일**: 2026-06-14
- **URL**: https://app.notion.com/p/37ff5e835bb48164b9ede45daf3f0c34

---

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
```
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
```
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
