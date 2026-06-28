# Sentinel Watch List 스키마 (권위 참조)

출처: `dah-sentinel-content` repo `Watchlists/*.json` (배포 대상, 단일 진실).
워치리스트는 **ARM 템플릿 JSON** 으로 저장되고 CSV 내용은 `properties.rawContent`
문자열(`\r\n` 구분)에 박혀 있다. `properties.itemsSearchKey` 가 SearchKey 다.

RuleUpdateAgent/GitHubRulePublisher 는 이 스키마를 그대로 따른다(추측 금지).
오탐 개선 시 KQL 불변 — `rawContent` 의 행만 추가(A/B)/수정(C)한다.

## 16개 워치리스트

| Watch List | itemsSearchKey | 컬럼(헤더) |
|---|---|---|
| AOI_Boundary_List | MissionId | MissionId,MinLat,MaxLat,MinLon,MaxLon,AltMin_m,AltMax_m,Description |
| Approved_Arm_Operator_List | OperatorId | OperatorId,ArmAuthority,FireAuthority,AssignedUAVId,ValidUntil,Note |
| Approved_CT_Transition_List | OperatorId | OperatorId,CanEscalate,CanDeescalate,MaxLevel,AllowedSource,Description |
| Approved_Firmware_Hash_List | Hash | Hash,UAVId,Version,ApprovedDate,Description |
| Approved_MPS_Planner_List | OperatorId | OperatorId,PlannerAuthority,ApproverAuthority,MaxROE,Description |
| Approved_Mission_Command_List | CommandType | CommandType,AllowedROE,IssuedByRole,Description |
| Approved_Operation_Schedule_List | MissionId | MissionId,MissionType,AllowedStartHour,AllowedEndHour,CTLevel,Description |
| Approved_Operators_List | OperatorId | OperatorId,DisplayName,Role,AllowedHours,Description |
| Approved_Payload_Config_List | PayloadConfig | PayloadConfig,AllowedROE,RequiredRole,Description |
| Approved_SystemId_List | SystemId | SystemId,UAVId,CallSign,AssignedGCS,Description |
| Approved_Weapon_List | WeaponId | WeaponId,Type,AssignedUAV,ArmAuthority,Description |
| C2_Whitelisted_GCS_List | GCS_IP | GCS_IP,GCS_Name,Protocol,AllowedPort,Description |
| GNSS_Exception_List | ZoneId | ZoneId,MinLat,MaxLat,MinLon,MaxLon,Reason,ExpiryDate |
| Operator_UAV_Binding_List | OperatorId | OperatorId,AllowedUAVId,Role,ValidFrom,ValidUntil |
| Trusted_TI_Source_List | SourceId | SourceId,SourceType,ConfidenceThreshold,Description |
| UAV_Threshold_List | ThresholdKey | ThresholdKey,Value,Unit,Description,B_항목,MITRE |

## 분석룰 → 워치리스트 (repo `AnalyticsRules/S*.json`)

| 룰 | 참조 워치리스트 | 유형 | remediation search_key |
|---|---|---|---|
| S1_GNSS_Spoofing | GNSS_Exception_List | B (지리 구역 예외) | ZoneId |
| S2_C2_Hijacking | C2_Whitelisted_GCS_List | A (GCS 화이트리스트) | GCS_IP |
| S6_Operator_BruteForce | Approved_Operators_List | A (운용자 화이트리스트) | OperatorId |
| S4_Firmware_Tampering | (없음) | — | — |
| S5_Parameter_Tampering | (없음) | — | — |

> `UAV_Threshold_List`(Type C)는 여러 룰이 임계값으로 참조. 행 예:
> `MaxJamIndicator,0.5,,RF 간섭 지표 임계 — 초과 시 재밍 의심,B-4,T0814`
> Type C 개선 = 해당 `ThresholdKey` 행의 `Value` 만 수정.

## ⚠ pollack-ai 의 구버전 주의
`pollack-ai/sentinel/Analytic Rules/S1_GNSS_Spoofing.json` 은 **구버전**이라 GNSS
워치리스트를 `UAVId_s` 로 읽는다. 배포되는 진짜는 repo 쪽(`ZoneId`)이다. 스키마는
항상 `dah-sentinel-content` repo 를 따른다.

## 에이전트의 한계(설계상)
에이전트는 SearchKey 컬럼 값 + remediation `columns` 힌트로 채울 수 있는 컬럼만
기록한다. 나머지(위경도 박스, 권한, 만료일 등)는 운용자가 PR 리뷰에서 보강한다
(회귀 게이트 + 1인 승인). 탐지를 느슨하게 하는 방향이라 사람 승인은 의도된 가드.
