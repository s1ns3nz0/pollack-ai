# Watch List 설정

- **Status**: To Do
- **담당자**: 김수지
- **URL**: https://app.notion.com/p/38df5e835bb4802e8047d49348b7c2c8

---

## B. Watch List (Sentinel 탐지 대상)
각 항목 = KQL 쿼리로 Sentinel Analytics Rule 또는 Hunting query 작성. `pollack-ai`의 Sigma → Sentinel 자동 배포 트랙과 매핑.

### B-1. 위치/항로 anomaly
- **AOI 이탈**: lat/lon 이 mission 의 정의된 box 밖
  ```kql
  UAVTelemetry_CL | where TimeGenerated > ago(5m)
  | where MsgType == 'GLOBAL_POSITION_INT'
  | where Lat !between (36.70 .. 36.73) or Lon !between (126.12 .. 126.15)
  | summarize Excursions=count() by UAVId, bin(TimeGenerated, 1m)
  ```
- **GPS jump**: 연속 GPS sample 위치 변화 > 1km/sec
- **EKF variance 폭증**: PosHorizVariance > 5 (S1 GNSS 스푸핑)

### B-2. 속도/고도 anomaly
- **순항 속도 위반**: Airspeed > 70 m/s 또는 < 9 m/s 인 cruise 중
- **저고도 cruise**: AltMSL_m < 100m 이면서 mode=AUTO 인 시간 > 30s
- **수직속도 폭증**: ClimbRate > ±20 m/s

### B-3. mission 조작
- **MISSION_CURRENT 잦은 변경**: 1분에 5번 이상 mission_reset
- **PARAM_SET burst**: 1분에 10건 이상 → 무단 PARAM 변경
- **SYSID_THISMAV 변경**: vehicle 식별자 자체 변조 시도

### B-4. mavlink 무결성
- **UnsignedCount 증가** (UAVMavsec): mavlink 서명 없는 메시지 다수
- **FailedCount > 0**: 서명 검증 실패
- **JamIndicator > 0.5** (UAVSatcomLink): RF 간섭/재밍

### B-5. SATCOM 무결성 (S3)
- **IntegrityStatus != 'ok'**: SATCOM seq 불일치 → MITM 의심
  ```kql
  UAVSatcomLink_CL | where TimeGenerated > ago(1h)
  | where IntegrityStatus != 'ok'
  | summarize count() by UAVId, IntegrityStatus, bin(TimeGenerated, 5m)
  ```
- **RttMs 폭증**: 평상 600ms → 5000ms 이상

### B-6. PGSE / 펌웨어 (S4)
- **ImageHashSubmitted != ImageHashExpected**: 펌웨어 서명 불일치
- **SbomForbiddenCount > 0**: SBOM 금지 패키지 포함
- **TokenExpiresAt - now < 5min**: 만료 직전 token

### B-7. C4I / 작전
- **야간 OrderId**: 23:00-05:00 사이 c4i 명령
- **OrderId 빈도 폭증**: 1분에 20건 이상
- **EventType='friendly_position_diverged'**: 아군 위치 보고 mismatch

### B-8. TI (Threat Intel)
- **Indicator match**: ti-stub feed 의 IOC 가 시뮬 IP/도메인 hit
- **ConfidencePct > 80**: 고신뢰 IOC

### B-9. 인증 / 감사
- **Failed login burst**: FailReason != null, 1분 5건 이상
- **Off-hours session**: SessionId 발급이 야간
- **Operator anomaly**: ActionName 패턴 outlier

### B-10. 무장 / 안전
- **SafetyState 'Armed' without auth Operator**: weapon-stub safety arm 시 sessionId 없음
- **WeaponId mismatch**: 등록 안 된 weapon

### B-11. 영상 (Imagery)
- **CAMERA_TRIGGER burst**: 1분에 50 frame 이상
- **CAMERA outside ROI**: 미션 AOI 밖에서 trigger

### B-12. 모드 / Failsafe
- **RTL/QRTL 진입 burst**: 짧은 시간에 3대 동시
- **STATUSTEXT severity <= 2**: Critical text 출력

### B-13. 비행 패턴 (편대)
- **편대 distance 폭증**: 3 UAVId 거리 > 5km
- **편대 alt 발산**: 표준편차 > 50m

---

## C. 우선순위 (구현 순서)

| Priority | Watch list | 이유 |
|---|---|---|
| 1 (High) | B-1 GPS spoof, B-4 mavlink integrity, B-6 PGSE, B-3 mission 조작 | S1/S4/A4 시나리오 직결 |
| 2 (Med) | B-5 SATCOM, B-12 mode/failsafe, B-9 auth | S3 + insider threat |
| 3 (Low) | B-13 편대, B-11 imagery, B-7 C4I | F1 편대 데모 추가 가치 |

---

## D. 자동화 트리거
- mission 별 plan 파일은 `/home/qgc/missions/` 에 박혀있음 (현재 v1/v2/v3.plan = A-5)
- A-1 ~ A-4 plan 도 신규 박기 + QGC import 절차
- 9 stub HTTP traffic 시퀀스 = cron/CronJob 또는 mission-planner UI 안에서 트리거
- 팀원 = 카드 별 mission 클릭 → 자동 plan upload + stub 호출

---

## 참고
- 현 인프라: AKS `dah-sim-aks` + 편대 3대 + 안흥 HOME + Sentinel 17-stream 일원화
- Sentinel workspace: `dah-data-law` (RG `dah-data-rg`)
- 자세한 환경: repo `uav-sim-env/README.md` + `HANDOFF.md`

---

## Watch List 설계 초안 (수지 추가 — 2026-06-28)

### 원칙
- KQL 룰은 건드리지 않는다
- 오탐 발생 시 **Watch List 값만** 추가/수정한다
- Rule Update Agent는 Watch List만 쓴다
- 임계값도 Watch List로 관리 → KQL이 Watch List에서 읽어서 비교

### 유형

| 유형 | 설명 | 오탐 개선 방법 |
|---|---|---|
| Type A: 화이트리스트형 | 목록에 없으면 이상 | 신규 정상 항목을 목록에 추가 |
| Type B: 예외 허용형 | 목록에 있으면 FP 제거 | 정상 구역/기체를 예외 목록에 추가 |
| Type C: 임계값형 | KQL이 이 값을 읽어서 비교 | 임계값 수치를 조정 |

### 진수님 원문 → Watch List 매핑

| 진수님 원문 | 하드코딩 값/로직 | Watch List | 유형 |
|---|---|---|---|
| B-1 AOI 이탈 | lat/lon 범위 하드코딩 | AOI_Boundary_List | Type B |
| B-1 EKF variance | `> 5` | UAV_Threshold_List: MaxPosHorizVariance | Type C |
| B-1 GPS jump | `> 1km/sec` | UAV_Threshold_List: MaxGpsJumpKmPerSec | Type C |
| B-2 순항 속도 | `> 70`, `< 9` | UAV_Threshold_List: MaxAirspeed_ms, MinAirspeed_ms | Type C |
| B-2 저고도 | `< 100m` | UAV_Threshold_List: MinCruiseAlt_m | Type C |
| B-2 수직속도 | `> ±20` | UAV_Threshold_List: MaxClimbRate_ms | Type C |
| B-3 mission_reset | `> 5/min` | UAV_Threshold_List: MaxMissionResetPerMin | Type C |
| B-3 PARAM_SET | `> 10/min` | UAV_Threshold_List: MaxParamSetPerMin | Type C |
| B-4 JamIndicator | `> 0.5` | UAV_Threshold_List: MaxJamIndicator | Type C |
| B-5 RttMs | `> 5000ms` | UAV_Threshold_List: MaxRttMs_SATCOM | Type C |
| B-6 펌웨어 해시 | 해시 불일치 비교 | Approved_Firmware_Hash_List | Type A |
| B-7 야간 시간 | `23:00~05:00` | UAV_Threshold_List: OffHoursStart, OffHoursEnd | Type C |
| B-7 OrderId 폭증 | `> 20/min` | UAV_Threshold_List: MaxC4IOrderPerMin | Type C |
| B-9 로그인 실패 | `> 5/min` | UAV_Threshold_List: MaxLoginFailurePerMin | Type C |
| B-9 비인가 운영자 | 목록 비교 | Approved_Operators_List | Type A |
| B-9 비인가 IP | 목록 비교 | C2_Whitelisted_GCS_List | Type A |
| B-10 WeaponId | 목록 비교 | Approved_Weapon_List | Type A |
| B-11 카메라 burst | `> 50/min` | UAV_Threshold_List: MaxCameraFramePerMin | Type C |
| B-11 CAMERA ROI | AOI 범위 비교 | AOI_Boundary_List | Type B |
| B-13 편대 거리 | `> 5km` | UAV_Threshold_List: MaxFormationDistance_km | Type C |
| B-13 편대 고도 | `> 50m 표준편차` | UAV_Threshold_List: MaxFormationAltStdDev_m | Type C |

### Watch List 현황

| Watch List | 유형 | 상태 | 비고 |
|---|---|---|---|
| Approved_Operators_List | Type A | ✅ 배포됨 | B-9 |
| Approved_SystemId_List | Type A | ✅ 배포됨 | B-3/B-4 |
| C2_Whitelisted_GCS_List | Type A | ✅ 배포됨 | B-9 |
| GNSS_Exception_List | Type B | ✅ 배포됨 | B-1 |
| AOI_Boundary_List | Type B | ✅ CSV 생성 완료 | B-1, B-11 — 안흥 좌표 기반 |
| Approved_Firmware_Hash_List | Type A | ✅ CSV 생성 완료 | B-6 — pgse-stub/data/approved_firmware.json |
| Approved_Weapon_List | Type A | ✅ CSV 생성 완료 | B-10 — weapon-stub/app.py |
| UAV_Threshold_List | Type C | ✅ CSV 생성 완료 | B-1~B-13, 17개 임계값 통합 |

---

### MITRE ATT&CK 기반 추가 Watch List (진수님 원문 외)

| # | Watch List | 유형 | MITRE Tactic | MITRE Technique | 목적 |
|---|---|---|---|---|---|
| 9 | Trusted_Scanner_List | Type B | Reconnaissance | T1595 Active Scanning | 승인된 포트스캐너 IP — FP 제거 |
| 10 | Approved_Mission_Command_List | Type A | Execution | T0821 Modify Controller Tasking | 승인된 미션 명령 타입만 허용 |
| 11 | Approved_Cron_List | Type A | Persistence | T1546 Event Triggered Execution | 승인된 자동화 트리거 목록 |
| 12 | Operator_UAV_Binding_List | Type A | Lateral Movement | T1078 Valid Accounts | 운영자별 제어 가능 기체 바인딩 |
| 13 | Approved_Camera_Schedule_List | Type B | Collection | T1125 Video Capture | 허용된 촬영 시간대/구역 |
| 14 | Approved_Arm_Operator_List | Type A | Impact | T0831 Manipulation of Control | 무장 권한 운영자 별도 관리 |

#### Operator_UAV_Binding_List 상세
- **목적**: 탈취된 계정으로 담당 외 기체를 제어하는 걸 탐지 — S6 GCS 침해 시나리오에서 중요
- **MITRE**: T1078 → Lateral Movement
- **컬럼**: `Operator`, `AllowedUAVId`, `Role`, `ValidFrom`, `ValidUntil`
- **예시**:
  ```csv
  Operator,AllowedUAVId,Role,ValidFrom,ValidUntil
  lt.kim,MUAV-AKS-SYS001,pilot,2026-01-01,2026-12-31
  capt.park,MUAV-AKS-SYS002,pilot,2026-01-01,2026-12-31
  ```

#### Approved_Arm_Operator_List 상세
- **목적**: 무장 권한은 일반 로그인 권한과 별도 관리
- **MITRE**: T0831 → Impact
- **컬럼**: `Operator`, `ArmAuthority`, `AssignedUAVId`, `ValidUntil`

---

### AI/Agent 도메인 추가 Watch List (황준식님 협의 필요)

| # | Watch List | 유형 | MITRE Tactic | MITRE Technique | 목적 |
|---|---|---|---|---|---|
| 15 | Approved_RAG_Source_List | Type A | ML Supply Chain | ATLAS AML.T0054 / T1195 | 승인된 RAG 데이터 소스만 허용 (S5) |
| 16 | Approved_Agent_Action_List | Type A | Execution | ATLAS AML.T0051 | 에이전트 허용 액션 목록 |
| 17 | Approved_Operation_Schedule_List | Type B | Defense Evasion | T1078 | 임무별 허용 운영 시간대 |

#### Approved_RAG_Source_List
- **목적**: S5 RAG 포이즈닝 — 승인된 소스 외 데이터 주입 탐지
- **MITRE**: ATLAS AML.T0054 LLM Prompt Injection / T1195 Supply Chain
- **컬럼**: `SourceId`, `SourceType`, `SourceUrl`, `ApprovedBy`, `ApprovedDate`

#### Approved_Agent_Action_List
- **목적**: AI SOC 에이전트가 수행 가능한 액션 제한
- **MITRE**: ATLAS AML.T0051 LLM Plugin Compromise
- **컬럼**: `AgentId`, `AllowedAction`, `Scope`, `ApprovedBy`

---

### 최종 합계: 17개

| 구분 | 개수 | Watch List |
|---|---|---|
| ✅ 배포 완료 | 4개 | 1~4 |
| ✅ CSV 생성 완료 | 4개 | 5 (AOI_Boundary), 6 (Firmware Hash), 7 (Weapon List), 8 (Threshold) |
| ❌ 팀 협의 후 생성 | 9개 | 9~17 (우선순위 High: 12, 14, 15) |

**다음 단계**: 5~8번 CSV 파일을 `s1ns3nz0/dah-sentinel-content` 리포 `watchlists/` 폴더에 PR → GitHub Actions로 자동 Sentinel 배포
