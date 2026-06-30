# 🛠️ UAV ATT&CK 매핑표 (Enterprise + ICS)

- **Status**: In Progress
- **담당자**: 김수지, 김동언
- **URL**: https://app.notion.com/p/38bf5e835bb4810d8dc9fd6f55bfcccc

---

(첨부 파일: uav_attck_matrix_full_v3.html / uav_attck_matrix_korean_v2.html / uav_attck_matrix_english_v2.html)

## 작업 현황
- ✅ 데이터 확인된 테이블
- 🔜 테이블 존재함 — 미션 돌리거나 파드 Running 시 데이터 들어올 수 있음
- ❌ 테이블 자체 없음 (또는 예방통제로만 대응 가능)

**2026-06-28 기준 테이블 확인 결과:**

| 테이블 | 상태 | 비고 |
|---|---|---|
| `UAVTelemetry_CL` | ✅ | SYS001/002/003 정상 데이터 |
| `UAVOpAudit_CL` | ✅ | 정상 |
| `UAVPgse_CL` | ✅ | 공격 데이터 포함 |
| `UAVFailsafe_CL` | ✅ | 정상 |
| `UAVMaintenance_CL` | ✅ | 정상 |
| `UAVCyberPosture_CL` | ✅ | 정상 |
| `UAVC4I_CL` | ✅ | 정상 |
| `UAVThreatIntel_CL` | ✅ | 정상 |
| `UAVWeapon_CL` | ✅ | dummy 50건 |
| `UAVSarPayload_CL` | ✅ | 정상 |
| `UAVMissionPlan_CL` | ✅ | 정상 |
| `UAVSatcomLink_CL` | ✅ | 레거시 MUAV-AKS-001만 (A-4 미션 필요) |
| `UAVServiceAudit_CL` | ✅ | 정상 |
| `UAVOperator_CL` | ✅ | SYS001/002/003 정상 |
| `UAVConfigAudit_CL` | ✅ | SYS001/002/003 데이터 확인 (6/27) |
| `UAVDatalinkConn_CL` | ✅ | 데이터 확인 완료 (IP/Port 기반 연결 로그) |
| `UAVDatalink_CL` | ✅ | 데이터 확인 완료 (컨테이너 네트워크 통계) |
| `UAVMavsec_CL` | ✅ | 데이터 확인 완료 |
| `UAVMissionEvent_CL` | ✅ | 데이터 확인 완료 |
| `UAVResourceMetrics_CL` | ✅ | 데이터 확인 완료 (컨테이너 단위 메트릭) |
| `UAVGcsAccess_CL` | 🔜 | 테이블 존재 확인 (getschema 확인됨) |
| `UAVRouterStats_CL` | 🔜 | 테이블 존재 확인 (getschema 확인됨) |
| `UAVImagery_CL` | 🔜 | 테이블 존재 확인 (getschema 확인됨) |

[E] = Enterprise ATT&CK / [I] = ICS ATT&CK / [E][I] = 둘 다 해당

담당 범위: **수지님 (Recon ~ Discovery) / 동언님 (Lateral Movement ~ Impact)**

---

## 테이블별 Tactic 경로

| 테이블 | 설명 | 주요 Tactic |
|---|---|---|
| `UAVPgse_CL` | 지상지원장비 — 발사 전 점검, 펌웨어 검증 기록 | Initial Access, Persistence, Stealth |
| `UAVOpAudit_CL` | 운영자 인증/접근 로그 | Initial Access, Persistence, Priv Escalation |
| `UAVMissionPlan_CL` | 임무 계획 생성/승인 로그 | Execution |
| `UAVTelemetry_CL` | 기체 텔레메트리 (MsgType별 컬럼 다름) | Stealth, Execution, Discovery |
| `UAVFailsafe_CL` | 안전장치 발동/비활성화 로그 | Stealth/Evasion |
| `UAVMaintenance_CL` | 정비 이벤트 로그 | Initial Access |
| `UAVCyberPosture_CL` | 시스템 보안 등급 상태 로그 | Stealth/Evasion |
| `UAVC4I_CL` | 부대 간 작전 명령/핸드오프 로그 | Initial Access, Execution, Priv Escalation |
| `UAVThreatIntel_CL` | 위협 인텔리전스 지표 (조인용) | Reconnaissance, Initial Access |
| `UAVWeapon_CL` | 무장 상태/조작 로그 | Execution, (동언님) Impact |
| `UAVSarPayload_CL` | SAR 센서 촬영 기록 | (동언님) Collection, Exfiltration |

---

## 1. Reconnaissance

| 출처 | Technique | 의미 | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| [E] | Active Scanning | 능동 스캔 | T1595 | 공격자가 5790/8080 포트 스캔으로 열린 서비스 탐색 | `UAVDatalinkConn_CL` | `LocalPort`, `PeerIp` | ✅ |
| [E] | Gather Victim Host Information | 호스트 정보 수집 | T1592 | 공격자가 기체 하드웨어/센서/펌웨어/GCS 소프트웨어 정보 수집 | `UAVThreatIntel_CL` | `IndicatorType`, `Indicator` | ✅ |
| [E] | Gather Victim Network Information | 네트워크 정보 수집 | T1590 | 공격자가 GCS-데이터링크-기체 간 통신 구조 및 네트워크 구성 파악 | - | - | ❌ 예방 통지 (네트워크 격리)로 대응 |
| [E] | Search Open Technical Databases | 공개 기술 DB 검색 | T1596 | 공격자가 ArduPilot/QGC CVE 공개 검색 | - | - | ❌ |

## 2. Resource Development

| 출처 | Technique | 의미 | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| [E] | Develop Capabilities | 공격 경로 개발 | T1587 | 공격자가 GPS 스푸핑 툴/MAVLink 인젝터 직접 개발 | - | - | ❌ (공격자가 자기 컴퓨터에서 만듦)→ 네트워크 격기 |
| [E] | Obtain Capabilities | 공격 경로 획득 | T1588 | 공격자가 공개 GPS 스푸핑 툴 획득 | - | - | ❌ (공격자가 외부에서 함) |
| [E] | Stage Capabilities | 공격 인프라 세팅 | T1608 | 공격자가 C2 서버 등 공격 인프라 준비 | - | - | ❌ (공격자가 외부에서 함) |

## 3. Initial Access

| 출처 | Technique | 의미 | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| [E][I] | Exploit Public-Facing Application | 공개 애플리케이션 취약점 공격 | T1190/T0819 | 공격자가 pgse-stub/auth-stub API 취약점 공격으로 초기 침투 | `UAVPgse_CL` | `StatusCode`, `Passed` | ✅ |
| [E] | External Remote Services | 외부 원격 서비스 악용 | T1133 | 공격자가 noVNC/QGC 원격 접속 악용 | `UAVGcsAccess_CL` | `ClientIp`, `Transport` | 🔜 |
| [E][I] | Supply Chain Compromise | 공급망 침해 | T1195/T0862 | 공격자가 변조된 펌웨어를 정상 납품 경로로 삽입 | `UAVPgse_CL` | `HashMatch`, `SbomForbiddenCount`, `Passed` | ✅ |
| [E] | Valid Accounts | 유효 계정 악용 | T1078 | 공격자가 탈취한 운영자 계정으로 GCS 접속 | `UAVOpAudit_CL`, `UAVThreatIntel_CL` | `EventType`, `ClientIp`, `Indicator` | ✅ |
| [I] | Wireless Compromise | 무선 침해 | T0860 | 공격자가 데이터링크 무선 채널 침투 | `UAVDatalink_CL` | `RxErrors`, `RxDropped` | ✅ |
| [I] | Transient Cyber Asset | 임시 사이버 자산 악용 | T0864 | 공격자가 정비용 노트북/USB로 시스템 침투 | `UAVMaintenance_CL` | `Operator`, `ComponentName`, `EventType` | ✅ |

## 4. Execution

| 출처 | Technique | 의미 | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| [E] | Command and Scripting Interpreter | 명령, 스크립트 인터프리터 악용 | T1059 | 공격자가 GCS 콘솔에서 악성 스크립트 실행 | `UAVServiceAudit_CL` | `Action`, `ContainerName` | ✅ |
| [E][I] | Native API / Execution through API | API 직접 호출로 비인가 명령 실행 | T1106/T0871 | 공격자가 MAVLink API 직접 호출로 비인가 명령 실행 | `UAVOperator_CL` | `SourceSystemId`, `Command` | ✅ |
| [E] | User Execution | 사용자 실행 유도 | T1204 | 공격자가 운영자를 속여 악성 미션파일 실행 유도 | `UAVMissionPlan_CL` | `PlanId`, `Planner`, `Roe`, `Status` | ✅ |
| [I] | Modify Controller Tasking | 컨트롤러 작업 변조 | T0821 | 공격자가 비행 미션 파라미터 무단 변경 | `UAVConfigAudit_CL` | `ParamId`, `ParamValueAfter` | ✅ |
| [I] | Unauthorized Message | 비인가 메시지 주입 | T1692.001 | 공격자가 비인가 MAVLink 메시지 주입 | `UAVOperator_CL`, `UAVDatalinkConn_CL` | `SourceSystemId`, `PeerIp` | ✅ |
| [E] | User Execution (무장) | | T1204 | 공격자가 Roe 위반 무장 활성화 유도 | `UAVWeapon_CL`, `UAVC4I_CL` | `SafetyState`, `SafetyStateBefore`, `Roe` | ✅ |

## 5. Persistence

| 출처 | Technique | 의미 | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| [E] | Modify Authentication Process | 인증 로직 변조 | T1556 | 공격자가 auth-stub 인증 로직 변조로 지속 접근 확보 | `UAVOpAudit_CL` | `EventType`, `FailReason` | ✅ |
| [E][I] | Modify Firmware | 펌웨어 백도어 삽입 | T1542.001/T1693.001 | 공격자가 펌웨어에 백도어 심어 재부팅 후에도 유지 | `UAVPgse_CL` | `HashMatch`, `Passed` | ✅ |
| [E][I] | Valid Accounts | 백도어 계정 생성 | T1078/T0859 | 공격자가 백도어 계정 생성으로 지속 접근 | `UAVOpAudit_CL` | `Operator`, `EventType` | ✅ |
| [E] | Event Triggered Execution | 조건부 악성 명령 | T1546 | 공격자가 특정 조건 발생 시 악성 명령 자동 실행 설정 | `UAVOperator_CL` | `ActionName`, `SourceSystemId` | ✅ |

## 6. Privilege Escalation

| 출처 | Technique | 의미 | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| [E][I] | Exploitation for Privilege Escalation | 취약점 이용 권한 상승 | T1068/T0890 | 공격자가 pgse/auth API 취약점으로 권한 상승 | `UAVPgse_CL`, `UAVOpAudit_CL` | `StatusCode`, `Operator`, `Passed` | ✅ |
| [E] | Valid Accounts | 고권한 계정 탈취 | T1078 | 공격자가 고권한 계정(super-admin) 탈취로 권한 획득 | `UAVOpAudit_CL`, `UAVC4I_CL` | `Operator`, `ClientIp`, `IssuedBy`, `TargetPriority` | ✅ |

## 7. Stealth / Evasion

| 출처 | Technique | 의미 | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| [E][I] | Indicator Removal | 흔적 제거 | T1070/T0872 | 공격자가 침투 흔적 삭제/로그 조작으로 은폐 | `UAVServiceAudit_CL` | `Action`, `ContainerName` | ✅ |
| [E][I] | Masquerading | 위장 | T1036/T0849 | 공격자가 정상 GCS인 척 비인가 명령 전송 | `UAVOperator_CL` | `SourceSystemId` | ✅ |
| [E] | Modify System Image | 시스템 이미지 변조 후 위장 | T1601 | 공격자가 펌웨어/보안등급 변조 후 정상으로 위장 | `UAVPgse_CL`, `UAVCyberPosture_CL` | `HashMatch`, `Level`, `ChangedBy`, `Reason` | ✅ |
| [E] | Rootkit | 루트킷 | T1014 | 공격자가 AV 온보드 시스템에 루트킷 삽입 | - | - | ❌ 예방(부팅 무결성 검증)으로 대응 |
| [I] | Unauthorized Message | 정상 패킷처럼 위장한 명령 주입 | T1692.001 | 공격자가 정상 패킷처럼 위장한 명령 주입 | `UAVMavsec_CL` | `UnsignedCount`, `FailedCount` | ✅ |
| [I] | Alarm Suppression | 경보 억제 | T0878 | 공격자가 무장 체크/경보 비활성화로 안전장치 무력화 | `UAVFailsafe_CL` | `EventType`, `Text`, `Severity` | ✅ |

## 8. Discovery

| 출처 | Technique | 의미 | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| [I] | Network Connection Enumeration | 네트워크 연결 열거 | T0840 | 공격자가 내부 네트워크 연결 스캔으로 자산 파악 | `UAVDatalinkConn_CL` | `PeerIp`, `LocalPort` | 🔜 |
| [I] | Network Sniffing | 네트워크 도청 | T0842 | 공격자가 MAVLink 트래픽 도청으로 통신 내용 수집 | `UAVMavsec_CL` | `UnsignedCount` | ✅ |
| [I] | Wireless Sniffing | 무선 도청 | T0887 | 공격자가 RF/위성 링크 도청으로 통신 감청 | `UAVSatcomLink_CL` | `IntegrityStatus` | ✅ |

---

참고 — 동언님 파트에서 아래 테이블 활용 가능:

| 테이블 | 활용 포인트 |
|---|---|
| `UAVSarPayload_CL` | TargetLat/TargetLon vs UAVC4I AreaLat/AreaLon → 허가 구역 외 촬영 탐지 |
| `UAVWeapon_CL` | Roe=recon-only인데 EventType=fire → 교전규칙 위반 |
| `UAVC4I_CL` | IssuedBy 비인가 발령자, 허가 구역 이탈 |

## 9. Lateral Movement

| 출처 | Technique | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|
| [E][I] | Valid Accounts | T1078 / T0859 | 공격자가 탈취 계정으로 인접 구성요소·편대기로 이동 | `UAVOpAudit_CL` | `Operator`, `ClientIp` | ✅ |
| [I] | Program Download | T0843 | 공격자가 다수 AV에 변조 임무/파라미터 다운로드(편대 전파) | `UAVConfigAudit_CL`, `UAVMissionEvent_CL` | `ParamId`, `EventName` | ✅ |
| [E][I] | Exploitation of Remote Services | T1210 / T0866 | 공격자가 mavlink-router/OpenSAND/stub 취약점으로 측면 이동 | `UAVDatalinkConn_CL` | `PeerIp`, `State` | ✅ |
| [E] | Remote Service Session Hijacking | T1563 | 공격자가 VNC/QGC 또는 SATCOM 세션 하이재킹으로 이동 | `UAVSatcomLink_CL`, `UAVGcsAccess_CL` | `SessionId`, `ClientIp` | 🔜 |
| [E][I] | Lateral Tool Transfer | T1570 / T0867 | 공격자가 공격 도구를 컨테이너/구성요소 간 전송 | `UAVServiceAudit_CL` | `Action`, `ImageName` | ✅ |
| [E][I] | Remote Services | T1021 / T0886 | 공격자가 컨테이너 간 원격 서비스(MAVLink 5760/5790·VNC :5900·noVNC :8080·SSH)로 인접 노드 피벗 | `UAVDatalinkConn_CL`, `UAVOpAudit_CL`, `UAVOperator_CL` | `PeerIp`, `State`, `ClientIp` | ✅ |
| [E] | Use Alternate Authentication Material | T1550 | 공격자가 탈취한 세션 토큰/쿠키·자격을 재사용해 인접 서비스 횡단 | `UAVOpAudit_CL`, `UAVMavsec_CL` | `SessionId`, `ClientIp`, `FailedCount` | ✅ |
| [I] | Insecure Credentials | T1694 | 공격자가 하드코딩/기본 자격(무인증 5790 등)을 발판으로 이동 | `UAVOpAudit_CL` | `Operator`, `ClientIp`, `FailReason` | ✅ |
| [E] | Taint Shared Content | T1080 | 공격자가 공유 임무계획·persona 파라미터를 오염시켜 이를 적재하는 모든 AV 감염 | `UAVMissionPlan_CL`, `UAVConfigAudit_CL` | `PlanId`, `ParamId` | ✅ |

## 10. Collection

| 출처 | Technique | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|
| [E][I] | Adversary-in-the-Middle | T1557 / T0830 | 공격자가 SATCOM 중간자로 영상·표적·텔레메트리 도청 | `UAVSatcomLink_CL` | `IntegrityStatus`, `Seq` | ✅ |
| [E] | Video Capture | T1125 | 공격자가 EO/IR 영상 다운링크를 수동 도청·수집(평문 링크, 행위 미기록) | - | - | ❌ |
| [E][I] | Automated Collection | T1119 / T0802 | 공격자가 다수 UAVId의 영상·SAR 프레임을 자동 도청·수집(수동, 미기록) | - | - | ❌ |
| [I] | Program Upload | T0845 | 공격자가 AV에서 임무/파라미터를 추출(읽기, 변경 아님→미기록) | - | - | ❌ |
| [I] | Monitor Process State | T0801 | 공격자가 텔레메트리·운용모드를 수동 관찰·수집(미기록) | - | - | ❌ |
| [I] | Wireless Sniffing | T0887 | 공격자가 RF/위성 링크를 수동 도청 | - | - | ❌ |
| [E][I] | Screen Capture | T1113 / T0852 | 공격자가 QGC 콘솔 화면(noVNC/VNC)을 캡처(행위 미기록) | - | - | ❌ |
| [E] | Browser Session Hijacking | T1185 | 공격자가 noVNC :8080 웹 콘솔 세션을 탈취(세션 IP 불일치로 일부 탐지) | `UAVOpAudit_CL` | `ClientIp`, `SessionId` | ✅ |
| [E][I] | Data from Local System | T1005 / T0893 | 공격자가 컨테이너 로컬 파일(임무·로그·더미 SAR)을 읽어 수집 | - | - | ❌ |
| [I] | Detect Operating Mode | T0868 | 공격자가 비행모드·Arm·페일세이프 상태를 수동 관찰(미기록) | - | - | ❌ |
| [I] | Point & Tag Identification | T0861 | 공격자가 MAVLink 파라미터·SAR 표적·세션 태그를 수동 열거 | - | - | ❌ |
| [E] | Input Capture | T1056 | 공격자가 GCS 콘솔 키입력·명령 입력을 가로챔 | - | - | ❌ |
| [E] | Data Staged | T1074 | 공격자가 유출 전 영상·SAR·표적을 한 노드에 집적 | - | - | ❌ |
| [E] | Archive Collected Data | T1560 | 공격자가 수집 영상·SAR 프레임을 압축·아카이브 | - | - | ❌ |

## 11. Command and Control

| 출처 | Technique | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|
| [E][I] | Standard Application Layer Protocol | T1071 / T0869 | 공격자가 MAVLink 채널 자체를 C2로 장악 | `UAVOperator_CL`, `UAVRouterStats_CL` | `SourceSystemId`, `CrcErrors` | ✅ |
| [E][I] | Non-Standard Port / Commonly Used Port | T1571 / T0885 | 공격자가 5790 등 포트로 C2 채널 유지 | `UAVDatalinkConn_CL` | `LocalPort`, `PeerIp` | ✅ |
| [E][I] | Proxy / Connection Proxy | T1090 / T0884 | 공격자가 mavlink-router를 경유해 명령을 중계·은닉 | `UAVRouterStats_CL` | `EndpointName`, `MsgTx` | ✅ |
| [E] | Fallback Channels | T1008 | 공격자가 LOS↔BLOS 전환을 악용해 C2 지속 | `UAVDatalink_CL`, `UAVSatcomLink_CL`, `UAVFailsafe_CL` | `RxDropped`, `SessionId`, `ModeAfter` | ✅ |
| [E] | Content Injection | T1659 | 공격자가 링크 콘텐츠를 주입(S3) | `UAVSatcomLink_CL` | `IntegrityStatus`, `Seq` | 🔜 |
| [E] | Ingress Tool Transfer | T1105 | 공격자가 C2 채널로 변조 파라미터·스크립트·임무파일을 AV/GCS에 반입 | `UAVDatalink_CL`, `UAVConfigAudit_CL` | `RxBytes`, `ParamId` | ✅ |
| [E] | Non-Application Layer Protocol | T1095 | 공격자가 MAVLink를 싣는 원시 TCP/UDP 전송계층을 C2 운반체로 활용 | `UAVDatalinkConn_CL`, `UAVDatalink_CL` | `State`, `PeerPort`, `RxBytes` | ✅ |
| [E] | Protocol Tunneling | T1572 | 공격자가 MAVLink/C2를 SATCOM 세션 내부로 터널링해 경계 우회 | - | - | ❌ |
| [E] | Multi-Stage Channels | T1104 | 공격자가 1단계 5790 진입 후 2단계 SATCOM으로 본 C2 운용 | `UAVDatalinkConn_CL`, `UAVSatcomLink_CL` | `LocalPort`, `SessionId` | ✅ |
| [E] | Encrypted Channel | T1573 | 공격자가 암호 채널로 C2를 은닉 | - | - | ❌ |
| [E] | Remote Access Tools | T1219 | 공격자가 VNC/noVNC·MAVProxy/QGC 등 정상 원격제어 도구로 지속 제어 | `UAVOpAudit_CL`, `UAVDatalinkConn_CL` | `ClientIp`, `UserAgent`, `PeerIp` | ✅ |
| [E] | Data Obfuscation | T1001 | 공격자가 C2 명령을 정상 MAVLink 필드·더미 트래픽에 섞어 은닉 | - | - | ❌ |
| [E] | Data Encoding | T1132 | 공격자가 C2 데이터를 인코딩해 MAVLink 메시지에 실어 파서 통과 | - | - | ❌ |

## 12. Exfiltration

| 출처 | Technique | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|
| [E] | Exfiltration Over C2 Channel | T1041 | 공격자가 MAVLink C2 채널로 SAR/EO 영상 유출 | `UAVDatalink_CL`, `UAVSatcomLink_CL` | `TxBytes`, `SessionId` | ✅ |
| [E] | Exfiltration Over Other Network Medium | T1011 | 공격자가 SATCOM/RF 별도 매체로 정찰영상 유출 | - | - | ❌ |
| [E] | Automated Exfiltration | T1020 | 공격자가 SAR 표적 프레임을 자동 유출 | `UAVSarPayload_CL` | `FrameId`, `SizeBytes` | ✅ |
| [E] | Scheduled Transfer | T1029 | 공격자가 탐지 회피 위해 주기 버스트로 전송 | `UAVResourceMetrics_CL` | `NetworkTxBytes` | ✅ |
| [E] | Exfiltration Over Alternative Protocol | T1048 | 공격자가 C2(MAVLink) 외 프로토콜(REST·터널)로 영상·표적 유출 | `UAVDatalink_CL`, `UAVDatalinkConn_CL` | `TxBytes`, `PeerPort` | ✅ |
| [E] | Data Transfer Size Limits | T1030 | 공격자가 영상/SAR를 작은 청크로 분할 송출해 임계 탐지 회피 | `UAVDatalink_CL` | `TxBytes`, `RxDropped` | ✅ |
| [E] | Exfiltration Over Web Service | T1567 | 공격자가 C4I(ATCIS/MIMS)·stub REST를 합법 채널처럼 악용해 산출물 반출 | - | - | ❌ |

## 13. Impair Process Control

| 출처 | Technique | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|
| [I] | Modify Parameter | T0836 | 공격자가 ArduPilot 파라미터/persona 변조로 제어 거동 왜곡 | `UAVConfigAudit_CL` | `ParamId`, `ParamValueAfter` | ✅ |
| [I] | Modify Firmware | T1693 | 공격자가 FCC 펌웨어 변조로 제어 로직 손상 | `UAVPgse_CL` | `HashMatch`, `Passed` | ✅ |
| [I] | Unauthorized Message | T1692 | 공격자가 위조 MAVLink 명령/보고 메시지 주입 | `UAVOperator_CL`, `UAVMavsec_CL` | `SourceSystemId`, `UnsignedCount` | ✅ |
| [I] | Brute Force I/O | T0806 | 공격자가 제어 입력을 반복 주입해 거동 강제 | `UAVOperator_CL` | `Command`, `Confirmation` | ✅ |

## 14. Inhibit Response Function

| 출처 | Technique | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|
| [I] | Modify Alarm Settings | T0838 | 공격자가 Failsafe 임계(`FS_*`)를 변조해 보호 미발동 | `UAVConfigAudit_CL` | `ParamId`, `ParamValueAfter` | ✅ |
| [I] | Denial of Service | T0814 | 공격자가 재밍·DoS로 링크를 거부 | `UAVDatalink_CL`, `UAVSatcomLink_CL` | `RxDropped`, `JamIndicator` | ✅ |
| [I] | Block Communications | T1695 | 공격자가 링크를 차단해 명령/보고 두절 | `UAVDatalink_CL` | `RxDropped`, `TxDropped` | ✅ |
| [I] | Block Reporting Message | T1691.002 | 공격자가 텔레메트리/보고 메시지만 선택 차단해 상황인식 차단 | `UAVTelemetry_CL`, `UAVDatalink_CL` | `MsgType`, `RxDropped` | ✅ |
| [I] | Service Stop | T0881 | 공격자가 telemetry-tap/관측 서비스를 중단 | `UAVServiceAudit_CL` | `Action`, `ContainerName` | ✅ |
| [I] | Alarm Suppression | T0878 | 공격자가 경보 메시지 드롭·RTL/LAND 트리거 무력화로 경보 미도달 | - | - | ❌ |
| [I] | Device Restart/Shutdown | T0816 | 공격자가 AV/FCC·컨테이너 강제 재시작·종료로 제어 루프 중단·강제착륙 유발 | `UAVResourceMetrics_CL`, `UAVFailsafe_CL`, `UAVOperator_CL` | `ContainerName`, `ModeAfter`, `Command` | ✅ |
| [I] | Change Credential | T0892 | 공격자가 운영자 자격/세션을 변경해 정상 운용자 잠금(통제·복구 차단) | `UAVOpAudit_CL` | `EventType`, `Operator`, `FailReason` | ✅ |
| [I] | Manipulate I/O Image | T0835 | 공격자가 FCC 센서 I/O(GNSS/IMU) 표상을 조작해 보호 로직 입력 왜곡 | `UAVTelemetry_CL` | `PosHorizVariance`, `VelocityVariance`, `FixType` | ✅ |
| [I] | Data Destruction | T0809 | 공격자가 관측·로그·임무 데이터를 파괴해 탐지·복구 무력화 | - | - | ❌ |
| [I] | Activate Firmware Update Mode | T0800 | 공격자가 FCC를 펌웨어 업데이트 모드로 강제 진입시켜 제어 중단 | - | - | ❌ |
| [I] | Rootkit | T0851 | 공격자가 FCC/컨테이너에 루트킷을 설치해 변조·중단 은폐 | - | - | ❌ |

## 15. Impact

| 출처 | Technique | ID | 공격자 행위 | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|
| [I] | Manipulation of View | T0832 | 공격자가 위조 텔레메트리·영상·SAR 표적으로 운용자를 기만 | `UAVTelemetry_CL`, `UAVSatcomLink_CL` | `PosHorizVariance`, `IntegrityStatus` | ✅ |
| [I] | Theft of Operational Information | T0882 | 공격자가 EO/IR·SAR 영상·표적좌표를 탈취 | - | - | ❌ |
| [I] | Loss of Control | T0827 | 공격자가 조종 명령을 무력화해 통제 상실 유발(A4/JAM) | `UAVOperator_CL`, `UAVFailsafe_CL` | `Result`, `ModeAfter` | ✅ |
| [I] | Loss of Safety | T0880 | 공격자가 Failsafe 무력화 상태로 위험 비행 지속 | `UAVFailsafe_CL`, `UAVConfigAudit_CL` | `EventType`, `ParamId` | ✅ |
| [I] | Damage to Property | T0879 | 공격자가 추락·강제착륙을 유발해 물리적 손상 | `UAVFailsafe_CL`, `UAVTelemetry_CL` | `ModeAfter`, `AltRel_m` | ✅ |
| [E][I] | Network Denial of Service | T1498 / T0814 | 공격자가 재밍으로 링크 가용성을 거부 | `UAVDatalink_CL`, `UAVSatcomLink_CL` | `RxDropped`, `JamIndicator` | ✅ |
| [E] | Data Manipulation | T1565 | 공격자가 전송중/저장 데이터(SAR 표적·텔레메트리) 변조 | `UAVSatcomLink_CL`, `UAVSarPayload_CL` | `IntegrityStatus`, `TargetLat` | ✅ |
| [I] | Denial of View | T0815 | 공격자가 영상·상황인식을 일시 상실시킴 | `UAVTelemetry_CL`, `UAVImagery_CL` | `MsgType`, `EventType` | 🔜 |
| [I] | Manipulation of Control | T0831 | 공격자가 비인가 명령·파라미터 변조로 AV를 의도대로 비행시켜 통제권 탈취 | `UAVOperator_CL`, `UAVConfigAudit_CL`, `UAVMissionEvent_CL` | `SourceSystemId`, `ParamId`, `CustomModeAfter` | ✅ |
| [I] | Denial of Control | T0813 | 공격자가 재밍·DoS로 명령 도달을 막아 일시적 조종 불능 유발 | `UAVDatalink_CL`, `UAVSatcomLink_CL`, `UAVFailsafe_CL` | `RxDropped`, `JamIndicator`, `ModeAfter` | ✅ |
| [I] | Loss of View | T0829 | 공격자가 텔레메트리·영상 스트림을 지속 단절시켜 상황인식 상실 | `UAVTelemetry_CL`, `UAVImagery_CL`, `UAVDatalink_CL` | `MsgType`, `EventType`, `RxDropped` | 🔜 |
| [I] | Loss of Availability | T0826 | 공격자가 장기 재밍·서비스중단·추락으로 임무 수행 불가 상태 유발 | `UAVResourceMetrics_CL`, `UAVDatalink_CL`, `UAVFailsafe_CL` | `CpuUsagePct`, `RxDropped`, `ModeAfter` | ✅ |
| [I] | Loss of Protection | T0837 | 공격자가 RTL/LAND 등 보호 메커니즘을 무력화해 안전 보호 상실 | `UAVFailsafe_CL`, `UAVConfigAudit_CL` | `EventType`, `ParamId` | ✅ |
| [I] | Loss of Productivity and Revenue | T0828 | 공격자가 임무 중단·재출격·자산 손실로 정찰 성과 저하 | `UAVMissionEvent_CL`, `UAVMissionPlan_CL` | `EventName`, `Status` | ✅ |
| [E] | Endpoint Denial of Service | T1499 | 공격자가 mavlink-router·stub·QGC 자원을 고갈시켜 노드 응답 거부 | `UAVResourceMetrics_CL`, `UAVDatalinkConn_CL` | `CpuUsagePct`, `State` | ✅ |
| [E] | System Shutdown/Reboot | T1529 | 공격자가 FCC/지원 컨테이너를 강제 종료·재시작해 제어 중단·강제착륙 | `UAVResourceMetrics_CL`, `UAVFailsafe_CL` | `ContainerName`, `ModeAfter` | ✅ |
| [E] | Firmware Corruption | T1495 | 공격자가 FCC/모듈 펌웨어를 손상시켜 비행체 영구 불능화 | `UAVPgse_CL`, `UAVConfigAudit_CL` | `HashMatch`, `ParamId` | ✅ |
| [E] | Data Destruction | T1485 | 공격자가 정찰영상·임무계획·로그를 삭제해 작전 성과·복구 무력화 | - | - | ❌ |
| [E] | Account Access Removal | T1531 | 공격자가 운영자 계정/세션을 잠금·삭제해 GCS 통제 불가 | `UAVOpAudit_CL` | `EventType`, `FailReason`, `Operator` | 🔜 |

---

## 전체 요약

| 구분 | ✅ 현재 확인 가능 | 🔜 배포 예정 | ❌ 탐지 불가 | 합계 |
|---|---|---|---|---|
| 수지님 (Recon~Discovery) | 26개 | 0개 | 7개 | 33개 |
| 동언님 (Lateral~Impact) | 54개 | 0개 | 24개 | 78개 |
| **전체** | **80개** | **0개** | **31개** | **111개** |

(참조: KQL 설계 참고 노트 — 수지님 작업용)
