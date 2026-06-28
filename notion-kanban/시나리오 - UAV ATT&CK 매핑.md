# 시나리오 - UAV ATT&CK 매핑

- **Status**: In Review
- **담당자**: 김수지, 김동언
- **URL**: https://app.notion.com/p/38cf5e835bb480f3bcc2d98144721b3e

---

# UAV 공격 시나리오 ↔ MITRE ATT&CK 매핑
각 시나리오의 **킬체인 단계**를 UAV 매트릭스의 **Tactic / Technique / ID / 로그 테이블 / 컬럼 / 탐지상태**에 연결한다.

## 범례
- **상태**: ✅ 테이블 확인 + 데이터 있음 / 🔜 테이블 존재 (미션 실행 시 데이터 생성) / ❌ 탐지 불가
- **출처**: `[E]` Enterprise ATT&CK · `[I]` ICS ATT&CK · `[A]` ATLAS(적대적 ML) · `[M]` ATT&CK Mobile
- **ATLAS 비고**: S5·S8·(S7/S9 일부)는 ATLAS 도메인 위협으로, UAV ICS/Enterprise 매트릭스에 직접 대응 기법이 없음 → 근접 매핑 + 비고에 명시.

---

## S1. GPS/GNSS 스푸핑
**자산** GNSS (Tier 1) · **심각도** H
**킬체인** 정찰 → EW 위치선점 → 위조 GNSS 신호 주입 → EKF 잔차 급등 → 항로 이탈
**시나리오 명시 MITRE** ICS T0830·T0856·T0831·T0815 / Enterprise T1557·T1565·T1499

| 킬체인 단계 | 출처 | Tactic | Technique | ID | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| 정찰(호스트/센서 정보 수집) | [E] | Reconnaissance | Gather Victim Host Information | T1592 | `UAVThreatIntel_CL` | `IndicatorType`, `Indicator` | ✅ |
| 위조 GNSS 신호 주입(센서 I/O 변조) | [I] | Inhibit Response Function | Manipulate I/O Image | T0835 | `UAVTelemetry_CL` | `PosHorizVariance`, `VelocityVariance`, `FixType` | ✅ |
| 신호 중간자 가로채기 ※GNSS RF 주입 근사 | [E][I] | Collection | Adversary-in-the-Middle | T1557 / T0830 | `UAVSatcomLink_CL` | `IntegrityStatus`, `Seq` | ✅ |
| 위조 텔레메트리로 운용자 기만 | [I] | Impact | Manipulation of View | T0832 | `UAVTelemetry_CL`, `UAVSatcomLink_CL` | `PosHorizVariance`, `IntegrityStatus` | ✅ |
| 위조 위치 데이터로 항법 상태 오염 | [E] | Impact | Data Manipulation | T1565 | `UAVSatcomLink_CL`, `UAVSarPayload_CL` | `IntegrityStatus`, `TargetLat` | ✅ |
| 비인가 제어로 항로 이탈 | [I] | Impact | Manipulation of Control | T0831 | `UAVOperator_CL`, `UAVConfigAudit_CL`, `UAVMissionEvent_CL` | `SourceSystemId`, `ParamId`, `CustomModeAfter` | ✅ |
| 위조 GPS 메시지로 항법 연산 부하 | [E] | Impact | Endpoint Denial of Service | T1499 | `UAVResourceMetrics_CL`, `UAVDatalinkConn_CL` | `CpuUsagePct`, `State` | ✅ |
| 상황인식 차단 | [I] | Impact | Denial of View | T0815 | `UAVTelemetry_CL`, `UAVImagery_CL` | `MsgType`, `EventType` | ✅ |

> **탐지 연결**: 룰은 부작용인 **EKF 잔차 이상**을 탐지 → **T0835 Manipulate I/O Image**에 대응. 보조신호 `FixType`/`SatellitesVisible`/`Eph_cm`는 T0832 정탐 신뢰도 가산.
> **매트릭스 미포함 ICS**: T0856 Spoof Reporting Message → T0832로 근사.

---

## S2. C2 재밍·하이재킹
**자산** C2_LINK (Tier 1) · **심각도** H
**킬체인** 재밍 → 세션 하이재킹 → 명령주입 → 통제권 탈취

| 킬체인 단계 | 출처 | Tactic | Technique | ID | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| 재밍(링크 거부) | [I] | Inhibit Response Function | Denial of Service | T0814 | `UAVDatalink_CL`, `UAVSatcomLink_CL` | `RxDropped`, `JamIndicator` | ✅ |
| 무선 채널 침투 | [I] | Initial Access | Wireless Compromise | T0860 | `UAVDatalink_CL` | `RxErrors`, `RxDropped` | ✅ |
| 세션 하이재킹 | [E] | Lateral Movement | Remote Service Session Hijacking | T1563 | `UAVSatcomLink_CL`, `UAVGcsAccess_CL` | `SessionId`, `ClientIp` | ✅ |
| 명령 주입(비인가 메시지) | [I] | Execution | Unauthorized Message | T1692.001 | `UAVOperator_CL`, `UAVDatalinkConn_CL` | `SourceSystemId`, `PeerIp` | ✅ |
| 정상 GCS 위장 | [E][I] | Stealth/Evasion | Masquerading | T1036 / T0849 | `UAVOperator_CL` | `SourceSystemId` | ✅ |
| 통제권 탈취 | [I] | Impact | Manipulation of Control | T0831 | `UAVOperator_CL`, `UAVConfigAudit_CL`, `UAVMissionEvent_CL` | `SourceSystemId`, `ParamId`, `CustomModeAfter` | ✅ |
| 조종 불능 | [I] | Impact | Denial of Control | T0813 | `UAVDatalink_CL`, `UAVSatcomLink_CL`, `UAVFailsafe_CL` | `RxDropped`, `JamIndicator`, `ModeAfter` | ✅ |

> **탐지 연결**: `isUnauth`(SystemId 불일치) = T1692.001 + T1036/T0849, `isJamming`(RSSI↓·패킷손실↑) = T0814, `isReplay`(시퀀스 역행) = T1563 리플레이 징후.

---

## S3. SATCOM MITM
**자산** SATCOM (Tier 2) · **심각도** M(방첩 상향 시 H)

| 킬체인 단계 | 출처 | Tactic | Technique | ID | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| 정찰(네트워크 정보 수집) | [E] | Reconnaissance | Gather Victim Network Information | T1590 | - | - | ❌ |
| SATCOM 중간자 가로채기 | [E][I] | Collection | Adversary-in-the-Middle | T1557 / T0830 | `UAVSatcomLink_CL` | `IntegrityStatus`, `Seq` | ✅ |
| 무선 링크 도청 | [I] | Discovery | Wireless Sniffing | T0887 | `UAVSatcomLink_CL` | `IntegrityStatus` | ✅ |
| 링크 콘텐츠 주입 | [E] | Command and Control | Content Injection | T1659 | `UAVSatcomLink_CL` | `IntegrityStatus`, `Seq` | ✅ |
| 전송중 데이터 변조 | [E] | Impact | Data Manipulation | T1565 | `UAVSatcomLink_CL`, `UAVSarPayload_CL` | `IntegrityStatus`, `TargetLat` | ✅ |
| 위조 영상/표적으로 기만 | [I] | Impact | Manipulation of View | T0832 | `UAVTelemetry_CL`, `UAVSatcomLink_CL` | `PosHorizVariance`, `IntegrityStatus` | ✅ |
| 데이터 유출 | [E] | Exfiltration | Exfiltration Over C2 Channel | T1041 | `UAVDatalink_CL`, `UAVSatcomLink_CL` | `TxBytes`, `SessionId` | ✅ |

> **탐지 연결**: 체크섬 불일치는 T1565 / T0830의 변조 증거. 지연시간 단독은 환경요인이라 Watchlist로 억제.

---

## S4. 펌웨어·공급망 변조
**자산** AUTOPILOT (Tier 1) · **심각도** H

| 킬체인 단계 | 출처 | Tactic | Technique | ID | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| 공급망 임플란트 | [E][I] | Initial Access | Supply Chain Compromise | T1195 / T0862 | `UAVPgse_CL` | `HashMatch`, `SbomForbiddenCount`, `Passed` | ✅ |
| 펌웨어 백도어 삽입 | [E][I] | Persistence | Modify Firmware | T1542 / T1693.001 | `UAVPgse_CL` | `HashMatch`, `Passed` | ✅ |
| 변조 펌웨어 배포 | [E][I] | Initial Access | Supply Chain Compromise | T1195 / T0862 | `UAVPgse_CL` | `HashMatch`, `Passed` | ✅ |
| 편대 전파(프로그램 다운로드) | [I] | Lateral Movement | Program Download | T0843 | `UAVConfigAudit_CL`, `UAVMissionEvent_CL` | `ParamId`, `EventName` | ✅ |
| 제어로직 변조(트리거) | [I] | Impair Process Control | Modify Firmware | T1693 | `UAVPgse_CL` | `HashMatch`, `Passed` | ✅ |
| 변조 후 정상 위장 | [E] | Stealth/Evasion | Modify System Image | T1601 | `UAVPgse_CL`, `UAVCyberPosture_CL` | `HashMatch`, `Level`, `ChangedBy`, `Reason` | ✅ |
| 펌웨어 영구 손상 | [E] | Impact | Firmware Corruption | T1495 | `UAVPgse_CL`, `UAVConfigAudit_CL` | `HashMatch`, `ParamId` | ✅ |

> Zero-Tolerance(서명·해시·SBOM 중 하나라도 불일치) = T1195/T0862 + T1542/T1693 + T1601 합집합.

---

## S5. RAG 포이즈닝 (AI_SOC 지식베이스/정책 오염)
**자산** AI_SOC (Tier 0, 제안) · **심각도** H(메타위협)

> ⚠️ ATLAS 1차 기준. UAV 매트릭스로는 근사 매핑.

| 킬체인 단계 | ATLAS 기법 | 근접 UAV 매트릭스 | ID | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|
| KB 접근(신뢰출처 위장) | AML.T0051.001 | (직접 대응 없음) | - | `AISOC_RAG_Logs_CL` | `DocSource_s` | ❌ |
| 오염 문서 주입(저장 데이터 변조) | AML.T0020 | [E] Impact · Data Manipulation | T1565 (근사) | `InternalKB_Documents_CL` | `IntegrityHash_s` 대조 | 🔜 |
| 내부 KB 직접 변조 후 위장 | RAGPoison | [E] Stealth · Modify System Image | T1601 (근사) | `Trusted_KB_Source_List` | `IntegrityHash_s` | 🔜 |
| 심각도 오판 → 대응 무력화 | AML.T0054 | [I] Inhibit · Alarm Suppression | T0878 (근사) | `AISOC_RAG_Logs_CL` | `SeverityGap` | ❌ |

---

## S6. GCS 침해·횡적확산
**자산** GCS (Tier 1) · **심각도** H

| 킬체인 단계 | 출처 | Tactic | Technique | ID | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| 초기침투(외부 원격 서비스) | [E] | Initial Access | External Remote Services | T1133 | `UAVGcsAccess_CL` | `ClientIp`, `Transport` | ✅ |
| 유효계정 탈취 | [E] | Initial Access | Valid Accounts | T1078 | `UAVOpAudit_CL`, `UAVThreatIntel_CL` | `EventType`, `ClientIp`, `Indicator` | ✅ |
| 고권한 계정 탈취 | [E] | Privilege Escalation | Valid Accounts | T1078 | `UAVOpAudit_CL`, `UAVC4I_CL` | `Operator`, `ClientIp`, `IssuedBy`, `TargetPriority` | ✅ |
| 다수기체 재지정 | [I] | Execution | Modify Controller Tasking | T0821 | `UAVConfigAudit_CL` | `ParamId`, `ParamValueAfter` | ✅ |
| 비인가 명령 주입 | [I] | Execution | Unauthorized Message | T1692.001 | `UAVOperator_CL`, `UAVDatalinkConn_CL` | `SourceSystemId`, `PeerIp` | ✅ |
| 횡적확산(계정 재사용) | [E][I] | Lateral Movement | Valid Accounts | T1078 / T0859 | `UAVOpAudit_CL` | `Operator`, `ClientIp` | ✅ |
| 횡적확산(원격서비스 취약점) | [E][I] | Lateral Movement | Exploitation of Remote Services | T1210 / T0866 | `UAVDatalinkConn_CL` | `PeerIp`, `State` | ✅ |
| 도구 전파 | [E][I] | Lateral Movement | Lateral Tool Transfer | T1570 / T0867 | `UAVServiceAudit_CL` | `Action`, `ImageName` | ✅ |

---

## S7. UGV 원격조종 탈취·노획
**자산** UGV_TELEOP (Tier 1) · **심각도** H

| 킬체인 단계 | 출처 | Tactic | Technique | ID | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| 정찰 | [E] | Reconnaissance | Gather Victim Host Information | T1592 | `UAVThreatIntel_CL` | `IndicatorType`, `Indicator` | ✅ |
| 재밍(링크 거부) | [I] | Inhibit Response Function | Denial of Service | T0814 | `UAVDatalink_CL`, `UAVSatcomLink_CL` | `RxDropped`, `JamIndicator` | ✅ |
| 센서 스푸핑(I/O 변조) [A]근사 | [I] | Inhibit Response Function | Manipulate I/O Image | T0835 | `UAVTelemetry_CL` | `PosHorizVariance`, `VelocityVariance`, `FixType` | ✅ |
| 기동불능(통제 상실) | [I] | Impact | Loss of Control | T0827 | `UAVOperator_CL`, `UAVFailsafe_CL` | `Result`, `ModeAfter` | ✅ |
| 비인가 조종으로 차량 탈취 | [I] | Impact | Manipulation of Control | T0831 | `UAVOperator_CL`, `UAVConfigAudit_CL`, `UAVMissionEvent_CL` | `SourceSystemId`, `ParamId`, `CustomModeAfter` | ✅ |
| 지상 노획(물리 손상) | [I] | Impact | Damage to Property | T0879 | `UAVFailsafe_CL`, `UAVTelemetry_CL` | `ModeAfter`, `AltRel_m` | ✅ |
| 자격증명 탈취 | [E][I] | (post-capture) Valid Accounts | Valid Accounts | T1078 / T0859 | `UAVOpAudit_CL` | `Operator`, `ClientIp` | ✅ |

---

## S8. 온보드 표적인식 AI 적대적 공격
**자산** PAYLOAD_EOIR (Tier 2) · **심각도** M(무장유도 연계 시 H)

> ⚠️ ATLAS 1차 기준.

| 킬체인 단계 | ATLAS 기법 | 근접 UAV 매트릭스 | ID | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|
| 모델 정찰(무권한 접근) | AML.T0015 | (직접 대응 없음) | - | - | - | ❌ |
| 적대적 패치/디코이 | AML.T0043 | (직접 대응 없음) | - | `PayloadEOIR_Inference_CL` | `EO_TargetClass_s` vs `IR_TargetClass_s` | 🔜 |
| 인식 회피 → 위조 표적 인식 | AML.T0020 | [I] Impact · Manipulation of View | T0832 (근사) | `UAVTelemetry_CL`, `UAVSatcomLink_CL` | `PosHorizVariance`, `IntegrityStatus` | ✅ |
| 표적 좌표 변조(무장유도 연계) | - | [E] Impact · Data Manipulation | T1565 (근사) | `UAVSatcomLink_CL`, `UAVSarPayload_CL` | `IntegrityStatus`, `TargetLat` | ✅ |
| 임무 무력화 | - | [I] Impact · Loss of Productivity | T0828 (근사) | `UAVMissionEvent_CL`, `UAVMissionPlan_CL` | `EventName`, `Status` | ✅ |

---

## S9. 군집 포화·SOC 과부하
**자산** AI_SOC (Tier 0) · **심각도** H

| 킬체인 단계 | 출처 | Tactic | Technique | ID | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| 다축 동시 침해(링크 거부) | [E][I] | Impact | Network Denial of Service | T1498 / T0814 | `UAVDatalink_CL`, `UAVSatcomLink_CL` | `RxDropped`, `JamIndicator` | ✅ |
| 비인가 명령 폭주 | [I] | Execution | Unauthorized Message | T1692.001 | `UAVOperator_CL`, `UAVDatalinkConn_CL` | `SourceSystemId`, `PeerIp` | ✅ |
| 경보 폭주 → 노드 자원 고갈 | [E] | Impact | Endpoint Denial of Service | T1499 | `UAVResourceMetrics_CL`, `UAVDatalinkConn_CL` | `CpuUsagePct`, `State` | ✅ |
| 운용자·탐지 포화 | [I] | Impact | Loss of Availability | T0826 | `UAVResourceMetrics_CL`, `UAVDatalink_CL`, `UAVFailsafe_CL` | `CpuUsagePct`, `RxDropped`, `ModeAfter` | ✅ |
| SOC 마비(메타) | [A] | (ATLAS) ML DoS | AML.T0029 | (직접 대응 없음) | `SOC_Alert_Stream_CL` | `AssetId_s`, `ScenarioId_s` | 🔜 |

---

## S10. SATCOM 단말/관리망 무력화
**자산** SATCOM (Tier 2) · **심각도** H

| 킬체인 단계 | 출처 | Tactic | Technique | ID | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| 관리망 침투(외부 원격 서비스) | [E] | Initial Access | External Remote Services | T1133 | `UAVGcsAccess_CL` | `ClientIp`, `Transport` | ✅ |
| 유효계정 | [E][I] | Initial Access | Valid Accounts | T1078 / T0859 | `UAVOpAudit_CL` | `Operator`, `EventType` | ✅ |
| 악성 펌웨어 업데이트 | [E][I] | Persistence | Modify Firmware | T1542 / T1693.001 | `UAVPgse_CL` | `HashMatch`, `Passed` | ✅ |
| 링크 거부(단말 동시 접속 차단) | [I] | Inhibit Response Function | Denial of Service | T0814 | `UAVDatalink_CL`, `UAVSatcomLink_CL` | `RxDropped`, `JamIndicator` | ✅ |
| 모뎀 무력화(서비스 중단) | [I] | Inhibit Response Function | Service Stop | T0881 | `UAVServiceAudit_CL` | `Action`, `ContainerName` | ✅ |
| 강제 재시작/종료 | [I] | Inhibit Response Function | Device Restart/Shutdown | T0816 | `UAVResourceMetrics_CL`, `UAVFailsafe_CL`, `UAVOperator_CL` | `ContainerName`, `ModeAfter`, `Command` | ✅ |
| 데이터 파괴 | [I] | Inhibit Response Function | Data Destruction | T0809 | - | - | ❌ |
| 운용망 고립(가용성 상실) | [I] | Impact | Loss of Availability | T0826 | `UAVResourceMetrics_CL`, `UAVDatalink_CL`, `UAVFailsafe_CL` | `CpuUsagePct`, `RxDropped`, `ModeAfter` | ✅ |

---

## S11. 모바일/전술 GCS 침해
**자산** GCS (Tier 1) · **심각도** H

| 킬체인 단계 | 출처 | Tactic | Technique | ID | 로그 테이블 | 컬럼 | 상태 |
|---|---|---|---|---|---|---|---|
| 악성앱/임플란트(임시 자산) | [I][M] | Initial Access | Transient Cyber Asset | T0864 | `UAVMaintenance_CL` | `Operator`, `ComponentName`, `EventType` | ✅ |
| 유효계정 탈취 | [E][I] | Initial Access | Valid Accounts | T1078 / T0859 | `UAVOpAudit_CL` | `Operator`, `EventType` | ✅ |
| 세션 토큰 재사용(대체 인증) | [E] | Lateral Movement | Use Alternate Authentication Material | T1550 | `UAVOpAudit_CL`, `UAVMavsec_CL` | `SessionId`, `ClientIp`, `FailedCount` | ✅ |
| 임무·자격증명 유출 | [E] | Exfiltration | Exfiltration Over C2 Channel | T1041 | `UAVDatalink_CL`, `UAVSatcomLink_CL` | `TxBytes`, `SessionId` | ✅ |
| 위조임무 업로드 | [E] | Execution | User Execution | T1204 | `UAVMissionPlan_CL` | `PlanId`, `Planner`, `Roe`, `Status` | ✅ |
| GCS 확산(도구 전파) | [E][I] | Lateral Movement | Lateral Tool Transfer | T1570 / T0867 | `UAVServiceAudit_CL` | `Action`, `ImageName` | ✅ |

---

## 종합 매핑 요약

| 시나리오 | 자산 | 주요 Tactic 경로 | 대표 ID(매트릭스) | ATLAS 비고 |
|---|---|---|---|---|
| S1 GPS/GNSS 스푸핑 | GNSS | Recon → Inhibit(I/O변조) → Collection(AiTM) → Impact | T1592 · **T0835** · T1557/T0830 · T0832 · T1565 · T0831 · T1499 · T0815 | T0856 → T0832 근사 |
| S2 C2 재밍·하이재킹 | C2_LINK | Inhibit(DoS) → Initial(무선) → Lateral(하이재킹) → Execution → Impact | T0814 · T0860 · T1563 · T1692.001 · T0831 · T0813 | - |
| S3 SATCOM MITM | SATCOM | Recon → Collection(AiTM) → Discovery → C2 → Impact → Exfil | T1557/T0830 · T0887 · T1659 · T1565 · T0832 · T1041 | - |
| S4 펌웨어·공급망 | AUTOPILOT | Initial(공급망) → Persistence → Lateral → Impair → Stealth → Impact | T1195/T0862 · T1542/T1693 · T0843 · T1601 · T1495 | - |
| S5 RAG 포이즈닝 | AI_SOC | (ATLAS) KB변조 → 심각도 오판 | T1565·T1601·T0878 *(근사)* | **ATLAS 1차** AML.T0051.001/T0020/T0054 |
| S6 GCS 횡적확산 | GCS | Initial(원격) → Valid → PrivEsc → Execution → Lateral×3 | T1133 · T1078 · T0821 · T1210/T0866 · T1570/T0867 | - |
| S7 UGV 노획 | UGV_TELEOP | Recon → Inhibit(DoS·I/O) → Impact(통제상실·탈취·물리) → Valid | T1592 · T0814 · **T0835** · T0827 · **T0831** · T0879 · T1078 | T0043 근사 |
| S8 온보드 AI 적대공격 | PAYLOAD_EOIR | (ATLAS) 모델정찰 → 적대패치 → 인식회피 | T0832·T1565·T0828 *(근사)* | **ATLAS 1차** AML.T0015/T0043/T0020 |
| S9 군집 포화 | AI_SOC | (메타) 다축 DoS → 경보폭주 → 가용성/SOC 마비 | T1498/T0814 · T1499 · T0826 | T0029 근사 |
| S10 SATCOM 무력화 | SATCOM | Initial(관리망) → Valid → Persistence → Inhibit → Impact | T1133 · T1078/T0859 · T1542/T1693 · **T0814** · T0881 · T0816 · T0826 | T0857→T1693, T0822→T1133 |
| S11 모바일 GCS 침해 | GCS | Initial → Valid → Lateral(대체인증) → Exfil → Execution → Lateral | T0864 · T1078/T0859 · T1550 · T1041 · T1204 · T1570/T0867 | ATT&CK Mobile 연계 |

### 매핑 원칙 메모
1. 킬체인 단계 → 매트릭스 기법 단위로 매핑.
2. 탐지룰이 실제로 보는 신호가 어느 기법에 대응하는지 명시.
3. S5·S8 등 ATLAS 도메인은 ATLAS 1차 + 결과 측면 ICS/Enterprise 근사.
4. 매트릭스 미포함 ICS 기법 처리: T0822→T1133, T0855→T1692.001, T0856→T0832, T0857→T1542/T1693.001, T0889→T0821/T0836.
