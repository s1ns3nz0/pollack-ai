# D3FEND UAV 만들기

- **Status**: In Review
- **담당자**: 김수지, 김동언
- **URL**: https://app.notion.com/p/38cf5e835bb480af9ab7eadd6aa7e757

---

(첨부 파일: d3fend_technique_full_v3.html)

> 💡 공격: T1595 Active Scanning → 방어: D3-NTA로 탐지 / D3-NI로 포트 격리 / D3-ITF로 인바운드 차단

# UAV × MITRE D3FEND 대응 매트릭스

## 0. D3FEND 대응기술 사전 (본 문서 사용분)

| 전술 | D3-ID | 대응기술 | UAV 적용 요지 |
|---|---|---|---|
| Model | `D3-AI` | Asset Inventory | UAS 5+1 구성요소·링크·컨테이너 자산 식별 |
| Model | `D3-OAM` | Operational Activity Mapping | 정상 운용자/명령/임무 베이스라인 |
| Harden | `D3-PH` | Platform Hardening | 호스트/컨테이너/FCC 강화 |
| Harden | `D3-AH` | Application Hardening | QGC·mavlink-router·stub 취약점 제거 |
| Harden | `D3-AA` | Agent Authentication | 운영자/구성요소 인증(auth-stub) |
| Harden | `D3-CH` | Credential Hardening | 자격 강화(기본/하드코딩 제거) |
| Harden | `D3-ACH` | Application Configuration Hardening | ArduPilot 파라미터·FS_* 보호 |
| Harden | `D3-MAN` | Message Authentication | **MAVLink2 서명**(평문 인젝션 차단) ★ |
| Harden | `D3-MENCR` | Message Encryption | 메시지 암호화 |
| Detect | `D3-NTA` | Network Traffic Analysis | UAVDatalink/RouterStats/DatalinkConn |
| Detect | `D3-UBA` | User Behavior Analysis | UAVOpAudit·운용자 이상행위 |
| Detect | `D3-FA` | File Analysis | 컨테이너 파일/펌웨어 분석 |
| Detect | `D3-PM` | Platform Monitoring | UAVServiceAudit·UAVResourceMetrics |
| Detect | `D3-PA` | Process Analysis | 컨테이너 프로세스 분석 |
| Detect | `D3-PHAM` | Physical Access Monitoring | 페이로드/지상장비 물리 접근 |
| Isolate | `D3-NI` | Network Isolation | 5790/8080 세그먼트 격리 |
| Isolate | `D3-ET` | Encrypted Tunnels | **링크 암호화/터널**(C-band/SATCOM 평문 제거) ★ |
| Isolate | `D3-AMED` | Access Mediation | 명령/자원 접근 중재 |
| Isolate | `D3-APA` | Access Policy Administration | 권한·2인통제 정책 |
| Isolate | `D3-CF` | Content Filtering | MAVLink/링크 콘텐츠 필터 |
| Isolate | `D3-EI` | Execution Isolation | 컨테이너 격리(탈출 방지) |
| Deceive | `D3-DO` | Decoy Object | 허니팟 GCS/가짜 MAVLink |
| Evict | `D3-OE` | Object Eviction | 악성 객체 제거 |
| Evict | `D3-CE` | Credential Eviction | 탈취 자격/세션 폐기 |
| Evict | `D3-PE` | Process Eviction | 인젝터 프로세스 종료 |
| Restore | `D3-RO` | Restore Object | 변조/삭제 데이터 복구 |
| Restore | `D3-RA` | Restore Access | 잠긴 운영자 접근 복구 |

> ★ 우리 `❌` 사각지대의 근본 대응:
> **`D3-MAN`(MAVLink2 서명, Harden)** = 평문 인젝션 차단,
> **`D3-MENCR`(Harden)·`D3-ET`(Isolate=Network Isolation 하위)** = 링크 암호화로 수동 도청 차단.

---

## 1. ATT&CK(마스터) → D3FEND 대응 (전술별)

> 표기: D3-ID는 **D3FEND v1.4.0 공식 매핑**(ENT 기법) 그대로. `[쌍 Txxxx]`=ICS를 Enterprise 쌍으로 대체, `[custom]`=D3FEND 미커버.
> 상태=마스터의 탐지상태(✅/🔜/❌). 공통 묶음: **NET** = `D3-NTA·D3-UBA·D3-NI`.

### 1. Reconnaissance
| ATT&CK | 상태 | D3FEND 대응 | 비고 |
|---|---|---|---|
| T1595 Active Scanning | ✅ | `D3-NTA`·`D3-NI`·`D3-ITF`(인바운드필터) | 일부 [custom](D3FEND 미세매핑) |
| T1592 / T1590 / T1596 | ❌ | `D3-AI`(자산 노출 최소화)·외부 OSINT 통제 | [custom] 사전침해 |

### 2. Resource Development
| ATT&CK | 상태 | D3FEND 대응 | 비고 |
|---|---|---|---|
| T1587/T1588/T1608 | ❌ | (외부 공격자 측) — 방어 대상 외 | [custom] 통제 불가 |

### 3. Initial Access
| ATT&CK | 상태 | D3FEND 대응 | 비고 |
|---|---|---|---|
| T1190/T0819 Exploit Public-Facing | ✅ | `D3-AH`·`D3-NTA`·`D3-PA`·`D3-UBA`·`D3-NI` | 공식(T1190) |
| T1133 External Remote Services | ✅ | `D3-PE` (+ `D3-NI`·`D3-AMED`) | 공식(T1133)=Evict |
| T1195/T0862 Supply Chain | ✅ | `D3-PH`·펌웨어/이미지 서명검증·SBOM | [custom](T1195 D3FEND 미매핑) |
| T1078 Valid Accounts | ✅ | `D3-OAM`·`D3-AA`·`D3-CH`·`D3-APA`·`D3-CE`·`D3-RA` | 공식(T1078) |
| T0860 Wireless Compromise | ✅ | `D3-ET`/`D3-MENCR`(링크 암호화) + 항재밍 | [custom] RF |
| T0864 Transient Cyber Asset | ✅ | `D3-AI`·이동매체 통제·`D3-AMED` | [custom] ICS |

### 4. Execution
| ATT&CK | 상태 | D3FEND 대응 | 비고 |
|---|---|---|---|
| T1059 Command and Scripting | ✅ | `D3-PH`·`D3-FA`·`D3-PM`·`D3-AMED`·`D3-APA`·`D3-CF`·`D3-EI`·`D3-DO`·`D3-OE`·`D3-RO` | 공식(T1059) |
| T1106/T0871 Native API | ✅ | `D3-PA`·`D3-AMED` (+ `D3-MAN`) | 공식(T1106)+MAVLink 서명 |
| T1204 User Execution | ✅ | `D3-APA`(2인통제)·`D3-OAM` | [custom] |
| T0821 Modify Controller Tasking | ✅ | `D3-ACH`·`D3-MAN` | [custom] ICS 파라미터 |
| T1692.001 Unauthorized Message | ✅ | `D3-MAN`(MAVLink 서명)·`D3-NTA`·`D3-CF` | [custom] ICS(주입) ★ |

### 5. Persistence
| ATT&CK | 상태 | D3FEND 대응 | 비고 |
|---|---|---|---|
| T1556 Modify Auth Process | ✅ | `D3-PA`·`D3-AMED`·`D3-EI`·`D3-PE` | 공식(T1556) |
| T1542/T1693.001 Modify Firmware | ✅ | `D3-PH`·보안부팅·펌웨어 서명검증(PGSE) | [custom] |
| T1078/T0859 Valid Accounts | ✅ | `D3-OAM`·`D3-AA`·`D3-CH`·`D3-APA`·`D3-CE`·`D3-RA` | 공식(T1078) |
| T1546 Event Triggered Execution | ✅ | `D3-PA`·`D3-PM`·`D3-FA` | [custom] |

### 6. Privilege Escalation
| ATT&CK | 상태 | D3FEND 대응 | 비고 |
|---|---|---|---|
| T1068/T0890 | ✅ | `D3-AH`·`D3-PM`·`D3-PA` | 공식(T1068) |
| T1078 Valid Accounts | ✅ | (동일) | 공식 |

### 7. Stealth / Evasion
| ATT&CK | 상태 | D3FEND 대응 | 비고 |
|---|---|---|---|
| T1070/T0872 Indicator Removal | ✅ | `D3-PH`·원격/불변 로깅·`D3-RO` | [custom] |
| T1036/T0849 Masquerading | ✅ | `D3-MAN`(출처 위장 차단)·`D3-UBA` | [custom] |
| T1601 Modify System Image | ✅ | `D3-PH`·이미지/펌웨어 서명검증 | [custom] |
| T1014 Rootkit | ❌ | `D3-AI`·`D3-PH`·`D3-FA`·`D3-PM`·`D3-OE`·`D3-RO` | 공식(T1014) |
| T1692.001 Unauthorized Message | ✅ | `D3-MAN`·`D3-NTA` | [custom] ICS ★ |
| T0878 Alarm Suppression | ✅ | `D3-PM`·경보 무결성 | [custom] ICS |

### 8. Discovery
| ATT&CK | 상태 | D3FEND 대응 | 비고 |
|---|---|---|---|
| T0840 Network Connection Enum | ✅ | `D3-NTA`·`D3-NI` | [쌍/custom] |
| T0842/T0887 Sniffing | ❌ | `D3-ET`/`D3-MENCR`(링크 암호화) ★ | [custom] 수동도청=암호화가 유일 대응 |

### 9. Lateral Movement
| ATT&CK | 상태 | D3FEND 대응 |
|---|---|---|
| T1078/T0859 | ✅ | `D3-OAM`·`D3-AA`·`D3-CH`·`D3-APA`·`D3-CE`·`D3-RA` |
| T0843 Program Download | ✅ | `D3-MAN`·`D3-ACH`(서명된 임무/파라미터) |
| T1210/T0866 Exploitation of Remote Services | ✅ | `D3-AH`·`D3-NTA`·`D3-PM`·`D3-PA`·`D3-UBA`·`D3-NI` |
| T1563 Remote Service Session Hijacking | ✅ | **NET** • `D3-PE` |
| T1570/T0867 Lateral Tool Transfer | ✅ | **NET** |
| T1021/T0886 Remote Services | ✅ | **NET** |
| T1550 Use Alt Auth Material | ✅ | `D3-PA`·`D3-AMED`·`D3-EI`·`D3-PE` |
| T1694 Insecure Credentials | ✅ | `D3-CH`·`D3-ACH` |
| T1080 Taint Shared Content | ✅ | `D3-AMED`·`D3-DO` (+ `D3-MAN` 서명임무) |

### 10. Collection
| ATT&CK | 상태 | D3FEND 대응 |
|---|---|---|
| T1557/T0830 AiTM | ✅ | **NET** + `D3-MAN`·`D3-MENCR` |
| T1125 Video Capture | ❌ | `D3-AI`·`D3-PH`·`D3-PHAM`·`D3-PM`·`D3-AMED` (+ `D3-ET`) |
| T1119/T0802 Automated Collection | ❌ | `D3-PH`·`D3-FA`·`D3-PM`·`D3-AMED`·`D3-APA`·`D3-CF` |
| T0845/T0801/T0868/T0861 | ❌ | `D3-ET`/`D3-MENCR`·`D3-AMED` |
| T0887 Wireless Sniffing | ❌ | `D3-ET`/`D3-MENCR` ★ |
| T1113/T0852 Screen Capture | ❌ | `D3-PA`·`D3-AMED` |
| T1185 Browser Session Hijacking | ✅ | **NET** |
| T1005/T0893 | ❌ | `D3-PH`·`D3-FA`·`D3-PM`·`D3-AMED`·`D3-APA`·`D3-CF` |
| T1056 Input Capture | ❌ | `D3-PH`·`D3-PA` |
| T1074/T1560 Staged/Archive | ❌ | `D3-PH`·`D3-FA`·`D3-PM`·`D3-AMED` |

### 11. Command and Control
| ATT&CK | 상태 | D3FEND 대응 |
|---|---|---|
| T1071/T0869 Std App Layer | ✅ | `D3-PH`·`D3-FA`·`D3-NTA`·`D3-PM`·`D3-UBA`·`D3-AMED`·`D3-APA`·`D3-CF`·`D3-NI`·`D3-DO`·`D3-OE`·`D3-RO` (+ `D3-MAN`) |
| T1571/T0885 Non-Standard Port | ✅ | **NET** |
| T1090/T0884 Proxy | ✅ | `D3-NTA`·`D3-NI` |
| T1008 Fallback Channels | ✅ | **NET** |
| T1659 Content Injection | ✅ | `D3-MAN`·`D3-CF`·`D3-NTA` |
| T1105 Ingress Tool Transfer | ✅ | **NET** (+ `D3-FA`) |
| T1095 Non-App Layer Protocol | ✅ | **NET** |
| T1572 Protocol Tunneling | ❌ | **NET** (터널 식별 한계) |
| T1104 Multi-Stage Channels | ✅ | **NET** |
| T1573 Encrypted Channel | ❌ | **NET** (콘텐츠 검사 불가) |
| T1219 Remote Access Tools | ✅ | **NET** |
| T1001/T1132 Obfuscation/Encoding | ❌ | **NET** |

### 12. Exfiltration
| ATT&CK | 상태 | D3FEND 대응 |
|---|---|---|
| T1041 Exfil Over C2 | ✅ | `D3-PH`·`D3-FA`·`D3-NTA`·`D3-PM`·`D3-UBA`·`D3-AMED`·`D3-APA`·`D3-CF`·`D3-NI`·`D3-DO`·`D3-OE`·`D3-RO` |
| T1020/T1029/T1048/T1030 | ✅ | **NET** |
| T1011 Exfil Over Other Medium | ❌ | **NET** (SATCOM 용량 미포착) |
| T1567 Exfil Over Web Service | ❌ | **NET** |

### 13. Impair Process Control
| ATT&CK | 상태 | D3FEND 대응 |
|---|---|---|
| T0836 Modify Parameter | ✅ | `D3-ACH`·`D3-MAN`·`D3-APA` |
| T1693 Modify Firmware | ✅ | `D3-PH`·보안부팅·펌웨어 서명 |
| T1692 Unauthorized Message | ✅ | `D3-MAN`·`D3-NTA`·`D3-CF` ★ |
| T0806 Brute Force I/O | ✅ | `D3-MAN`·`D3-AMED`·`D3-NTA` |

### 14. Inhibit Response Function
| ATT&CK | 상태 | D3FEND 대응 |
|---|---|---|
| T0838 Modify Alarm Settings | ✅ | `D3-ACH`(FS_* 보호)·`D3-MAN` |
| T0814/T1498/T1499 DoS | ✅ | 항재밍·링크 다중화·`D3-NI` |
| T1695 Block Communications | ✅ | 항재밍·링크 다중화 |
| T1691.002 Block Reporting Message | ✅ | `D3-CF`·`D3-MAN` |
| T0881 Service Stop | ✅ | `D3-PM`·서비스 감시·`D3-RO` |
| T0878 Alarm Suppression | ❌ | `D3-PM`·경보 무결성 |
| T0816 Device Restart/Shutdown | ✅ | `D3-PM`·`D3-AMED` |
| T0892 Change Credential | ✅ | `D3-AA`·`D3-CH`·`D3-CE`·`D3-RA` |
| T0835 Manipulate I/O Image | ✅ | 다중센서 융합·항스푸핑 (GNSS) |
| T0809 Data Destruction | ❌ | `D3-RO`·원격/불변 로깅 |
| T0800 Activate Firmware Update Mode | ❌ | 보안부팅·펌웨어모드 인가 |
| T0851 Rootkit | ❌ | `D3-AI`·`D3-PH`·`D3-FA`·`D3-PM`·`D3-OE`·`D3-RO` |

### 15. Impact
| ATT&CK | 상태 | D3FEND 대응 |
|---|---|---|
| T0832/T1565 Manipulation of View / Data Manipulation | ✅ | `D3-MAN`·`D3-MENCR`·`D3-RO`·다중센서 검증 |
| T0831 Manipulation of Control | ✅ | `D3-MAN`·`D3-APA`·`D3-ACH` |
| T0882 Theft of Operational Information | ❌ | `D3-ET`/`D3-MENCR`·`D3-APA` |
| T0827/T0813/T0829/T0815/T0826 | ✅ | 항재밍·링크 다중화·`D3-RO`·`D3-RA` |
| T0880/T0837/T0879 | ✅ | `D3-ACH`(Failsafe 보호)·`D3-RO` |
| T0828 Loss of Productivity | ✅ | `D3-RA` |
| T1498/T0814/T1499 DoS | ✅ | 항재밍·`D3-NI`·자원 제한 |
| T1529 System Shutdown / T1495 Firmware Corruption | ✅ | `D3-PM`·`D3-PH`·보안부팅·`D3-RO` |
| T1485 Data Destruction | ❌ | `D3-RO`·불변 로깅 |
| T1531 Account Access Removal | ✅ | `D3-OAM`·`D3-AA`·`D3-CH`·`D3-APA`·`D3-CE`·`D3-RA` |

---

## 2. D3FEND 전술 피벗 + `❌` 갭 처방 (핵심 결론)

마스터의 `❌`(탐지 사각지대)는 **Detect로는 못 막고 Harden/Isolate(예방)로 가야 한다**는 게 D3FEND가 주는 결론이다.

| 마스터 `❌` 사각지대 | 근본 원인 | D3FEND 처방(전술) |
|---|---|---|
| 수동 도청·스니핑(T0842/T0887/T1040, Collection 다수) | 평문 MAVLink/RF 링크 | **Isolate**: `D3-ET` Encrypted Tunnels + **Harden**: `D3-MENCR` ★ |
| MAVLink 평문 인젝션·위조(A4, T1692/T1659/T0830) | 무서명 메시지 | **Harden**: `D3-MAN`(MAVLink2 서명) ★ |
| 암호 C2·터널·난독(T1573/T1572/T1001/T1132) | 콘텐츠 검사 불가 | **Isolate**: `D3-NI`·`D3-CF` + **Detect**: `D3-NTA`(메타데이터) |
| 데이터 삭제·은닉(T1070/T0809/T1485) | 삭제 행위 미기록 | **Restore**: `D3-RO` + WORM 로깅, **Harden** `D3-PH` |
| 루트킷·부트킷·펌웨어(T1014/T0851/T1495/T0800) | 호스트/부트 무결성 부재 | **Harden**: `D3-PH`·보안부팅·펌웨어 서명검증(PGSE) |
| GNSS 스푸핑·재밍(S1/JAM, T0835/T0814/T1695) | RF/CPS 영역 | **[custom]** 다중센서 융합·항재밍·링크 다중화 (D3FEND 미커버) |

### D3FEND 7전술 × UAV 핵심 대응
- **Model**: `D3-AI`(UAS 자산)·`D3-OAM`(운용 베이스라인)
- **Harden**: `D3-MAN`·`D3-MENCR`·`D3-ACH`·`D3-PH`·`D3-AA`/`D3-CH` ← **사각지대 대부분 해소**
- **Detect**: `D3-NTA`·`D3-PM`·`D3-PA`·`D3-UBA`·`D3-FA`
- **Isolate**: `D3-NI`·`D3-ET`·`D3-AMED`·`D3-APA`·`D3-CF`·`D3-EI`
- **Deceive**: `D3-DO`
- **Evict**: `D3-CE`·`D3-PE`·`D3-OE`
- **Restore**: `D3-RO`·`D3-RA`

---

## 3. 방법·한계 (재현성)
- **데이터 출처**: D3FEND **v1.4.0**(2026-03-31).
- **공식 매핑 보유**: 마스터 Enterprise 기법 **40개**. 나머지는 `[custom]` 처리.
- **ICS(T0xxx)**: D3FEND ATT&CK 매핑 대상 아님 → `[쌍]` 또는 `[custom]`.
- **D3FEND 구조적 공백**: RF/GNSS/재밍 등 사이버-물리 위협(S1·JAM)에 대한 D3FEND 대응기술 없음.
- `D3-MAN`·`D3-MENCR`·`D3-ACH`는 v1.4.0 실재 Harden 기술, `D3-ET`는 Isolate(Network Isolation 하위)로 공식 매핑 포함.
