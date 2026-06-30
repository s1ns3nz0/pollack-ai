# 마이터 어택 UAV 만들기

- **Status**: Done
- **담당자**: 김수지, 김동언
- **URL**: https://app.notion.com/p/388f5e835bb4802cab3fc4d44738d89d

---

1. 마이터 어택 매트릭스처럼 uav 버전을 enterprise, ics, uav 논문 이거 섞어서 만들기
[https://scholarsjunction.msstate.edu/cgi/viewcontent.cgi?article=7217&context=td](https://scholarsjunction.msstate.edu/cgi/viewcontent.cgi?article=7217&context=td)
1. 각 테크닉 별로 우리 자산에 적용 가능한지/가능 안 한지 생각해보기 > 다 필터링해보기
	- 참조: UAV ATT&CK 매핑표 (Enterprise + ICS)
2. 각 테크닉 + 자산 별로 어떻게 적용할 수 있을 지 정리 > sentinel 경고로 띄움
3. 다 묶으면 거기서 연결해서 나올 수 있는 시나리오를 묶기 (상관 관계)
	- 참조: 시나리오 - UAV ATT&CK 매핑

## 클로드 브레인스토밍 양진수 혼자
끝나고 바로 올리기

MITRE 프레임워크 선택부터 짚고 가야 해. 일반 Enterprise ATT&CK로는 UAV 시나리오가 어색해져. 최신 상황 확인할게.핵심을 잡았어. 탐지룰을 어떻게 시작할지 막막한 건 당연해. 순서가 거꾸로라서 그래. 시나리오부터 만들고 룰을 빼는 게 아니라, **ATT&CK 기법 하나 → 그게 어느 테이블에 어떤 흔적을 남기는지 → 그걸 잡는 룰** 순서로 가야 해.

---

## 먼저: 어떤 매트릭스를 쓸 거냐
UAS 전용 ATT&CK 매트릭스가 이미 존재해. DroneSec이 만든 UAS용 ATT&CK 프레임워크가 있고, 적대적 행위를 매핑·추적·계획하는 데 쓸 수 있어. 근데 이걸 그대로 쓰기보단 **Enterprise ATT&CK + UAS 기법을 섞는 게** 점수에 유리해. 이유는 너희 환경(pgse-stub REST API, mavlink-router, QGC)이 절반은 일반 IT 시스템이라서야.

실제 연구도 이 방향으로 가. STRIDE로만 위협 모델링하는 다른 연구들과 달리, 공격자 목표 도달 단계를 MITRE ATT&CK로 모델링하면 개선이 크고, Docker 기반 SITL 환경에서 공격 경로를 체계적으로 분석할 수 있어. 너희 레포가 딱 이 SITL 구조잖아.

---

## 탐지룰 만드는 실제 순서 (이게 막힌 부분)

### 1단계 — Kill Chain을 ATT&CK 전술로 깔기
UAV 공격을 14개 전술 다 안 쓰고, **현실적인 5~6개 전술만** 골라서 체인 짜:
```
Reconnaissance → Initial Access → Execution →
Defense Evasion → Impact
```

### 2단계 — 각 전술에 "너희 환경에서 실제로 가능한" 기법 매핑

| 전술 | ATT&CK 기법 | 너희 환경의 구체적 행위 | 어느 테이블에 찍히나 |
|---|---|---|---|
| Reconnaissance | T1595 Active Scanning | 5790/tcp 포트 스캔 | datalink-los 연결 로그 |
| Initial Access | T1190 Exploit Public-Facing App | pgse-stub `/armory/firmware` 무인증 접근 | pgse API 로그 |
| Execution | T0855 Unauthorized Command (ICS) | 비인가 sysid의 COMMAND_LONG | telemetry-tap NDJSON |
| Defense Evasion | T0856 Spoof Reporting Message | GPS_RAW_INT 위조로 EKF 속임 | telemetry / EKF_STATUS |
| Impact | T0831 Manipulation of Control | DO_SET_SERVO 페이로드 트리거 | telemetry COMMAND_LONG |

ICS 매트릭스 기법(T08xx)을 섞는 게 핵심이야. UAV는 사이버-피지컬 시스템이라 ICS 전술이 딱 맞고, 이게 단순 재밍 시나리오랑 차별화되는 창의성 포인트야.

### 3단계 — 기법별로 KQL 탐지룰 1개씩
여기서 막혔을 텐데, 룰은 **"정상이면 절대 안 나오는 조건"** 하나만 찾으면 돼. 예를 들어:

```kql
// T0855: 비인가 소스의 명령 주입
// 정상 GCS는 sysid=255(GCS) 또는 알려진 ID만 명령을 보냄
TelemetryTap_CL
| where msg_type == "COMMAND_LONG"
| where src_sysid !in (255, 1)   // 화이트리스트 외
| where command in (176, 183, 400)  // SET_MODE, SET_SERVO, ARM
| project TimeGenerated, src_sysid, command, target_system
```

```kql
// T0856: GPS 스푸핑 (EKF 잔차 급증)
TelemetryTap_CL
| where msg_type == "EKF_STATUS_REPORT"
| where pos_horiz_variance > 1.0   // 정상 비행 시 거의 0
| join kind=inner (
    TelemetryTap_CL
    | where msg_type == "GPS_RAW_INT"
    | where eph > 500   // 수평 정확도 급락
) on $left.TimeGenerated == $right.TimeGenerated
```

---

## 핵심 — 단일 룰이 아니라 "상관 룰"이 점수다
개별 탐지룰은 누구나 만들어. 창의성은 **전술 간 시간 상관관계**에서 나와. Sentinel의 분석 규칙으로 이걸 묶어:

```
[T1190] pgse-stub 무인증 펌웨어 접근  (T+0초)
   ↓ 5분 이내
[T0856] GPS 스푸핑으로 EKF 교란       (T+180초)
   ↓ 동시
[T0855] 비인가 COMMAND_LONG 주입      (T+185초)
   ↓ 10초 이내
[T0831] 서보/페이로드 제어 변조        (T+192초)
```

이 4개가 **15분 윈도우 안에 순서대로** 발생하면 "UAV 하이재킹 캠페인"으로 단일 인시던트 발생 — 이런 멀티스테이지 룰이 평가에서 먹혀.

---

## 지금 당장 할 것
방향을 하나로 좁혀줄게. 어디부터 시작할지 골라봐.

정확해. 그게 맞는 방법이고, 한 가지만 더 얹으면 완벽해.

네가 말한 흐름:
```
Recon 기법 나열 → 우리 시스템 매핑
Initial Access 기법 나열 → 우리 시스템 매핑
... (전술별 반복)
→ 매핑된 것들 중 연결되는 것끼리 잇기
→ Sentinel 시나리오
```

이대로 하면 돼. 근데 **함정이 하나** 있어. 전술별로 기법을 다 나열한 다음 잇다 보면, 매핑은 다 됐는데 **서로 연결이 안 되는 조합**이 나와. 예를 들어 Recon에서 "포트 스캔"을 골랐는데 Initial Access에서 "물리적 USB 접근"을 고르면, 이 둘은 같은 공격자의 연속 행위로 안 이어져. 따로 노는 룰 두 개가 될 뿐이야.

그래서 잇는 단계에서 **"연결고리"의 정체를 명확히** 해야 해. 두 기법이 이어지려면 셋 중 하나가 성립해야 함:

| 연결고리 종류 | 의미 | 예시 |
|---|---|---|
| **시간 인접성** | A 직후 B가 발생 | 포트스캔(T+0) → 익스플로잇(T+30초) |
| **공유 식별자** | 같은 src_ip / sysid / session | 같은 IP가 스캔도 하고 명령도 주입 |
| **인과 의존성** | A 성공이 B의 전제조건 | 펌웨어 변조 성공해야 → 페이로드 실행 가능 |

가장 강력한 시나리오는 **세 개가 다 걸리는** 체인이야. 같은 IP(공유 식별자)가, 짧은 시간 안에(시간 인접성), 앞 단계 성공을 발판으로(인과) 다음을 하는 것.

---

### 그래서 작업 시트는 이렇게
전술별 나열 표에 **"연결 키" 컬럼을 미리** 넣어둬. 그래야 나중에 잇기가 기계적으로 됨.

```
전술        | ATT&CK | 우리 시스템 행위        | 로그 테이블   | 연결키(이 기법이 남기는 식별자)
-----------|--------|----------------------|-------------|------------------------
Recon      | T1595  | 5790/tcp 스캔          | datalink-los | src_ip, timestamp
Initial    | T1190  | pgse 무인증 펌웨어 접근   | pgse_api    | src_ip ←여기서 위와 연결!
Execution  | T0855  | 비인가 COMMAND_LONG    | telemetry   | src_sysid, timestamp
Impact     | T0831  | DO_SET_SERVO          | telemetry   | src_sysid ←여기서 연결!
```

이렇게 짜면 "src_ip로 Recon→Initial 잇고, src_sysid로 Execution→Impact 잇고, 그 사이는 timestamp로 잇는다"가 한눈에 보여. 이게 그대로 Sentinel 상관 규칙의 `join` 조건이 돼.

---

### 한 가지 보강
전술 나열할 때 **ATT&CK 매트릭스를 그냥 위에서부터 다 적지 마.** 너희 환경에 흔적이 안 남는 기법은 매핑해봐야 탐지룰을 못 만들어. 역방향으로 가는 게 빨라:

> "우리가 가진 로그 테이블(telemetry, pgse_api, datalink, QGC) 각각에서 **비정상으로 찍힐 수 있는 필드값**이 뭐냐"
> → 그걸 먼저 뽑고
> → "이 비정상값을 만드는 ATT&CK 기법이 뭐냐" 역매핑

로그에 안 남는 기법은 애초에 후보에서 빠지니까, 매핑했는데 룰을 못 만드는 헛수고가 사라져.

---

정리하면 네 이해가 맞고, 두 가지만 추가하면 돼: **(1) 잇기 전에 연결키를 미리 표에 박아라, (2) 기법은 매트릭스가 아니라 네 로그에서 역으로 뽑아라.**

첫 번째 시나리오로 뭘 고를지 아직 안 정했으면 말해줘. 그거 정하면 위 표를 실제 기법·KQL까지 채워서 한 장으로 만들어줄게.

아니, 그 말이 아니야. 내가 헷갈리게 말했네. 명확히 정리할게.

## alert는 무조건 생성해

1층 룰은 **alert를 생성해.** 그건 끄면 안 돼. alert가 있어야 탐지가 되는 거니까.

내가 말한 건 **alert가 아니라 incident**야. 둘이 다른 거야.

| 용어 | 의미 |
|---|---|
| **Alert** | 룰이 조건 맞으면 뜨는 신호. 1층은 무조건 생성 |
| **Incident** | alert를 묶어서 분석가가 다루는 케이스 단위 |

Sentinel 분석 규칙 만들 때 보면 이 옵션이 있어:
```
[Incident settings]
☑ Create incidents from alerts triggered by this rule
```

내가 "끄는 걸 고려하라"고 한 건 **이 incident 생성 체크박스**였어. alert를 끄라는 게 아니라.

---

## 근데 이것도 사실 너무 앞서나간 조언이었어
평가용 프로젝트면 그냥 **1층도 incident까지 다 생성하게 둬.** 이유:
- 1층이 incident를 안 만들면, 공격이 1단계에서 끝났을 때 화면에 아무것도 안 떠. 탐지했다는 걸 보여줄 수가 없음.
- "단계별로도 잡힌다"를 시연하려면 1층 incident가 보여야 점수가 됨.

내가 incident 끄기를 언급한 건 실무에서 **alert 폭주(noise)**를 막으려는 최적화인데, 평가 환경에선 그 문제가 없으니까 신경 쓸 필요 없어.

---

## 그래서 결론
```
1층 룰들 → alert 생성 O, incident 생성 O
2층 룰   → alert 생성 O, incident 생성 O (캠페인으로)
```

전부 다 생성해. 대신 2층은 **alert grouping**을 설정해서, 같은 공격이면 1층 incident들이 2층 incident 아래로 묶이거나 연관(related)되게만 해주면 깔끔해져.

진짜 중요한 건 incident 켜고 끄고가 아니라, **1층 룰마다 엔티티 매핑(IP, sysid 등)을 제대로 박는 것**이야. 그래야 2층이든 grouping이든 "같은 공격자"로 엮을 수 있어. 거기에만 신경 쓰면 돼.

혼란 줘서 미안. 시나리오 정해지면 룰 채워줄게.
