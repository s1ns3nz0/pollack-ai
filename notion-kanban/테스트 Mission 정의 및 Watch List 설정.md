# 테스트 Mission 정의 및 Watch List 설정

- **Status**: To Do
- **담당자**: 양진수, 황준식
- **우선순위**: High
- **마감일**: 2026-06-28
- **URL**: https://app.notion.com/p/38cf5e835bb48193a5dcd239b938dc7a

---

KUS-FS MUAV(고정익 MALE) 편대 3대를 ADD 안흥 시험비행장(36.71, 126.13) 기반으로 운용하는 시나리오와, Sentinel watch list 에 박을 구체 데이터.

---

## A. 실 운용개념 Mission Plan (5종)
각 mission = QGC `.plan` 파일 한 개. `gcs-qgc` pod 의 `/home/qgc/missions/` 에 박힘.

### A-1. ISR Long Patrol (장기체공 정찰)
- **목적**: ROI 영공 4-8시간 patrol, EO/IR + 영상 다운링크
- **편대**: 3대 시계방향, 1km × 1km 박스, 시작 corner 다름
- **mission items**:
  1. NAV_TAKEOFF (alt 80m, pitch 15°)
  2. NAV_WAYPOINT × 4 (1.1km 박스, alt 80)
  3. DO_JUMP → seq 2 (무한 loop)
  4. NAV_LAND (안흥 활주로)
- **데이터 흐름**: UAVTelemetry 다량, UAVMissionEvent (waypoint_reached) 균등
- **예상 비행시간**: 4시간 (~14400 telemetry rows / vehicle)

### A-2. SAR Grid Search (수색구조 격자탐색)
- **목적**: 손실 표적 정보 받음 → 좌표 grid serpentine 패턴 + CAMERA_TRIGGER
- **편대**: 3대 격자 분할 (V1 = NW, V2 = NE, V3 = S)
- **mission items**:
  1. NAV_TAKEOFF
  2. 격자 lawnmower 패턴 (NAV_WAYPOINT × N)
  3. 각 waypoint 사이 DO_DIGICAM_CONTROL (CAMERA_TRIGGER)
  4. NAV_LAND
- **데이터 흐름**: UAVImagery 발화 (CAMERA_TRIGGER/CAMERA_IMAGE_CAPTURED), UAVTelemetry 위치 grid

### A-3. C4I Hand-off (정보융합 임무)
- **목적**: 표적 식별 → ATCIS/MIMS 으로 hand-off
- **편대**: V1 = 정찰 (patrol), V2 = relay (LOS↔SATCOM 중계), V3 = standby
- **mission items** (V1):
  1. NAV_TAKEOFF + patrol
  2. ROI 진입 시 (mavlink ROI_LOCATION) → c4i-stub `/atcis/orders` POST (Operator 가 외부 트리거)
  3. NAV_LAND
- **데이터 흐름**: UAVC4I (OrderId), UAVOperator (set_roi_location ActionName)

### A-4. SATCOM Relay (BLOS 시나리오)
- **목적**: LOS 끊긴 상태 (편대 V1 가 시야 밖) → SATCOM 으로 유지
- **편대**: V1 = 원거리 patrol (LOS 끊김 시뮬), V2/V3 = LOS 정상
- **mission items** (V1):
  1. NAV_TAKEOFF
  2. NAV_WAYPOINT (50km 떨어진 지점, datalink-los netem loss 100% 시뮬)
  3. SATCOM (datalink-satcom) 만 라이브 유지
  4. NAV_LAND
- **데이터 흐름**: UAVSatcomLink (LinkId, RttMs 변동), UAVTelemetry 빈도 감소

### A-5. Formation Flying (편대 비행 데모)
- **목적**: 3대 동시 활주로 → 패트롤 → 동시 LAND (현재 구현)
- **편대**: V1/V2/V3 시작 corner 다름, 동시 시계방향 patrol
- **mission items**: 각 vehicle `/home/qgc/missions/v{1,2,3}.plan`
- **데이터 흐름**: UAVTelemetry 3 UAVId (SYS001/002/003) 균등, UAVMissionEvent waypoint_reached 시간차

---

## 테스트 Mission 정의 + Watch List (방어 AI 시뮬레이션 스캐폴드)

목적: 방어 AI(SOC) 테스트용 가상 임무 프로파일과 감시 대상(watchlist)을 정의한다. ※ 실제 작전계획이 아니라 SOC 시뮬레이션·시나리오 검증용 스캐폴드이며, 접경/거부지역(denied-area)을 일반화한 것.

### 1) Mission Plan — 테스트 임무 정의

| 임무유형 | 목적 | 비행 프로파일(고도·속도·체공) | 대표 자산 |
|---|---|---|---|
| ISR 주공(정찰) | 핵심 표적·징후 식별 | 중고도 · 순항 ~100–150km/h · 장체공 | 정찰 UAV(MALE) |
| ISR 조공·기만(decoy) | 적 방공 반응 유도·양동 | 저~중고도 · 가변속 | 소형 다수 |
| 통신중계 | 데이터링크 확장·NCW | 고고도 체공 | 중계 UAV |
| 전자전(EW) | 재밍·기만으로 적 센서 교란 | 중고도 | EW 페이로드 기체 |
| 타격(무장) | 표적 무력화 | loitering 체공 후 종말 강하·고속 | loitering munition/FPV |

### 2) 시나리오별 UAV 운용방식 (목적별 · 주공/조공) — 교리 수준
- 목적별 분리 편조: ISR(탐지) / 기만(decoy로 방공 반응 유도) / 전자전(재밍·기만) / 타격(무장) — 한 패키지에 섞지 않고 목적별로 날린다.
- 주공-조공 협조: 주공(핵심 표적 ISR·타격)에 자원 집중, 조공(기만·양동)으로 적 주의·방공을 분산 → 주공 생존성↑. NCW로 '조공이 탐지 → 주공이 타격'(센서-슈터 분리).
- 무장 운용 원칙: 무장 UAV는 ROE·교전권한·HITL 게이트 하에서만. 종말단계 자율(통신두절 내성) + 인가 표적 화이트리스트.
- 군집/스웜: 다수 저가기로 포화 → 적 방공에 비용 비대칭 강요.

### 3) Watch List 데이터 정의 (임무별 감시 텔레메트리) ★ 핵심 산출물
임무가 정해지면 '정상 범위'가 정해지고, 거기서 벗어나면 경보가 뜬다 — 이게 SOC watchlist.

| 감시 항목(telemetry) | 정상 기준(예시) | 이상 시 의심 시나리오 |
|---|---|---|
| GNSS-INS 잔차 · HDOP · C/N0 | 잔차 낮음·위성수 안정 | S1 GPS 스푸핑 (도심 협곡 경미저하는 오탐) |
| C2 RSSI · 명령 시퀀스 · 미발신 명령 | 연속·인가 소스 | S2 C2 하이재킹 (기상 RSSI 저하는 오탐) |
| SATCOM MAC 검증 실패율 · 체크섬 | 낮음 | S3 SATCOM MITM (예정 점검은 오탐) |
| 펌웨어 해시·서명 · SBOM | 일치 | S4 공급망 변조 (서명일치 업데이트는 오탐) |
| 정책기대등급 vs 에이전트 판정 괴리 | 일치 | S5 RAG 포이즈닝 |
| GCS 로그인 시간·위치 · 다수기체 재지정 | 인가·정상시간 | S6 GCS 침해 (인가 재지정은 오탐) |
| 센서간 표적 불일치 · 탐지 신뢰도 분포 | 일관 | S8 온보드 AI 적대공격 |
| 경보 레이트 · 다축 상관 | 평시 수준 | S9 군집 포화 |
| 다수단말 동시 접속실패 · 관리채널 변경 | 정상 | S10 SATCOM 무력화 |
| 비인가 앱 · 임무파일 접근 · 토큰 재사용 | 정상 | S11 모바일 GCS |

### 4) 속도·제원 참고 (공개 · 시뮬레이션 기본값)
소형 정찰 ~100–150km/h · 중고도 장체공(MALE) ~130–250km/h·체공 20h+ · loitering munition 순항 ~100–185km/h(종말 강하 시 더 빠름) · FPV ~100–150km/h.

### 남은 일 / 협업
- 실제 임무 파라미터·작전구역·표적·주최측 데이터로 확정(추가 예정)
- watchlist를 Sentinel Analytic Rule + 시나리오 YAML의 telemetry 필드와 동기화 (김수지).

---

## 테스트 작전 시나리오 — 영변 일대 ISR 임무 (시뮬레이션/훈련용 스캐폴드)

이것은 방어 AI(SOC) 테스트·시나리오 검증용 가상 작전 시나리오임. 실제 작전명령(OPORD)이 아니며 실제 좌표·적 방공 제원·이동 회랑·타격계획은 포함하지 않는다(전부 notional/TBD). 목적은 아군 UAV 임무 프로파일을 정의해 watchlist(감시 텔레메트리)와 자율 결심 로직을 도출하는 것.

### 1. 상황 / 목표 (Situation / Objective)
- 목표물(가정): 영변 핵시설 일대의 핵심 표적(원자력 관련 시설)을 정보수집 목표로 가정 → 해당 일대를 작전지역(AO)으로 구성.
- 임무: 아군 집결지점(notional)에서 목표지점까지 정보자산(UAV 3기)이 동시 ISR 수행.
- 지휘관 의도: 핵심표적 정보 획득과 동시에 아군 자산 생존성 최우선 — 정보는 못 얻어도 자산은 돌아온다.

### 2. 기동 개념 (Scheme of Maneuver)
- 3개 독립 회랑(corridor)을 구성하고 UAV 3기를 동시 비행 — 분산으로 단일 피격 시 전체 손실을 막고 다축 커버리지 확보.
- SEAD(방공 무력화)를 기반(enabler)으로 전제: 회랑 진입 전 적 방공 위협이 억제되어 있다고 가정.
- 생존성 보장: 위협축 회피 라우팅 + 저피탐 고도·기동, 회랑별 진입/이탈 시점 분산.

### 3. 위협 대응 / 결심 사다리 (Decision Ladder) ★ watchlist·자율판단의 핵심
- 회랑 간 피격 위협 탐지 시: ① 위협 회피 우회 → ② 우회 불가 시 RTB(집결지/안전지대 복귀).
- 피격 위험이 지속될 경우: ③ 대체 자산(타 UAV/센서)으로 정보 수집 전환 → ④ 그래도 불가 시 상급부대에 RFI(정보요청)로 획득.
- **결심 순서(자율 후보 → HITL 확인):** 위협 탐지 → 회피 → RTB → 대체자산 → RFI. 이 사다리가 곧 Response 플레이북/HITL 게이트의 분기 로직이 된다.

### 4. 정보자산 3기 편조 (예시)
- UAV-1 (주공 ISR): 핵심표적 직접 정찰 — 자원·보호 우선 집중.
- UAV-2 (조공/기만 + 측방): 양동으로 방공 반응 유도·분산, 측방 커버리지로 주공 생존성↑.
- UAV-3 (예비/중계): 주공 RTB 시 대체 수집, 데이터링크 중계(NCW)로 회랑 간 표적 핸드오프.

### 5. 방어 AI 연계 (이 임무 → watchlist 도출)
- 각 UAV의 정상 비행/통신 프로파일(회랑·고도·속도·C2 RSSI·GNSS)을 baseline으로 설정 → 이탈 시 경보(위 Watch List 표와 연결). 예: 회랑 이탈/예기치 않은 RTB, C2 두절=S2, GNSS 이상=S1, 3기 동시 이상=S9.
- 결심 사다리(회피→RTB→대체→RFI)를 Response 플레이북 분기 + 등급별 HITL로 매핑 → '아군 UAV가 공격받는 중'을 SOC가 탐지·대응하는 흐름으로 시뮬레이션.

---

## 시나리오에 따른 UAV 운용방식 (목적별 도출)

| 목적 | 시나리오 유형 | 핵심 운용 | 방어 AI 연계(watch / 대응) |
|---|---|---|---|
| 정찰(ISR) | M1 핵심표적 정찰(주공) | 회랑 ISR · 저피탐 | 회랑 이탈·센서 신뢰도 이상 감시 |
| 기만(Decoy) | M2 양동·방공 반응 유도(조공) | 다수 저가기 미끼 | 유도된 방공 반응 신호 수집 |
| 전자전(EW) | M3 재밍·기만 지원 | 적 레이더/통신 교란 | 아군 EW 오작동·피아 구분 |
| SEAD 지원 | M4 방공 위협 탐지·표적화 지원 | 위협 방향탐지(DF)·핸드오프 | 위협축 데이터·센서-슈터 연계 |
| 통신중계 | M5 데이터링크 연장 | 고고도 중계 | 링크 품질·중계 부하 감시 |
| 피해평가(BDA) | M6 타격 후 효과 확인 | 재진입 ISR | 재진입 생존성·잔존 위협 |
| 타격(무장) | M7 무장 UAV 표적 무력화 | loitering · ROE/HITL | 표적 화이트리스트·HITL 게이트 |
| 생환/복귀 | M8 위협 시 RTB·대체수집·RFI | 결심 사다리 실행 | 자율 RTB 트리거·대체자산 전환 |

정리: 임무(M1~M8)는 '정상 운용 프로파일'을 정의해 watchlist의 기준선을 만들고, S1~S11 공격 시나리오는 그 기준선에서의 '이탈(이상)'을 정의한다.

---

## 통합 매핑 — 팀원 임무(A) ↔ 목적(M) ↔ 공격(S) ↔ 데이터 ↔ Watch

| 팀원 임무(A) | 목적(M) | 주입 가능 공격(S) | 핵심 데이터 테이블 | Watch 항목 |
|---|---|---|---|---|
| A-1 ISR Long Patrol | M1 정찰 | S1 GPS 스푸핑 · S2 C2 하이재킹 | UAVTelemetry | GNSS 잔차 · C2 RSSI |
| A-2 SAR Grid Search | M1 정찰 / M6 BDA | S8 온보드AI 적대공격 · S1 | UAVImagery · UAVTelemetry | 센서 신뢰도 · 표적 불일치 |
| A-3 C4I Hand-off | M4 SEAD지원 / M5 중계 | S6 GCS 침해 · S11 모바일GCS · S5 RAG | UAVC4I · UAVOperator | 인가 명령 · 재지정 · 정책괴리 |
| A-4 SATCOM Relay (BLOS) | M5 중계 / M8 생환 | S10 SATCOM 무력화 · S3 MITM | UAVSatcomLink (RttMs) | MAC fail · 다수단말 동시실패 |
| A-5 Formation Flying | M1 정찰 + 편대 | S9 군집 포화(다축) | UAVTelemetry(3 UAVId) · UAVMissionEvent | 경보 레이트 · 다축 상관 |

읽는 법: A-x를 정상으로 돌려 baseline을 만들고 → 같은 임무에 짝지은 S공격을 주입(-ATK 변형)하면 해당 Watch 항목이 이탈 → SOC가 탐지·판정·대응.
