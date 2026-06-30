# UAV 시뮬레이션 체급 확장 설계서: MPD(Group 1) → KUS-FS급(MALE, 지작사급)

> **상태**: Draft v0.1
> **대상 리포**: `uav-sim-env`(시뮬), `dah-sentinel-content`(탐지), `pollack-ai`(SOC 에이전트)
> **워크스페이스**: `dah-data-law` (RG `dah-data-rg`, koreacentral)
> **목적**: 현재 분대급 MPD 시뮬 환경을 전구(지작사)급 중고도 장기체공(MALE) 정찰체계로 확장하기 위한 아키텍처·컴포넌트·수집·탐지·단계별 계획의 단일 청사진.

---

## 0. 한 줄 요약

분대급 **MPD(Group 1, quadplane VTOL, LOS only)** 시뮬을 전구급 **KUS-FS급(MALE, 고정익, SATCOM/BLOS, SAR, 2~4대 편대)**로 확장한다. 핵심 변화는 **SATCOM/BLOS 링크 신설**이며, 이로써 그동안 비활성이던 **S3(SATCOM MITM) 위협면이 실재화**된다.

---

## 1. 배경 — 왜 지작사급인가

| 제대 | 대표 기체 | 체급 | 종심/반경 | 통신 | 운용 주체 |
| --- | --- | --- | --- | --- | --- |
| 분대/소대 | **MPD (현재)** | Group 1 | 수 km~수십 km | LOS only | 육군 |
| 군단 | 송골매 RQ-101 | Group 3 | ~50km / 110km(중계 200) | LOS + 중계 | 육군 |
| **전구(지작사)** | **KUS-FS (MUAV)** | **Group 4~5 MALE** | **100~300km** | **BLOS/SATCOM** | 공군(운용) → 지작사(소비) |
| 전략/국가 | 글로벌호크 RQ-4 | Group 5 HALE | 수천 km | SATCOM | 공군 |

**종심이 기체를 결정한다.** 지작사급 작전종심(100~300km)은 LOS 가시선 범위를 넘기 때문에 **위성 중계(SATCOM)가 필수**가 되고, 이 지점에서 위협면이 질적으로 달라진다.

> ⚠️ **조직 경계 주의**: KUS-FS·글로벌호크 같은 전구·전략 정찰자산은 실제로는 **공군(정찰비행단)이 운용**하고 지작사는 그 정보(영상/표적)를 받는 구조다. 따라서 SOC 설계 시 "보호 경계"가 군단급보다 복잡해진다 — **자산은 공군 망, 정보 소비는 육군**이라는 조직 간 데이터 핸드오프 지점 자체가 새로운 공격면이다.

---

## 2. 현재 상태 (As-Is) — MPD Group 1

`uav-sim-env` README / docker-compose 기준 현행 구성.

```
                      ┌──────────────────────────┐
                      │   gcs-qgc (10.50.0.30)   │
                      │   QGroundControl / noVNC │
                      └──────────▲───────────────┘
                                 │ MAVLink UDP :14551
┌──────────────────┐  MAVLink   ┌──────────────────────────┐
│ av-mpd           │  UDP:14550 │ datalink-los (10.50.0.20)│
│ 10.50.0.10       │ ─────────▶ │ mavlink-router           │
│ ArduPilot SITL   │            │ tc netem (delay/loss)    │
│ Quadplane (MPD)  │ ◀───────── │ :5790 평문 MAVLink(A4)    │
└──────────────────┘            └──────────────────────────┘
                                          │ :14552
                                          ▼
                                 telemetry-tap → NDJSON
                                          │
                          /var/log/uav-sim-env/*.ndjson
                                          │ AMA → DCE → DCR
                                          ▼
                                  UAVTelemetry_CL (dah-data-law)
```

**현행 특성**
- 기체: `ArduPlane` / `-f quadplane` (VTOL), persona `mpd_quadplane.parm`
- 통신: **LOS only** (UDP/MAVLink), BLOS 없음
- 페이로드: EO/IR + 자폭탄(서보채널 9/10) — 정찰·타격 겸용 소형
- 단일기 운용
- 활성 위협면: **S1**(GNSS 스푸핑), **S4**(펌웨어/공급망), **A4**(MAVLink 인젝션), IT/JAM/OP
- 비활성: **S3(SATCOM MITM)** — LOS only라 칠 대상이 없음

---

## 3. 목표 상태 (To-Be) — KUS-FS급 MALE

**사이징 기준 (KUS-FS 제원)**
- 형상: 대형 고정익 (길이 13m, 폭 25m), 1200마력 터보프롭
- 고도/체공: 최대 45,000ft(~13.7km), **24시간**
- 능력: 6~14km 상공에서 **100~300km 밖** 표적 고해상도 촬영
- 페이로드: EO/IR + **SAR**(합성개구레이더) + GMTI
- 구성: 비행체 **2~4대 + 지상통제(GCS) + 지상지원**
- 통신: **LOS(C밴드) + BLOS(SATCOM)** 이중 링크

```
                         ┌─────────────────────────────┐
                         │ gcs-muav (지상통제 GCS)        │
                         │ QGC / 임무계획 / 영상·SAR 분석  │
                         └──────────▲───────────▲────────┘
              LOS C-band            │           │   BLOS (위성 중계)
              (근거리)               │           │   (종심 100~300km)
┌──────────────────┐                │     ┌─────┴───────────────────┐
│ av-muav-1..N     │  MAVLink       │     │ datalink-satcom (신규)    │
│ ArduPilot SITL   │ ───────────────┘     │ SATCOM 게이트웨이 모사     │
│ -f plane (MALE)  │ ───────────────────▶ │ 무결성/세션/지연 주입      │
│ + SAR stub       │                      └─────────┬───────────────┘
│ (2~4대 편대)      │                                │
└──────────────────┘            datalink-los (LOS) ─┤
                                                     ▼
                                          telemetry-tap (확장)
                                                     │
                          /var/log/uav-sim-env/*.ndjson (신규 스트림 포함)
                                                     │ AMA → DCE → DCR
                                                     ▼
              UAVTelemetry_CL + UAVSatcomLink_CL + UAVSarPayload_CL (신규)
```

---

## 4. As-Is → To-Be 변경 매트릭스

| 항목 | As-Is (MPD) | To-Be (KUS-FS급) | 변경 강도 |
| --- | --- | --- | --- |
| 기체 frame | `-f quadplane` (VTOL) | `-f plane` (고정익, 고고도·장기체공 튜닝) | 중 |
| persona | `mpd_quadplane.parm` | `muav_male.parm` (신규) | 중 |
| 이착륙 | 수직이착륙 | 활주로/카타펄트 (TKOFF 모드) | 중 |
| **통신** | LOS only | **LOS + SATCOM/BLOS 이중 링크** | **상 (신규 컴포넌트)** |
| 페이로드 | EO/IR + 자폭 | **EO/IR + SAR**(정찰 중심, 무장은 옵션) | 중 |
| 운용 대수 | 단일기 | **2~4대 편대** | 상 |
| 임무 종심 | 수십 km | **100~300km** | 중 |
| 수집 테이블 | `UAVTelemetry_CL` 등 기존 | **+ `UAVSatcomLink_CL`, `UAVSarPayload_CL`** | 상 |
| DCR | 기존 stream | **+ SATCOM/SAR stream·dataflow** | 중 |
| 활성 위협면 | S1/S4/A4/IT/JAM/OP | **+ S3(SATCOM MITM)**, + 편대 lateral | 상 |

---

## 5. 신규/변경 컴포넌트 상세

### 5.1 기체 — MALE 고정익 persona (`av-muav`)

- **베이스**: 기존 `av-mpd`와 동일하게 ArduPilot SITL(`ArduPlane`, `Plane-4.5`) 재사용.
- **변경점**: `FRAME=plane`(quadplane 제거), 신규 persona `muav_male.parm`.
  - 순항속도·실속속도·날개폭 등 공력 파라미터를 MALE급으로 튜닝
  - 고고도(45,000ft) 비행을 위한 고도/기압 관련 파라미터
  - 장기체공(24h)을 가정한 배터리/연료 모델(`SIM_*`)
  - 이착륙: VTOL 제거, **TKOFF 모드**(활주로/카타펄트) 기반
- **컨테이너 전략**: `av-mpd`는 보존(군단급 비교용), **`av-muav`를 신규 추가**해 두 체급을 동시 비교 가능하게 유지 권장.

### 5.2 통신 — SATCOM/BLOS stub (`datalink-satcom`) ★ 핵심 신규

지작사급의 정의적 변화. LOS(`datalink-los`)는 유지하고 **BLOS 경로를 신설**한다.

- **모사 대상**: 위성 중계 게이트웨이 (지상국 ↔ 위성 ↔ UAV).
- **구현**: FastAPI/프록시 + `tc netem`으로 **위성 링크 특성** 주입.
  - 큰 전파지연(수백 ms RTT), 지터, 간헐적 단절
  - **세션/핸드셰이크** 개념(위성 빔 전환, 키 협상)
  - 무결성 메타데이터(시퀀스·서명·세션ID)
- **공격면 (S3)**: 무결성 위반(시퀀스 점프/서명 불일치), 세션 하이재킹, 중간자(MITM) 주입, 의도적 지연/재밍.
- **로그 출력**: NDJSON → `UAVSatcomLink_CL` (link_id, session_id, seq, integrity_status, rtt_ms, jam_indicator, src/dst ...).

### 5.3 페이로드 — SAR stub (`sar-stub`)

- **모사 대상**: 합성개구레이더 영상 수집/전송 (구름·야간 투시).
- **구현**: 주기적 "SAR 프레임 메타" 이벤트 생성(좌표, 해상도, 프레임ID, 용량). 실제 영상 바이너리는 불필요 — **메타데이터만**.
- **로그 출력**: NDJSON → `UAVSarPayload_CL` (frame_id, target_lat/lon, resolution, size_bytes, sensor_mode ...).
- **보안 의의**: 영상 유출·변조·수집표적 조작(어디를 찍었나) 추적.

### 5.4 편대 운용 (2~4대)

- **구현**: `av-muav`를 docker-compose `--scale` 또는 인스턴스별 서비스(`av-muav-1..N`)로 다중화. ArduPilot SITL `-I {INSTANCE}` 활용(포트 오프셋 자동 분리).
- **식별**: 각 기체에 `uav_id`(예: `MUAV-001..004`) 부여 → 모든 로그에 일관 태깅.
- **보안 의의**: 한 대 침해 → 편대 전체 **횡적 확산(lateral movement)** 개념 도입. 편대 단위 이상행위(동시 항로 이탈, 동일 명령 일괄 수신) 탐지 가능.

---

## 6. 데이터 수집 파이프 변경

### 6.1 신규 테이블 (`tables.bicep` 확장)

| 테이블 | 소스 stub | 핵심 컬럼(초안) |
| --- | --- | --- |
| `UAVSatcomLink_CL` | datalink-satcom | link_id, session_id, seq, integrity_status, rtt_ms, jam_indicator |
| `UAVSarPayload_CL` | sar-stub | frame_id, target_lat, target_lon, resolution, size_bytes, sensor_mode |

기존 `UAVTelemetry_CL`(EKF/MAVLink)은 그대로 재사용.

### 6.2 DCR 확장 (`dcr.bicep`)

- `streamDeclarations`: 신규 2종 스트림(satcom, sar)의 JSON 스키마 선언
- `dataSources`: telemetry-tap이 새로 떨구는 NDJSON 파일 경로 추가 (예: `/var/log/uav-sim-env/satcom.ndjson`, `sar.ndjson`)
- `dataFlows`: 각 stream → 각 신규 테이블 매핑
- `transformKql`: 1차 passthrough, 추후 마스킹/필터 고도화

> ⚠️ **흔한 함정**: `streamDeclarations` 필드명/타입이 실제 NDJSON과 불일치하면 데이터가 조용히 drop된다. SAR/SATCOM 스키마는 stub 구현과 **동시에** 확정할 것.

---

## 7. 위협면 변화 & Detection-as-Code

### 7.1 새로 열리는 / 강화되는 위협면

| 코드 | 위협 | As-Is | To-Be | 비고 |
| --- | --- | --- | --- | --- |
| **S3** | SATCOM MITM·무결성 위반 | ❌ 비활성 | ✅ **신규 핵심** | datalink-satcom 필요 |
| S1 | GNSS 스푸핑 | ✅ | ✅ **중요도↑** | 적 종심 깊어 LOS 시각백업 없음 |
| A4 | MAVLink 인젝션 | ✅ | ✅ | LOS·BLOS 양쪽 적용 |
| (신규) | SAR 표적 조작·영상 유출 | — | ✅ | UAVSarPayload_CL |
| (신규) | 편대 횡적 확산 | — | ✅ | 다대 운용 |
| OP/JAM/IT/S4 | 인증·재밍·2인통제·공급망 | ✅ | ✅ 유지 | — |

### 7.2 탐지 룰 추가 (`dah-sentinel-content/AnalyticsRules/`)

레포 컨벤션(`<scenario>-<short>.yaml`, 룰ID `dah-<scenario>-<n>`, MITRE 매핑) 준수.

- `S3-satcom-integrity-fail.yaml` — `UAVSatcomLink_CL`의 integrity_status 위반/seq 점프 탐지
- `S3-satcom-session-hijack.yaml` — 동일 link_id에 session_id 급변/중복
- `SAR-target-tamper.yaml` — 임무 외 좌표 SAR 수집 / 비정상 프레임 폭증
- `FLEET-lateral-anomaly.yaml` — 편대 다수기 동시 항로 이탈/동일 명령 수신
- 기존 S1/A4 룰은 그대로 유지(형상 무관 재사용)

---

## 8. 단계별 마이그레이션 계획 (의존성 순서)

> 원칙: **수신 그릇(테이블/DCR) → 송신 컴포넌트(stub) → 데이터 검증 → 탐지 룰** 순. (테이블 없으면 데이터가 drop되므로 항상 그릇 먼저.)

**Phase A — 기체 전환 (저위험, 독립적)**
1. `muav_male.parm` 작성, `av-muav` 컨테이너 추가(`-f plane`)
2. 종심 100~300km 정찰 미션(`muav_recon.plan`) 작성
3. 기존 telemetry-tap로 `UAVTelemetry_CL` 정상 수집 확인 (S1/A4 회귀 테스트)

**Phase B — SATCOM 링크 신설 (핵심)**
4. `tables.bicep`에 `UAVSatcomLink_CL` 추가 → 배포
5. `dcr.bicep`에 satcom stream/dataSource/dataFlow 추가 → 배포
6. `datalink-satcom` stub 구현 + telemetry-tap에 satcom NDJSON 출력 연결
7. `/var/log/uav-sim-env/satcom.ndjson` 생성 및 `UAVSatcomLink_CL` 적재 확인

**Phase C — SAR 페이로드**
8. `UAVSarPayload_CL` 테이블 + DCR stream 추가
9. `sar-stub` 구현 + NDJSON 출력 → 적재 확인

**Phase D — 편대화**
10. `av-muav` 2~4대 스케일아웃, `uav_id` 태깅 일관성 확인

**Phase E — 탐지 (Detection-as-Code)**
11. S3/SAR/FLEET 룰 YAML 작성 → PR → main 머지 → Sentinel 자동 배포
12. 공격 시나리오 주입(레드팀)으로 정탐/오탐 검증

```
A(기체) ──────────────┐
                      ├─▶ D(편대) ─▶ E(탐지)
B(SATCOM) ─▶ C(SAR) ──┘            ▲
        └──────────────────────────┘  (S3 룰은 B 완료 후 테스트 가능)
```

---

## 9. 리포지토리별 변경 목록

### `uav-sim-env`
- `av-muav/` 신규 (Dockerfile, entrypoint, `persona/muav_male.parm`, `missions/muav_recon.plan`)
- `datalink-satcom/` 신규 (FastAPI + tc netem)
- `sar-stub/` 신규
- `telemetry-tap/tap.py` 확장 (satcom/sar NDJSON 출력)
- `docker-compose.yml` 서비스 추가 + `--scale` 구성
- `infra/` Bicep: `tables.bicep`, `dcr.bicep` 확장
- `docs/sentinel-schemas.md` 신규 테이블 스키마 추가
- README Phase 로드맵 갱신 (Phase 2 → 진행)

### `dah-sentinel-content`
- `AnalyticsRules/S3-*.yaml`, `SAR-*.yaml`, `FLEET-*.yaml` 추가
- `HuntingQueries/` SATCOM/SAR 탐색 쿼리(선택)
- `Watchlists/` 편대 `uav_id` 목록(선택)
- 시나리오↔룰 매트릭스 갱신

### `pollack-ai`
- 신규 인시던트 타입(S3, SAR, FLEET)을 받는 에이전트 흐름 검증(황준식 담당 영역)

---

## 10. 리스크 / 미해결 질문

- **조직 경계**: KUS-FS는 공군 운용 자산. SOC 보호 범위를 "공군 망 + 육군 소비 핸드오프"까지 볼 것인가, 아니면 시뮬 단순화를 위해 단일 망으로 추상화할 것인가? → **결정 필요**
- **SATCOM 무결성 모델 수준**: 실제 위성 프로토콜을 어디까지 흉내낼지(시퀀스·서명만 vs 키 협상까지). MVP는 시퀀스/세션ID/서명상태 수준 권장.
- **무장 겸용**: KUS-FS는 향후 무장 가능. 정찰 전용으로 둘지, `weapon-stub` 연계까지 확장할지.
- **비용**: 편대(2~4대) + SITL 다중 인스턴스는 VM 리소스 부담↑. 현 `Standard_D4s_v5`로 충분한지 확인 필요(스케일아웃 시 상향 고려).
- **S3 레드팀 도구**: SATCOM MITM 주입을 무엇으로 할지(커스텀 스크립트 vs 기존 mavlink 도구 확장).

---

## 11. 참조

- `uav-sim-env` README / `docs/sentinel-schemas.md`
- `dah-sentinel-content` README (브랜치/커밋/룰 컨벤션)
- KUS-FS 제원: 위키백과 / 나무위키 / 대한항공 MUAV 브로슈어
- ArduPilot SITL: <https://ardupilot.org/dev/docs/sitl-simulator-software-in-the-loop.html>
- MAVLink common: <https://mavlink.io/en/messages/common.html>
- Microsoft Sentinel Repositories: <https://learn.microsoft.com/azure/sentinel/ci-cd>
