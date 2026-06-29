# Airspace & GNSS Context — Investigation 외부 컨텍스트 보강 (#1)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-06-30 |
| 상태 | Approved (브레인스토밍 완료, 구현 계획 작성 단계) |
| 작성자 | s1ns3nz0 |
| 관련 ADR | docs/adr/0002-autonomous-self-improving-blue-soc.md |
| 후속 | #2 MISP/OTX TI 확장 (별도 spec), #3 Shodan/Censys 공격면 (별도 spec) |

## 1. 배경 & 동기

현재 `InvestigationAgent` 의 외부 보강 입력 = `ContextRetriever`(RAG) · `ThreatIntelTool` · `SandboxDetonator` · `VulnContext` · `MemoryReadGate`(exp). 모두 사이버 도메인 한정. UAV 보호 관점에서 다음 공백이 있다:

- **GNSS 위협 외부 상관 부재** — S1(GPS 스푸핑/재밍) 시나리오는 EKF 잔차 + GPS 글리치 플래그 *내부* 신호만 본다. 같은 시각·지역에 외부 jamming 활동이 활성인지 *외부 출처* 로 확인하지 못한다.
- **공역 인식 부재** — 임무 영역 내 적대/비등록 비행체 진입 여부를 SOC 가 모른다. 멀티-UAV / swarm 위협 컨텍스트 부재.

이 spec은 두 외부 출처를 `InvestigationAgent` 에 결합한다:

- **GPSJam.org** — 글로벌 GPS jamming/spoofing 활성 셀 지도 (커뮤니티 데이터, 무료 REST).
- **OpenSky Network API** — 실시간 ADS-B 항적 (상용 + 일부 군용, 무료 REST, 인증 시 한도 증가).

## 2. 목표 / 비목표

### 2.1 목표
- 두 외부 출처를 `Investigation` 단계에서 *결정론 보강* 신호로 통합.
- S1 시나리오의 `confidence` 가 외부 jamming 활성 시 보강되도록 한다.
- 적대/비등록 비행체 근접 시 `confidence` 가 보강되도록 한다.
- `signal_judge` 의 `corroborated` 판정에 외부 신호가 기여한다.
- 두 출처 모두 graceful degrade (장애·키 없음·좌표 없음) — 핫패스 SLO 보존.
- 기존 TI/Sandbox/Vuln 와 동일한 Protocol 어댑터 패턴 유지.

### 2.2 비목표
- `SeverityEngine` 수정 (외부 신호로 등급을 바꾸지 않는다 — LLM/외부 판정권 박탈 원칙 유지).
- 실시간 스트림 / 백그라운드 폴러 (per-alert lazy + TTL 캐시로 충분).
- Redis / 외부 캐시 (in-memory MVP).
- HITL UI 변경.
- RF SDR / DroneShield / NOAA Space Weather (별도 사이클).

## 3. 결정 요약 (브레인스토밍 결과)

| # | 결정 | 근거 |
|---|---|---|
| D1 | `GnssJamTool` + `AirspaceTool` 두 Protocol 분리 | 단일 책임. 한쪽 장애가 다른 쪽 보강을 막지 않음. 테스트 격리 |
| D2 | Per-alert lazy 호출 + TTL in-memory 캐시 (GnssJam 5분, Airspace 30초) | TI/Sandbox 패턴 일관성. 핫패스 지연 수초~1초 추가 |
| D3 | `Alert.lat`/`Alert.lon` 추가 + `asset-tiers.yaml.coords` fallback | 합성/실 양쪽 동작. 자산 경계 고정도 가능 |
| D4 | severity 불변 — `InvestigationResult` 보강만 | LLM 판정권 박탈 원칙 동일 적용 |
| D5 | 외부 출처별 `Finding` 모델 명시 (Any 금지) | 기존 `ThreatIntelFinding` 패턴 일관성 |

## 4. Architecture

```text
Alert (lat/lon | asset_id→coords)
   │
   ▼
InvestigationAgent ── 병렬 호출 ─┬── ContextRetriever     (기존)
                                  ├── ThreatIntelTool     (기존)
                                  ├── SandboxDetonator    (기존)
                                  ├── VulnContext         (기존)
                                  ├── MemoryReadGate      (기존)
                                  ├── GnssJamTool         ★ 신규
                                  └── AirspaceTool        ★ 신규
   │
   ▼
InvestigationResult(+ gnss_jam_findings, airspace_findings, confidence 보강)
   │
   ▼
ValidationAgent.signal_judge — jam/airspace 도 `corroborated` 기여
   │                              SeverityEngine 불변
   ▼
Response / RuleUpdate → Report (OSCAL evidence 에 findings 임베드)
```

## 5. Components

### 5.1 신규 파일

| 경로 | 책임 |
|---|---|
| `tools/gnss_jam_tool.py` | `GnssJamTool` Protocol 정의 + `GpsJamRetriever` (REST 어댑터, TTL 5분 캐시, graceful degrade) |
| `tools/airspace_tool.py` | `AirspaceTool` Protocol 정의 + `OpenSkyRetriever` (REST 어댑터, TTL 30초 캐시, BBox 계산, graceful degrade) |
| `tools/gnss_jam_stub.py` | 테스트/데모용 in-memory stub — 특정 좌표·시간에 jam 활성 |
| `tools/airspace_stub.py` | 동일 — 가상 적대 UAV 좌표 |
| `tests/__tests__/test_gnss_jam_tool.py` | httpx MockTransport + TTL 캐시 동작 + 5xx graceful + 빈 좌표 처리 |
| `tests/__tests__/test_airspace_tool.py` | 동일 + BBox 계산 + hostile 판정 |

### 5.2 수정 파일

| 경로 | 변경 |
|---|---|
| `core/models.py` | `Alert.lat: float \| None = None`, `Alert.lon: float \| None = None`; 신규 `GnssJamFinding`, `AirspaceFinding`; `InvestigationResult.gnss_jam_findings: list[GnssJamFinding] = []`, `airspace_findings: list[AirspaceFinding] = []` |
| `core/policy/asset-tiers.yaml` | 각 자산에 선택 `coords: { lat: float, lon: float, radius_km: float }` 추가 |
| `core/settings.py` | `opensky_username: SecretStr \| str = ""`, `opensky_password: SecretStr \| str = ""`, `gpsjam_endpoint: str = "https://gpsjam.org/api/"`, `airspace_known_friends: list[str] = []` (callsign 화이트리스트) |
| `agents/investigation_agent.py` | 생성자에 `gnss_jam: GnssJamTool \| None`, `airspace: AirspaceTool \| None` 추가. 메서드 `_resolve_coords(alert)`, `_lookup_gnss_jam(alert, coords)`, `_lookup_airspace(alert, coords)`. confidence 보강 규칙 |
| `agents/graph.py` | `build_soc_graph(gnss_jam=, airspace=)` 인자. `_default_gnss_jam(settings)`, `_default_airspace(settings)` factory — 설정 있으면 실 어댑터, 없으면 None |
| `agents/validation_agent.py:signal_judge` | `corroborated = ...) or jam_findings or airspace_hostile` |

### 5.3 의존 그래프 (단방향)

```
core/models.py
   ▲
   ├── tools/gnss_jam_tool.py   ── tools/gnss_jam_stub.py (테스트용)
   ├── tools/airspace_tool.py   ── tools/airspace_stub.py (테스트용)
   └── agents/investigation_agent.py
              ▲
              └── agents/graph.py
```

각 도구 모듈은 `core` 와 `httpx` 만 의존. agents 측이 도구를 import.

## 6. 데이터 모델

```python
# core/models.py
class Alert(BaseModel):
    # ... 기존 필드 ...
    lat: float | None = None  # WGS84 위도(deg)
    lon: float | None = None  # WGS84 경도(deg)

class GnssJamFinding(BaseModel):
    """GPSJam.org 셀 한 건. level 은 0(no signal loss)~3(severe)."""
    cell: str            # "lat_int,lon_int" 1° 그리드 키 (소스 그대로)
    level: int           # 0..3
    as_of: str           # ISO8601 date — gpsjam 일 단위
    source: str = "gpsjam"

class AirspaceFinding(BaseModel):
    """OpenSky 항적 한 건."""
    icao24: str          # 트랜스폰더 ICAO24 (16진)
    callsign: str = ""   # 비행 콜사인 (없을 수 있음)
    lat: float
    lon: float
    distance_km: float   # 경보 좌표 대비 거리
    hostile: bool        # callsign 화이트리스트 외 / 미등록 패턴
    on_ground: bool = False
    source: str = "opensky"

class InvestigationResult(BaseModel):
    # ... 기존 필드 ...
    gnss_jam_findings: list[GnssJamFinding] = Field(default_factory=list)
    airspace_findings: list[AirspaceFinding] = Field(default_factory=list)
```

## 7. Data Flow

```text
1. Alert 도착 → _resolve_coords(alert):
     if alert.lat is not None and alert.lon is not None:
         return (alert.lat, alert.lon)
     coords = asset-tiers.yaml[alert.asset_id].get("coords")
     return (coords.lat, coords.lon) if coords else None

2. coords 가 None 이면 두 도구 호출 생략 → guardrail_flags 에
   "좌표 부재 — 외부 컨텍스트 강등" 추가.

3. 도구 호출 (각자 SOCPlatformError 잡고 빈 결과로 강등):
   GnssJamTool.aretrieve(lat, lon, t)
     → 캐시 키 `(floor(lat), floor(lon), date YYYY-MM-DD)` (1° 그리드 + 일 단위) — TTL 5분
     → GET {gpsjam_endpoint}?bbox={floor(lat)},{floor(lon)},{ceil(lat)},{ceil(lon)}&date=YYYY-MM-DD
     → list[GnssJamFinding]

   AirspaceTool.aretrieve(coords, t)
     → BBox 계산: lat ± 0.1°, lon ± 0.1° (약 ±11km)
     → 캐시 키 `(round(lat,1), round(lon,1), floor(epoch/30))` (0.1° + 30초 버킷) — TTL 30초
     → GET https://opensky-network.org/api/states/all?lamin=...&lomax=...&lamax=...&lomin=...
     → list[AirspaceFinding]  (hostile 판정:
        callsign 공백 AND on_ground=False  →  hostile=True
        callsign 비공백 AND callsign ∉ airspace_known_friends  →  hostile=True
        else  →  hostile=False)

4. confidence 보강 규칙 (결정론, 각 +0.2 한 번씩만):
   - gnss_jam_findings 중 `level ≥ 2` AND `alert.scenario_id.upper().startswith("S1")` (S1·S1-GNSS-001 등 GNSS 시나리오 군) → +0.2
   - airspace_findings 중 `hostile=True` AND `distance_km ≤ 10` → +0.2
   - 보강 후 `round(min(1.0, ...), 3)` — 기존 `_confidence` 패턴 동일

5. InvestigationResult 에 findings 임베드.

6. ValidationAgent.signal_judge — corroborated 가 다음 조건들의 OR:
   - 기존: similar_cases / confidence≥0.5 / experience_corroboration>0
   - 추가: any(jam.level≥2) / any(airspace.hostile)

7. ReportAgent — guardrail_flags 에 "외부 jam/airspace 컨텍스트 사용" 추가 +
   OSCAL evidence 에 findings 직렬화.
```

## 8. Error Handling

| 시나리오 | 처리 |
|---|---|
| HTTP 5xx / 타임아웃 / DNS 실패 | `SOCPlatformError` 잡고 빈 결과 (기존 `_lookup_ti` 등과 동일 graceful) |
| API 키 / 자격증명 미설정 | 어댑터 자체 미생성 (graph 의 `_default_*` factory 가 None 반환) |
| 응답 스키마 변경 | pydantic `extra="ignore"` + 파싱 실패 시 빈 결과 |
| 좌표 부재 | 두 도구 호출 자체 생략 + `guardrail_flags` |
| OpenSky 익명 rate-limit (400/day) | TTL 캐시 적극 + 미캐시 호출 4s throttle (`asyncio.Semaphore(1)` + 마지막 호출 ts) |
| GPSJam endpoint 변경 / 응답 형식 | settings 외부화. 어댑터가 빈 결과로 강등 시 핫패스는 그대로 진행 |

## 9. Testing

| 테스트 파일 | 케이스 |
|---|---|
| `test_gnss_jam_tool.py` | MockTransport 정상 JSON → finding 파싱 / 5xx → 빈 결과 / TTL 캐시 동작 (같은 키 두 번 호출 시 1회만 HTTP) |
| `test_airspace_tool.py` | 동일 + BBox 계산 검증 / hostile 판정 분기(callsign 빈값·미등록 / 등록 friend) |
| `test_investigation_agent.py` (확장) | jam 도구 주입 + S1 시나리오 + level≥2 stub → `confidence` +0.2 / 적대 UAV stub → +0.2 / 둘 다 → 0.4 (한 번씩만) / 좌표 부재 → guardrail_flag |
| `test_soc_agents.py` (확장) | 그래프 end-to-end (stub 두 개 주입) → `InvestigationResult.gnss_jam_findings` 비어있지 않음 + `guardrail_flags` 외부 컨텍스트 표시 |
| `test_validation_signal_judge` | hostile airspace 만 있어도 corroborated 인정 / 미주입 시 기존 거동 보존 |

## 10. Settings 추가

```bash
# .env.example
GPSJAM_ENDPOINT=https://gpsjam.org/api/
OPENSKY_USERNAME=
OPENSKY_PASSWORD=
AIRSPACE_KNOWN_FRIENDS=KAF01,KAF02   # 콤마 분리 callsign (등록 자산)
```

## 11. YAGNI — 이번 사이클에서 제외

- ❌ Redis / 외부 캐시
- ❌ 백그라운드 폴러
- ❌ severity engine 변경
- ❌ HITL UI 변경
- ❌ multi-region BBox 분할
- ❌ RF SDR / DroneShield
- ❌ NOAA Space Weather (다른 사이클)
- ❌ UTM/WGS84 변환 (degree 단위 직접 사용)
- ❌ 다중 GPSJam 셀 해상도 (1° 그리드만)

## 12. 마이그레이션 / 호환성

- `Alert.lat`/`lon` 은 `None` 디폴트 — 기존 호출자/시뮬/테스트 무수정.
- `InvestigationResult` 의 신규 필드 디폴트 `[]` — 기존 코드 무영향.
- `build_soc_graph` 의 새 인자 디폴트 `None` — 미주입 시 도구 호출 없음.
- `asset-tiers.yaml.coords` 는 선택 — 없으면 fallback 없이 alert.lat/lon 만 봄.

## 13. 후속 사이클 (별도 spec)

- **#2 MISP/OTX TI 확장** — 기존 `ThreatIntelTool` 의 새 백엔드 어댑터. 코드 패턴 동일.
- **#3 Shodan/Censys 공격면 스캔** — 신규 `ExposureAgent` (그래프 위상 7-에이전트로 변경). pre-detection 단계 추가.

## 14. 참조

- `docs/adr/0002-autonomous-self-improving-blue-soc.md` — Deployment A/B 분리 원칙
- `agents/investigation_agent.py` — 기존 외부 도구 통합 패턴
- `core/models.py:ThreatIntelFinding` — Finding 모델 패턴
- GPSJam: <https://gpsjam.org/about>
- OpenSky REST: <https://openskynetwork.github.io/opensky-api/rest.html>
