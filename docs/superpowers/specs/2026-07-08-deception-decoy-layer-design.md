# Deception 레이어 (Decoy/Canary) — 미끼 접촉 → TTP 자동수집

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (grill 완료, 구현 착수 단계) |
| 작성자 | s1ns3nz0 |
| 관련 ADR | `docs/adr/0002-autonomous-self-improving-blue-soc.md` |
| 자매 spec | `2026-06-30-attacker-profile-store-design.md` (actors), `2026-06-30-outcome-probe-design.md` (ProbeEngine) |
| 후속 | sim_bridge decoy 센서 어댑터(uav-sim-env lane), canary 토큰 회전 |

## 1. 배경 & 동기

발단 질문: *"kill chain 으로 요청을 분석해 요청자 서버를 역으로 공격할 수 없나?"*

→ **hack-back 은 거부.** 이유: (1) 관측 source IP 는 거의 항상 스푸핑/봇넷 피해자/경유지 —
역공격은 무고한 제3자 타격, (2) 무단 접근은 관할권 불문 위법(정보통신망법 48조, CFAA),
(3) 국가행위자 상대 시 확전 유발. authorized pentest 범위는 계약 자산 한정 —
임의 요청자엔 authorization 없음.

대신 **자기 인프라 안에서의 active defense** 로 재설정. 그 첫 조각이 deception:
미끼(decoy/canary)를 심고, 상대가 걸려들면 그 접촉 자체가 **거짓양성 거의 0 인
초고신뢰 공격자 신호**. 현재 `actors/` 적립은 TP-only 라 신호 기근인데, decoy 접촉이
가장 깨끗한 `CONFIRMED_TP` 피드를 공급한다.

## 2. 목표 / 비목표

### 2.1 목표
- **decoy 2계층**: (자산) `asset-tiers.yaml` decoy 자산 + (canary) 비밀 토큰 해시 레지스트리.
- **신뢰 경계로 분리한 두 얼굴**:
  - untrusted alert 측 → 읽기전용 `decoy_hit` enrich 플래그(severity/dynamics 격상). TP 승격 없음.
  - trusted 관측 측 → `Observation.canary_hit` → `ProbeEngine` → `CONFIRMED_TP` → `ActorWriteGate` TTP 적립.
- 기존 enrich 3형제(`prediction_match`/`kill_chain_advanced`)와 동형 배선.
- 정책 파일 graceful-degrade(`.from_yaml()` + `SOCPlatformError`) 패턴 유지.
- 포이즈닝 면역·hack-back 거부 원칙 불변.

### 2.2 비목표
- 실제 배포형 honeypot 인프라(honeyd/cowrie/T-Pot, 격리 VLAN) — uav-sim-env lane 소관, 경계 밖.
- decoy 센서가 canary_hit 을 밀어넣는 sim_bridge 어댑터 — 계약(`Observation.canary_hit`)만 열어둠.
- 자동 외향/파괴 대응(COA Deny·Disrupt·Destroy) 촉발 — 운영자 메뉴/휴먼 게이트 유지.
- SeverityEngine 코어 변경.
- canary 토큰 회전 자동화(운영 후속).

## 3. 결정 요약 (grill 결과)

| # | 결정 | 근거 |
|---|---|---|
| Q1 | decoy = 파이프라인 내부 decoy-signal 모델(B). 실배포 honeypot(A)는 로그 계약만 | 플랫폼이 Sentinel alert 소비하는 분석 계층 — 결정론·읽기전용 enrich 결에 맞음 |
| Q2 | 2계층: **자산**(`asset_id` 라벨) + **canary token**(비밀 IOC). 계정/시나리오 차원 버림 | 자산=기존 레지스트리 재사용, canary=최고충실도+귀속. 나머지는 부분집합/중복 |
| Q3 | decoy-hit = 읽기전용 enrich(B). **canary→TP 승격 / asset→enrich-only** | asset_id 는 위조가능(라벨), canary 는 자기인증(비밀 지식=증거). 충실도 差 |
| Q4 | 세 봉인: ①canary 값은 해시만 커밋(원본은 .env) ②canary TP 는 적립 전용, 외향 COA 자동촉발 금지 ③fingerprint-scoped dedup | 위조 canary→강제 TP→우리 COA 무기화(hack-back 함정 재발) 차단 |
| Q5 | 터치포인트 2개: ①`core/deception.py` enrich(untrusted) ②`Observation.canary_hit`+`ProbeEngine`(trusted) | CONFIRMED_TP 는 inbound alert 아닌 신뢰 관측에서 발생 → 승격을 관측 채널에 태워 위조 벡터 구조적 차단 |
| Q6 | 스코프 = ①+② 풀 수직 슬라이스(b) | (a)는 반쪽(TTP 수집 없음), (c) 센서 어댑터는 타 lane |

## 4. Architecture

```text
  [untrusted 경로]                         [trusted 경로]
  inbound Alert                            decoy 센서 관측(sim_bridge)
  (asset_id, iocs)                         Observation(canary_hit=True)
       │                                        │
       ▼ _triage_with_match                     ▼ OutcomeProbeAgent
  DecoyDetector.enrich                     ProbeEngine.decide
   asset_id ∈ decoy_assets  ─┐             canary_hit → CONFIRMED_TP
   sha256(iocs) ∩ hashes    ─┴─► decoy_hit      │
       │                       (severity↑)      ▼
       ▼                                    ActorWriteGate.submit
  Triage/dynamics 격상                       TTP 자동 적립(포이즈닝 면역)
   (TP 승격 없음)
```

**대칭**: COA matrix 는 이미 "Deceive=디코이" 셀 보유(방어 *행동*). 본 레이어는 그 *감지* 짝.

## 5. 상세 설계

### 5.1 신규 `core/deception.py` (enrich, 읽기전용)
```python
class DecoyDetector:
    """decoy 자산/canary 접촉 → alert.decoy_hit enrich(읽기전용)."""
    def __init__(self, decoy_assets: set[str], canary_hashes: set[str]) -> None: ...
    async def enrich(self, alert: Alert) -> Alert:
        # asset_id ∈ decoy_assets  OR  sha256(각 ioc) ∈ canary_hashes → decoy_hit=True
        # 위조가능 신호 — enrich 플래그까지만. TP 승격 절대 없음.
```
- `agents/graph.py::_triage_with_match` 에 progressor 뒤 **세 번째 enricher** 배선.
- `Alert` 에 `decoy_hit: bool = False` 필드 추가(`kill_chain_advanced` 와 동형).
- severity/dynamics 정책이 `decoy_hit` 를 격상 입력으로 소비(정책 YAML 튜닝).

### 5.2 `Observation` + `ProbeEngine` 확장 (TP 적립, 신뢰관측)
- `core/outcome.py::Observation` 에 `canary_hit: bool = False` 추가(신뢰 센서가 채움).
- `ProbeEngine.decide()`: `canary_hit` 분기 → `CONFIRMED_TP`(mission_effect 와 동급, effect=0.3).
- 승격이 **신뢰 관측 채널**을 타므로 위조 canary(alert 본문)로는 TP 불가 — 구조적 차단.

### 5.3 정책 파일
- `core/policy/decoy-assets.yaml` — decoy 자산 id 목록(라벨, 커밋 OK). 또는 asset-tiers.yaml 에 `decoy: true`.
- `core/policy/canary-tokens.yaml` — **sha256 해시만(토큰이 고엔트로피라 salt 불필요)**(`canary_hashes: [...]`), 원본 토큰은 `.env`/`Settings`.
- 로더: 기존 `.from_yaml()` + `SOCPlatformError` graceful-degrade. 파일 부재 시 detector=None(기능 off).

### 5.4 세 봉인(Q4) 매핑
1. **해시-only 커밋** — canary-tokens.yaml 은 sha256 해시. 매칭 = 들어온 ioc 해시 후 멤버십.
2. **적립 전용** — canary TP 는 `ActorWriteGate` 만 도달. COA 자동실행 무배선(휴먼 게이트 유지).
3. **fingerprint dedup** — actor_id 는 hotpath strip → 위조 canary 는 공격자 자기 fingerprint 로 뭉침(프레이밍 불가). + 토큰당 dedup 로 replay count 뻥튀기 방지.

## 6. 테스트 (`tests/__tests__/`)
- `test_decoy_detector`: asset hit / canary-hash hit / miss / 빈 정책 graceful.
- `test_decoy_enrich_no_tp`: enrich 는 verdict 불변(TP 승격 없음 회귀 가드).
- `test_probe_canary_confirmed_tp`: `Observation(canary_hit=True)` → CONFIRMED_TP.
- `test_forged_canary_alert_no_tp`: alert 본문 canary → enrich 만, actor 적립 0(포이즈닝 회귀 가드).
- `test_canary_dedup`: 동일 토큰 replay → count 1회.

## 7. 롤아웃
1. 정책 파일 2개 + `.env.example` 에 `canary token seed` 항목.
2. `core/deception.py` + `Alert.decoy_hit` + graph 배선.
3. `Observation.canary_hit` + `ProbeEngine` 분기.
4. black/ruff/mypy/pytest.
5. 브랜치 `feat/deception-decoy-layer`, 커밋 `feat(deception): decoy/canary 미끼 접촉 → TTP 자동수집(enrich + TP 적립 분리)`.
