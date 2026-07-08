# Inbound 신뢰 경계 — 구조적 whitelist wire 모델 (enrich 위조 근절)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (grill 완료, Codex 검증 → 구현) |
| 작성자 | s1ns3nz0 |
| 근거 | Codex 반복 지적(MBCRA M-1 등) 전역판 — untrusted 입력이 enrich 플래그 위조 |
| base | `feat/cyber-bda`(스택 최상단 — 전 enrich 필드 존재) |

## 1. 배경 & 동기
hotpath(`app/hotpath.py`)는 `actor_id` 만 strip 한다. 나머지 파이프라인 내부 필드
(`decoy_hit`·`key_terrain`·`kill_chain_advanced`·`prediction_match`·dynamics 3종)는
untrusted `/alert` POST 가 위조해 severity 를 **격상(또는 no_effect_sustained 로 억제)**
할 수 있다. 매 신규 enrich 기능마다 Codex 가 같은 취약점을 지적했다. pop 목록(blacklist)은
fail-open(신규 필드 깜빡→위조가능). **구조적 whitelist 경계**로 근절한다.

## 2. 목표 / 비목표
### 목표
- `UntrustedAlertPayload` whitelist wire 모델 — 외부 생산자가 채울 수 있는 서술 필드만.
- `.to_alert()` → 내부 `Alert`(8개 내부전용 필드는 기본값).
- hotpath 를 wire 모델 경유로 교체(유일 untrusted 진입점).
- **drift 가드 테스트** — Alert 필드 = wire 필드 ∪ 내부전용8. 신규 필드 분류 강제.
### 비목표
- 신뢰 생산자(sim_bridge·outcome_probe·correlation) 변경 — `Alert()` 직접 생성 유지(actor_id 등 세팅 능력 보존).
- 개별 detector 의 authoritative-overwrite 재작업 — 경계에서 근절하므로 불필요.
- Alert 모델 필드 이동/삭제 — 필드는 그대로, wire 노출만 제한.

## 3. 내부전용 12필드 (wire 제외) — Codex 설계검증 반영
| 필드 | 채우는 주체 | 위조 위험 |
|---|---|---|
| actor_id | sim_bridge/운영자(직접 Alert) | 신원 위장 |
| prediction_match | PredictionMatcher | 격상 |
| kill_chain_advanced | KillChainProgressor | 격상 |
| decoy_hit | DecoyDetector | 격상 |
| key_terrain | KeyTerrainDetector | 격상 |
| dwelling_min | OutcomeProbe/관측 | 격상(체류 임계) |
| lateral_correlation | 관측 | 격상(min floor) |
| no_effect_sustained | 관측 | **억제(de-escalation)** |
| **ground_truth** | eval/sim(직접 Alert) | **Critical — default_judge 판정 우회(억제)** |
| **expected_detection** | 시나리오(직접 Alert) | **High — RuleUpdateAgent watchlist/PR 권한** |
| **posture** | CPCON provider/운영자 | Medium — severity 권한 + 하향금지 lock(방어측 조건, 위협보고가 지정 불가) |
| **defense_playbook** | 시나리오/룰(직접 Alert) | Medium — response 행동 + HITL 프롬프트 지시 |

wire 허용 15: id·scenario_id·title·asset_id·asset_tier·mission_phase·severity_baseline·mitre·signals·iocs·cves·sbom_components·llm_suggested_severity·lat·lon.

**의미적 트리거링(Codex High) 수용**: whitelisted asset_id/iocs/mitre 가 detector 통해 파생
플래그(decoy_hit 등)를 유발하는 건 막지 않는다 — 이는 *escalation-only*(자기 alert 격상)
이고 억제 불가(no_effect_sustained 등은 내부전용). 위협 내용이 탐지를 유발하는 건 설계상
정상(미끼 자산 접촉 → decoy_hit 은 탐지가 작동한 것). 테스트로 문서화.

**드롭 로깅(Codex 권고)**: to_alert 시 payload 에 내부전용 키가 있었으면 warning 로깅
(위조 시도 telemetry). extra="ignore" 는 가용성 위해 유지(forbid 는 정상 트래픽 거부).

## 4. 설계
```python
class UntrustedAlertPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")  # 위조 enrich 필드 구조적 드롭
    # 허용 서술 필드만: id, scenario_id, title, asset_id, asset_tier,
    # mission_phase, posture, severity_baseline, mitre, signals, iocs, cves,
    # sbom_components, expected_detection, defense_playbook, ground_truth,
    # llm_suggested_severity, lat, lon
    ...
    def to_alert(self) -> Alert:
        return Alert(**self.model_dump())  # 8개 내부전용은 Alert 기본값
```
- hotpath: `Alert.model_validate(payload)` → `UntrustedAlertPayload.model_validate(payload).to_alert()`.
- `_INTERNAL_ONLY_FIELDS: frozenset` 모듈 상수 — drift 가드가 참조.

## 5. 트러스트 불변식
- **untrusted wire 는 8필드를 물리적으로 못 실음**(모델에 없음 + extra="ignore").
- 신뢰 생산자는 `Alert()` 직접 생성 → 8필드 세팅 가능(경계 밖).
- fail-safe: 신규 inbound 필드 깜빡 → wire 에서 안 받음(기능 degrade)이지 위조구멍 아님.

## 6. 테스트 (`tests/__tests__/test_inbound_boundary.py`)
- 위조 payload(decoy_hit/key_terrain/no_effect_sustained/actor_id=조작) → to_alert 후 전부 기본값.
- 정상 서술 필드는 그대로 전달.
- **drift 가드**: `set(Alert.model_fields) == set(UntrustedAlertPayload.model_fields) | _INTERNAL_ONLY_FIELDS` — 불일치 시 실패(신규 필드 분류 강제).
- hotpath 통합: 위조 alert POST → 격상 안 됨.

## 6.1 Codex diff 검증 반영 (구현 후)
5개 체크포인트 전부 PASS(12필드 완결·round-trip 무누출·hotpath 교체·drift 가드·raw 위조탐지).
잔여 지적:
- **High `severity_baseline`(wire)**: severity 엔진 시작점 → caller 영향. **내부이동 안 함** —
  baseline 은 SOC 계산이 아닌 **탐지소스 필드**(signals·mitre 와 동류, Codex 도 mitre 는 Low).
  엔진이 필수입력으로 요구 + 파생 소스도 결국 untrusted. 대신 **경계 명확화 + 억제불가 실증**:
  내부 modifier(asset/key_terrain/dynamics)가 baseline 무관 격상 + 최종 판정은 env-validation.
  → `test_forged_low_baseline_still_escalates` 로 증명.
- **Low `mitre`**: investigation confidence/STRIDE 영향. 탐지소스 필드라 수용(내부필드 재유입 없음).

## 7. 롤아웃
1. UntrustedAlertPayload + to_alert + _INTERNAL_ONLY_FIELDS.
2. hotpath 교체.
3. Codex 검증(설계+diff) → black/ruff/mypy/pytest.
4. 브랜치 `feat/inbound-trust-boundary`, 커밋 `feat(security): inbound 신뢰경계 — whitelist wire 모델로 enrich 위조 근절`.
