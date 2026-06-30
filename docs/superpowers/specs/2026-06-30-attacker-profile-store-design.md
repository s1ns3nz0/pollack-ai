# Attacker Profile Store (`actors/`) — AI 공방전 보강

| 항목 | 값 |
|---|---|
| 작성일 | 2026-06-30 |
| 상태 | Approved (브레인스토밍 완료, 구현 계획 작성 단계) |
| 작성자 | s1ns3nz0 |
| 관련 ADR | `docs/adr/0002-autonomous-self-improving-blue-soc.md` |
| 자매 spec | `2026-06-30-airspace-gnss-context-design.md` (#1) |
| 후속 | 대응 효과 학습, Decay, Cross-actor TTP 클러스터링 (별도 spec) |

## 1. 배경 & 동기

본선은 AI 공방전 — **고정 소수 팀(공격자 AI)** 이 해커톤 내내 반복 공격한다. 예선의 범용 UAV SOC 와 달리, 본선은 *상대 식별·예측* 이 점수에 큰 영향. 현재 구조는 다음 셋이 *유사하지만 다른* 의미를 다룬다:

| 기존 | 단위 | 공격자 정보 적용 한계 |
|---|---|---|
| `core/experience.py` (`exp/`) | scenario_id + signals 지문 | 시나리오 단위 — 같은 공격자가 시나리오 바꾸면 인지 못 함 |
| `tools/ti_tool.py` | indicator(IP/해시) | 단일 IOC. 공격자 ≠ 단일 IOC |
| RAG `kb/incident_cases` | 정적 사례 문서 | 사전 지식, 동적 누적 X |

→ 새 추상화 `actors/` 도입. **exp/ 의 게이트·서명·비대칭 신뢰 패턴은 복제·확장.**

## 2. 목표 / 비목표

### 2.1 목표
- 공격자 단위 동적 프로필을 RAGFlow `actors/` 데이터셋에 적립.
- **하이브리드 식별**: `Alert.actor_id` 명시 우선, 없으면 (mitre, signals, ip/24) 지문으로 자동 클러스터.
- Triage 의 priority 가중에 **explicit + 누적 ≥ 2 + CONFIRMED_TP** 한정으로 활용 (포이즈닝 표면 최소화).
- Investigation 의 confidence 보강에 explicit + fingerprint 모두 활용 (한 번 +0.2).
- exp/ 와 동일 강도의 변조 방어 (서명 + 지문 재계산 + INCONCLUSIVE/FP 적립 거부).
- 데이터셋 미배포 시 graceful — 기존 파이프라인 거동 보존.

### 2.2 비목표
- `SeverityEngine` 변경 (원칙 유지).
- Response/Report 보강 (대응 효과 차원은 별도 사이클).
- 다중 actor 동시 매치.
- Decay / Forgetting / Cross-actor 클러스터링.
- 시각화 / 대시보드 / HITL UI 변경.

## 3. 결정 요약 (브레인스토밍 결과)

| # | 결정 | 근거 |
|---|---|---|
| D1 | 공격자 유형: 고정 소수 팀 | 본선 룰 — 프로필이 의미 있다 |
| D2 | 식별 키: 하이브리드 (`actor_id` 우선, 없으면 fingerprint) | 운영 메타 유무에 무관하게 동작 |
| D3 | 저장 차원: TTP 빈도 + IOC 패턴 + Kill chain (대응 효과 제외) | 식별·예측 중심, YAGNI |
| D4 | 사용 위치: Triage priority + Investigation confidence | 두 노드만 보강. severity 불변 |
| D5 | 저장소: 별도 `actors/` 데이터셋 + 전용 게이트 | exp/ 와 의미 분리, 대회 종료 시 소각 가능 |
| D6 | priority 강등은 explicit + count≥2 + TP 만 | AUTO/fingerprint actor 위장으로 강등 불가 — 포이즈닝 방어 |

## 4. Architecture

```text
                       Alert (actor_id? + mitre/signals/iocs)
                                  │
                                  ▼
                ┌───────────  Triage  ───────────┐
                │ priority 가중(활성 explicit actor) │
                └─────────────┬─────────────────┘
                              ▼
                ┌──────  Investigation  ─────────┐
                │ exp 회상 + actor 회상 → confidence │
                └─────────────┬─────────────────┘
                              ▼
                       Validation → Response/RuleUpdate → Report
                              │
                              ▼  (env_verdict=CONFIRMED_TP 확정 시)
                    OutcomeProbe → ActorWriteGate
                              │
                              ▼
                    RAGFlow `actors/` 데이터셋
                              ▲
                              │  ActorReadGate (서명 검증 + 신뢰 필터)
                              │
                    Triage / Investigation 가 회상
```

## 5. Components

### 5.1 신규 파일
| 경로 | 책임 |
|---|---|
| `core/actors.py` | `ActorWriteGate` + `ActorReadGate` + `ActorStore` Protocol + 비대칭 신뢰 (explicit > auto, TP-only 적립) |
| `core/actor_fingerprint.py` | `fingerprint(alert)`, `resolve_actor_id(alert)` — 결정론 키 부여 |
| `tools/ragflow_actors.py` | RAGFlow `actors/` 데이터셋 어댑터 (`ActorStore` 구현) |
| `tools/actor_store_inmemory.py` | 테스트/MVP 용 in-memory `ActorStore` |
| `tests/__tests__/test_actor_fingerprint.py` | 결정론 / 정렬 / 부분집합 안정성 |
| `tests/__tests__/test_actor_write_gate.py` | TP-only / explicit/auto / 머지 / 서명 / kill_chain 캡 |
| `tests/__tests__/test_actor_read_gate.py` | 서명 검증 / 위조 폐기 |
| `tests/__tests__/test_triage_actor.py` | priority 강등 분기 / 미주입 거동 보존 |
| `tests/__tests__/test_investigation_actor.py` | confidence +0.2 / non-match 무영향 / exp + actor 공존 |

### 5.2 수정 파일
| 경로 | 변경 |
|---|---|
| `core/models.py` | `Alert.actor_id: str \| None = None`; 신규 `ActorTtpStat`, `ActorIocPattern`, `ActorKillChainStep`, `ActorProfile` |
| `agents/triage_agent.py` | 생성자에 `actor_read: ActorReadGate \| None`, `min_alerts: int`. **explicit + count≥min_alerts** 면 `priority = max(1, priority-1)` + 근거 기록 |
| `agents/investigation_agent.py` | 생성자에 `actor_read`. `_recall_actor(alert)`. TTP 매치 시 `confidence += 0.2` (한 번) |
| `agents/graph.py` | `_default_actor_read(settings)` factory + `build_soc_graph(actor_read=, actor_write=)` |
| `app/learning.py` | `run_cycle` 에 actor 적립 단계 추가 (env_verdict=TP 만) |
| `core/settings.py` | `ragflow_actors_dataset_id: str = ""`, `actor_priority_min_alerts: int = 2`, `actor_signing_secret: SecretStr` |

### 5.3 의존 그래프
```
core/models.py
   ▲
   ├── core/actor_fingerprint.py
   ├── core/actors.py            ── tools/actor_store_inmemory.py (테스트)
   │                             ── tools/ragflow_actors.py
   ├── agents/triage_agent.py
   ├── agents/investigation_agent.py
   └── app/learning.py
              ▲
              └── agents/graph.py
```

## 6. Data Model

```python
# core/models.py
class ActorTtpStat(BaseModel):
    tactic: str                       # MITRE tactic id
    technique: str                    # MITRE technique id
    count: int
    last_seen: str                    # ISO8601

class ActorIocPattern(BaseModel):
    kind: str                         # "ip_24" | "asn" | "domain" | "user_agent" | "session_pattern"
    value: str
    count: int
    last_seen: str

class ActorKillChainStep(BaseModel):
    ts: str
    alert_id: str
    scenario_id: str
    technique: str

class ActorProfile(BaseModel):
    actor_id: str                              # explicit 또는 `fp:<sha256-16>`
    is_explicit: bool
    first_seen: str
    last_seen: str
    alert_count: int
    ttp_stats: list[ActorTtpStat] = Field(default_factory=list)
    ioc_patterns: list[ActorIocPattern] = Field(default_factory=list)
    kill_chain: list[ActorKillChainStep] = Field(default_factory=list)   # 최대 50건 슬라이드
    content_hash: str = ""
    signature: str = ""

    def fingerprint(self) -> str:
        """정규화된 핵심 내용의 SHA-256 — 서명·검증 기준."""
        payload = {
            "actor_id": self.actor_id,
            "is_explicit": self.is_explicit,
            "alert_count": self.alert_count,
            "ttp": sorted([s.model_dump() for s in self.ttp_stats], key=str),
            "ioc": sorted([p.model_dump() for p in self.ioc_patterns], key=str),
            "chain": [s.model_dump() for s in self.kill_chain],
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
```

## 7. Fingerprint / actor_id 해결

```python
# core/actor_fingerprint.py
def _ip24(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ""

def fingerprint(alert: Alert) -> str:
    payload = {
        "tactics": sorted(alert.mitre.get("tactics", [])),
        "techniques": sorted(alert.mitre.get("techniques", [])),
        "signals": sorted(alert.signals),
        "ip_24": sorted({_ip24(i) for i in alert.iocs if _ip24(i)}),
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return "fp:" + hashlib.sha256(canonical.encode()).hexdigest()[:16]

def resolve_actor_id(alert: Alert) -> tuple[str, bool]:
    if alert.actor_id:
        return alert.actor_id, True
    return fingerprint(alert), False
```

**빈 payload 처리**: 모든 필드 빈값(`tactics=[]`, `techniques=[]`, `signals=[]`, `ip_24=[]`)이면 `fingerprint` 가 결정론 고정 키 `_EMPTY_FP = "fp:" + sha256('{"ip_24": [], "signals": [], "tactics": [], "techniques": []}').hex[:16]` 를 반환. write gate 가 이 값을 받으면 `REJECTED_EMPTY` 로 적립 거부 (무한 충돌 방지).

## 8. Write/Read Gate

### 8.1 Write
```python
class ActorWriteGate:
    """exp 패턴 복제 + 비대칭 신뢰 확장.

    적립 조건(전부 충족):
    1. env_verdict == CONFIRMED_TP (FP/INCONCLUSIVE 거부)
    2. fingerprint(alert) 가 비어있지 않음
    """

    async def submit(
        self, alert: Alert, env_verdict: EnvVerdict, provenance: Provenance
    ) -> WriteDecision:
        if env_verdict != EnvVerdict.CONFIRMED_TP:
            return WriteDecision(status=REJECTED_NOT_TP, reason="actor 적립은 TP 만")
        actor_id, is_explicit = resolve_actor_id(alert)
        if actor_id == _EMPTY_FP:
            return WriteDecision(status=REJECTED_EMPTY, reason="빈 fingerprint")
        existing = await self._store.aload(actor_id)
        merged = self._merge(existing, alert, is_explicit)
        merged.content_hash = merged.fingerprint()
        merged.signature = self._signer.sign(merged.content_hash)
        await self._store.awrite(merged)
        return WriteDecision(status=WRITTEN, fingerprint=merged.content_hash)
```

### 8.2 Read
```python
class ActorReadGate:
    async def recall(self, actor_id: str) -> ActorProfile | None:
        try:
            record = await self._store.aload(actor_id)
        except SOCPlatformError as exc:
            self._logger.warning("actor 회상 실패, None: %s", exc)
            return None
        if record is None or not self._verify(record):
            return None
        return record

    def _verify(self, p: ActorProfile) -> bool:
        if not p.signature or not p.content_hash:
            return False
        if p.content_hash != p.fingerprint():
            return False
        return p.signature == self._signer.sign(p.content_hash)
```

### 8.3 머지 규칙
- `alert_count += 1`
- 해당 technique 의 `ActorTtpStat.count += 1` + `last_seen` 갱신 (없으면 추가)
- IOC 패턴: ip → `ip_24` 마스킹 후 count, 신규 ua/session 패턴 추가
- `kill_chain.append({ts, alert_id, scenario_id, technique})` — 50건 초과 시 앞 드롭
- `is_explicit` 는 OR 누적 — 한 번이라도 explicit 으로 들어오면 True

## 9. 통합 — Triage / Investigation

### 9.1 Triage priority 가중 (explicit 한정)
```python
async def run(self, state):
    alert = state["alert"]
    level, rationale = self._engine.compute(alert)
    priority = _PRIORITY[level]
    if self._actor_read is not None and alert.actor_id is not None:
        profile = await self._actor_read.recall(alert.actor_id)
        if (profile and profile.is_explicit
                and profile.alert_count >= self._min_alerts):
            priority = max(1, priority - 1)
            rationale.append(f"actor[{profile.actor_id}] active → priority -1")
    # ... severity 가드레일(기존) ...
```

### 9.2 Investigation confidence 보강
```python
async def _recall_actor(self, alert):
    if self._actor_read is None: return None
    actor_id, _ = resolve_actor_id(alert)
    return await self._actor_read.recall(actor_id)

# run() 안:
profile = await self._recall_actor(alert)
if profile is not None:
    current_techs = set(alert.mitre.get("techniques", []))
    top_techs = {s.technique for s in
                 sorted(profile.ttp_stats, key=lambda x: -x.count)[:3]}
    if current_techs & top_techs:
        confidence = round(min(1.0, confidence + 0.2), 3)
        flags.append(f"actor[{profile.actor_id}] TTP 매치 → conf +0.2")
```

## 10. 학습 사이클 — Deployment B

```python
# app/learning.py:run_cycle
async def run_cycle():
    for outcome in await self._probe.drain():
        await self._exp_gate.submit(...)                    # 기존
        if (self._actor_gate is not None
                and outcome.env_verdict == EnvVerdict.CONFIRMED_TP):
            await self._actor_gate.submit(
                outcome.alert, outcome.env_verdict, outcome.provenance,
            )
```

## 11. 포이즈닝 방어

| 위협 | 방어 |
|---|---|
| 적이 `Alert.actor_id` 에 다른 팀 ID 위장 → 그쪽 priority 강등 유도 | **신뢰 주입 경계**: `actor_id` 는 `sim_bridge` / 운영진 emitter / 신뢰 inbound webhook 만 채울 수 있다. SOC 그래프 내부 노드는 `actor_id` 를 *읽기 전용*. 외부 입력 (Sentinel alert 본문, RAG 컨텍스트, LLM 출력) 에서 들어온 `actor_id` 는 hotpath 진입 단계에서 strip + 재가공 (`alert.actor_id = None`). 가드는 `app/hotpath.py:_run_alert` 의 신뢰 메타 화이트리스트로 구현 |
| 자동 노이즈 다발로 priority 강등 유도 | priority 가중은 only **explicit + count≥2 + 누적 TP** — fingerprint actor 는 priority 영향 0 |
| 자동 fingerprint 충돌(다른 공격자 같은 지문) | confidence 보강은 +0.2 한 번. severity 영향 0. signal_judge 의 *다른 근거* OR — 단독 판정 X |
| 저장소 직접 변조 | `ActorReadGate._verify` 서명 + 지문 재계산 (exp 패턴 동일) |
| CONFIRMED_FP 를 actor 적립 사용한 *반복 fingerprint* 학습 | write gate 가 CONFIRMED_FP/INCONCLUSIVE 거부. FP 패턴은 `exp/` suppression 한정 |

## 12. Error Handling

| 시나리오 | 처리 |
|---|---|
| RAGFlow `actors/` 데이터셋 미배포 | factory None → graceful, 두 에이전트 거동 보존 |
| store 장애 | `SOCPlatformError` 잡고 None / WriteDecision 실패 |
| 빈 fingerprint | 적립 거부 (`REJECTED_EMPTY`) |
| 서명 불일치 | 회상 단계 폐기 + warning log |
| `actor_id` 출현 형식 오류 (공백/특수문자) | resolve 단계에서 strip + 빈 문자열은 fingerprint fallback |

## 13. Testing 매트릭스

| 테스트 파일 | 케이스 |
|---|---|
| `test_actor_fingerprint.py` | 같은 alert → 같은 키, signals 순서 무관, ip /24 마스킹, 빈 mitre 처리, 빈 payload → 거부 신호 |
| `test_actor_write_gate.py` | TP-only / explicit/auto 머지 / kill_chain 50건 캡 / 서명 부여 / 중복 호출 머지 |
| `test_actor_read_gate.py` | 미서명 폐기 / 지문 불일치 폐기 / 정상 회상 / 저장소 장애 None |
| `test_triage_actor.py` | explicit + count≥2 → priority -1 / fingerprint actor → 무영향 / 미주입 → 거동 보존 |
| `test_investigation_actor.py` | TTP 매치 → conf +0.2 / non-match → 무영향 / exp + actor 둘 다 → 각자 +0.2 / 미주입 거동 보존 |
| `test_learning_actor_cycle.py` | TP 적립, FP/INCONCLUSIVE skip, 게이트 미주입 시 학습 사이클 거동 보존 |

## 14. Settings 추가

```bash
# .env.example
RAGFLOW_ACTORS_DATASET_ID=
ACTOR_PRIORITY_MIN_ALERTS=2
ACTOR_SIGNING_SECRET=                # HMAC 비밀키 (필수 — 미설정 시 SHA256 폴백)
```

## 15. YAGNI — 이번 사이클 제외

- ❌ Response/Report 보강
- ❌ 다중 actor 동시 매치 (한 alert → 한 actor)
- ❌ Decay / Forgetting
- ❌ Cross-actor TTP 유사도 클러스터링
- ❌ 시각화 / 대시보드
- ❌ Approval HITL 메시지 변경
- ❌ severity engine 변경
- ❌ 비-IPv4 IOC 마스킹 (IPv6/도메인 우선순위 차후)

## 16. 마이그레이션

- `Alert.actor_id` 디폴트 `None` — 기존 호출자 무수정
- `build_soc_graph(actor_read=None, actor_write=None)` 디폴트 — graph 미주입 시 거동 보존
- `actors/` 데이터셋 미배포 시 factory None → 기존 파이프라인 그대로
- `app/learning.py` actor 적립은 `_actor_gate is not None` 가드 — exp 사이클 단독 실행 가능

## 17. 후속 사이클 (별도 spec)

- **Actor 대응 효과 학습** — Response 후 outcome 추적, PB 효과 점수로 보강
- **Decay** — 오래된 actor 자동 만료 (대회 종료 후 자동 삭제)
- **Cross-actor TTP 클러스터링** — 미식별 fingerprint 군 → 운영자 라벨링 UX
- **Approval HITL 컨텍스트** — "Team-X 재등장" 메시지

## 18. 참조

- `docs/adr/0002-autonomous-self-improving-blue-soc.md` — 자가발전 Blue SOC 원칙
- `core/experience.py` — 복제 대상 패턴 (게이트/서명/비대칭 신뢰)
- `core/models.py:ExperienceRecord` — 데이터 모델 패턴
- `agents/investigation_agent.py:_recall_experience` — 회상 통합 패턴
