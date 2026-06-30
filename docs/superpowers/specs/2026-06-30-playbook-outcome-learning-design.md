# Playbook Outcome Learning — PB 효과 점수 학습 (B-1)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-06-30 |
| 상태 | Approved (브레인스토밍 완료, 구현 단계) |
| 작성자 | s1ns3nz0 |
| 자매 spec | #2 Attacker Profile Store, C1 Attack Sequence Prediction |
| 후속 | A-1 OutcomeProbe 실연동, Multi-PB 후보 풀 + 자동 선택, Active Learning |

## 1. 배경 & 동기

#2 Attacker Profile Store 의 비목표였던 *대응 효과 차원*. 본선 AI 공방전에서 같은
공격자가 반복 등장하므로, 같은 공격자에 대해 어느 플레이북(PB)이 *얼마나 효과 있었는지*
누적·노출하면 다음 alert 처리 시 운영자(또는 차후 자동 선택)가 근거 기반 판단을 할 수
있다. 본 spec 은 **측정·적립**만 한다 — PB 자동 선택은 후속 사이클.

## 2. 목표 / 비목표

### 2.1 목표
- `ActorProfile.pb_scores` 신규 필드에 (playbook_id → 점수) 누적.
- `ActorPlaybookOutcomeGate` 단일 통로 — 입력 검증·서명 갱신·저장.
- 점수 모델 = 단순 평균 (count + sum_effect → avg).
- Report 가 (선택) actor 의 PB 효과 top-3 노출.
- `outcome.effect` 는 호출자가 결정한 0~1 점수 (신호 매핑 spec 외부).
- 기존 ActorWriteGate/ActorReadGate 패턴·서명 재사용.

### 2.2 비목표
- PB 자동 선택 (multi-PB 후보 풀 부재).
- outcome 신호 자동 측정 (A-1 OutcomeProbe 실연동 후속).
- Active Learning / 운영자 피드백 루프.
- EMA / Bayesian.
- Decay / Forgetting.

## 3. 결정 요약

| # | 결정 | 근거 |
|---|---|---|
| D1 | 측정만 (PB 자동 선택 X) | 본선 시간 + multi-PB 풀 부재 |
| D2 | 점수 모델 = 단순 평균 | 결정론·해석·회귀 가능 |
| D3 | outcome 입력 = 외부 0~1 점수 | 신호 매핑 책임 분리. 가장 agnostic |
| D4 | 저장 = `ActorProfile.pb_scores` 확장 | 기존 actors/ 패턴 재사용 |
| D5 | OutcomeProbe 실연동은 spec 밖 | 본 spec gate/모델만 |

## 4. Architecture

```text
ResponseAgent 실행 (정탐 경로)
        │
        ▼
[OutcomeProbe — 외부, 미구현]
        │   PB 효과 측정 (재발/dwelling/no_effect → 0~1 점수)
        ▼
ActorPlaybookOutcomeGate.submit(outcome)
        │
        ├── store.aload(actor_id) → 프로필 (없으면 REJECTED_NO_ACTOR)
        ├── pb_scores[playbook_id] 누적 (count++, sum_effect+=)
        ├── content_hash = fingerprint() 갱신
        ├── signature = signer.sign(content_hash) 갱신
        └── store.awrite(profile)
        │
        ▼
다음 alert 의 Report 가 pb_scores top-3 를 노출 (운영자 판단 보조)
```

## 5. Components

### 5.1 신규
| 경로 | 책임 |
|---|---|
| `core/playbook_outcome.py` | `PlaybookOutcome` 모델 + `ActorPlaybookOutcomeGate` 클래스 + REJECTED_NO_ACTOR 상태 |
| `tests/__tests__/test_playbook_outcome.py` | 모델 검증 / 점수 누적 / 서명 round-trip / 빈값 거부 / 미존재 actor 거부 / Report 노출 |

### 5.2 수정
| 경로 | 변경 |
|---|---|
| `core/models.py` | 신규 `ActorPlaybookScore`. `ActorProfile.pb_scores: dict[str, ActorPlaybookScore] = {}`. `fingerprint()` 에 pb_scores 포함 |
| `core/actors.py` | `ActorWriteStatus.REJECTED_NO_ACTOR` 추가 |
| `agents/report_agent.py` | 생성자에 `actor_read: ActorReadGate \| None`. profile 회상 → pb_scores top-3 가 있으면 `guardrail_flags` 에 노출 |
| `agents/graph.py` | ReportAgent 에 `actor_read` 주입 |

## 6. Data Model

```python
class ActorPlaybookScore(BaseModel):
    """ActorProfile 의 PB 효과 점수 한 건(spec B-1)."""

    playbook_id: str
    count: int = Field(default=0, ge=0)
    sum_effect: float = Field(default=0.0, ge=0.0)
    avg_effect: float = Field(default=0.0, ge=0.0, le=1.0)
    last_seen: str = ""


class PlaybookOutcome(BaseModel):
    """PB 실행 결과 측정값 한 건(spec B-1).

    호출자가 신호→점수 매핑 책임. effect 0=차단 실패, 1=완전 차단.
    """

    actor_id: str
    playbook_id: str
    effect: float = Field(ge=0.0, le=1.0)
    ts: str
    reason: str = ""


class ActorProfile(BaseModel):
    # 기존 ...
    pb_scores: dict[str, ActorPlaybookScore] = Field(default_factory=dict)

    def fingerprint(self) -> str:
        # 기존 payload 에 pb_scores 추가 (정렬 keys)
        ...
```

## 7. Gate 로직

```python
class ActorPlaybookOutcomeGate:
    """PB 효과 점수 적립 단일 통로."""

    def __init__(self, store: ActorStore, signer: ActorSigner | None = None) -> None:
        self._store = store
        self._signer = signer or Sha256ActorSigner()
        self._logger = get_logger("ActorPlaybookOutcomeGate")

    async def submit(self, outcome: PlaybookOutcome) -> ActorWriteDecision:
        if not outcome.actor_id.strip() or not outcome.playbook_id.strip():
            return ActorWriteDecision(
                status=ActorWriteStatus.REJECTED_EMPTY,
                reason="actor_id/playbook_id 빈값",
            )
        try:
            existing = await self._store.aload(outcome.actor_id.strip())
        except SOCPlatformError as exc:
            return ActorWriteDecision(
                status=ActorWriteStatus.REJECTED_STORE_ERROR,
                reason=f"store 조회 실패: {exc}",
            )
        if existing is None:
            return ActorWriteDecision(
                status=ActorWriteStatus.REJECTED_NO_ACTOR,
                reason="actor 미적립 — outcome 측정 불가",
            )
        s = existing.pb_scores.get(outcome.playbook_id) or ActorPlaybookScore(
            playbook_id=outcome.playbook_id
        )
        s.count += 1
        s.sum_effect = round(s.sum_effect + outcome.effect, 4)
        s.avg_effect = round(s.sum_effect / s.count, 4)
        s.last_seen = outcome.ts
        existing.pb_scores[outcome.playbook_id] = s
        existing.content_hash = existing.fingerprint()
        existing.signature = self._signer.sign(existing.content_hash)
        try:
            await self._store.awrite(existing)
        except SOCPlatformError as exc:
            return ActorWriteDecision(
                status=ActorWriteStatus.REJECTED_STORE_ERROR,
                reason=f"store 저장 실패: {exc}",
            )
        return ActorWriteDecision(
            status=ActorWriteStatus.WRITTEN, actor_id=existing.actor_id
        )
```

## 8. Report 노출

```python
# report_agent.run() — actor_read 주입 시
if self._actor_read is not None and alert.actor_id:
    profile = await self._actor_read.recall(alert.actor_id.strip())
    if profile is not None and profile.pb_scores:
        top = sorted(profile.pb_scores.values(), key=lambda s: -s.avg_effect)[:3]
        flags = state.get("guardrail_flags", []) + [
            f"actor[{profile.actor_id}] PB 효과 top-3: "
            + ", ".join(f"{s.playbook_id}={s.avg_effect:.2f}({s.count})" for s in top)
        ]
        report.guardrail_flags = flags
```

`actor_read` 미주입 시 graceful skip — 기존 거동 보존.

## 9. 포이즈닝 / 신뢰 경계

| 위협 | 방어 |
|---|---|
| 외부 outcome.effect 인젝션 (1.0 다발) | gate 호출 = sim_bridge / 운영자 hook 만 (신뢰 경계). 미존재 actor 거부 |
| 미존재 actor 로 점수 적립 | `REJECTED_NO_ACTOR` |
| store 직접 변조 | ActorReadGate 서명 검증 (기존 패턴) |
| effect 범위 외 | pydantic 검증 실패 → 호출자 책임 |

## 10. Error Handling

| 시나리오 | 처리 |
|---|---|
| actor_id/playbook_id 빈값 | REJECTED_EMPTY |
| actor 미존재 | REJECTED_NO_ACTOR |
| store 장애 | REJECTED_STORE_ERROR |
| Report 의 actor_read 장애 | None 반환 → 노출 skip |

## 11. Testing 매트릭스

| 테스트 | 케이스 |
|---|---|
| `test_outcome_model_bounds` | effect 범위 0~1 검증 (음수/1 초과 거부) |
| `test_gate_rejects_empty` | 빈 actor_id 또는 playbook_id → REJECTED_EMPTY |
| `test_gate_rejects_no_actor` | actor 미존재 → REJECTED_NO_ACTOR |
| `test_gate_accumulates` | 3회 submit → count=3 + sum/avg 정확 |
| `test_gate_multiple_playbooks` | 같은 actor 두 PB → 독립 누적 |
| `test_gate_signature_round_trip` | submit → ReadGate.recall → 서명 검증 통과 (pb_scores 포함) |
| `test_report_pb_scores_exposure` | profile.pb_scores 있음 → guardrail_flags 에 노출 |
| `test_report_no_actor_read_skip` | actor_read 미주입 → 기존 거동 보존 |

## 12. YAGNI

- ❌ PB 자동 선택
- ❌ Multi-PB 후보 풀 (시나리오 yaml 확장)
- ❌ EMA / Bayesian
- ❌ outcome 자동 측정 (A-1 후속)
- ❌ Decay / Forgetting
- ❌ 점수 시계열 시각화

## 13. 마이그레이션

- `ActorProfile.pb_scores` 디폴트 `{}` — 기존 코드 무영향
- `fingerprint()` 변경 → 기존 서명된 프로필이 *재서명 필요*. 첫 submit 시 자동 갱신.
  단 ReadGate 가 기존 서명을 거부할 수 있음 — 운영 가이드: 본 변경 머지 직후 actor 데이터셋 초기화 또는 일괄 재서명 스크립트(차후)
- `report_agent.actor_read` 디폴트 None — 미주입 시 거동 보존
- 신규 `REJECTED_NO_ACTOR` 상태 — 호출자 코드 영향 없음 (enum 확장)

## 14. 후속

- **A-1 OutcomeProbe 실연동** — outcome 자동 측정 → gate 자동 호출
- **Multi-PB 후보 풀** — 시나리오 yaml 의 `defense_playbook_candidates` 확장
- **PB 자동 선택** — actor 점수 최고 + epsilon-greedy exploration
- **Active Learning** — 운영자 피드백으로 가중치 보정
- **Decay** — 오래된 점수 가중 감소

## 15. 참조

- `core/actors.py` — 복제 대상 패턴 (gate/store/signer)
- `core/models.py:ActorProfile` — 확장 대상
- `agents/report_agent.py` — 노출 지점
- `docs/superpowers/specs/2026-06-30-attacker-profile-store-design.md` — 부모 spec
