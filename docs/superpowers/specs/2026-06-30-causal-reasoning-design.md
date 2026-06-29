# Causal Reasoning — 신호→영향 인과 체인 분석 (A1)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-06-30 |
| 상태 | Approved (브레인스토밍 완료, 구현 계획 작성 단계) |
| 작성자 | s1ns3nz0 |
| 자매 spec | #1 Airspace/GNSS, #2 Attacker Profile, B1 Multi-Judge, D1 RAGAS, C1 Sequence Prediction |
| 후속 | LLM 단독 인과 추론, 인과 룰 자동 학습, 베이지안 네트워크 |

## 1. 배경 & 동기

현재 Investigation 의 `summary` 는 *서술형* 분석. 인과 관계가 *명시* 되지 않아:
- 운영자가 *왜* 정탐인지 추적이 어려움
- OSCAL evidence 의 해석 가능성 부족
- 데모 깊이 부족 — "GPS 스푸핑 → EKF 잔차 → 항로 이탈" 같은 *체인* 가시화 없음

→ **결정론 규칙 기반 인과 체인** 도입. LLM 은 *자연어 근거* 만 (인과 자체는 yaml 규칙).

## 2. 목표 / 비목표

### 2.1 목표
- `core/policy/causal-rules.yaml` 에 `signal → effect → next_step` 결정론 매핑.
- alert 의 `signals` 와 매칭되는 체인 빌드 → `CausalChain`.
- `ReportAgent` 가 체인을 `SOCReport.causal_summary` + OSCAL evidence 에 임베드.
- 인과 자체는 결정론 — LLM 인젝션이 인과 *왜곡* 불가.
- LLM 은 *체인 단계 설명* 만 (선택).
- 룰 미주입 / 신호 매치 없음 → 빈 체인 (graceful).

### 2.2 비목표
- LLM 단독 인과 추론 (인젝션 표면)
- 인과 룰 자동 학습
- 베이지안 네트워크
- 인과 발견 (causal discovery) — 룰은 수동 작성
- `SeverityEngine` 변경

## 3. 결정 요약

| # | 결정 | 근거 |
|---|---|---|
| D1 | 규칙 기반 결정론 (yaml) | 해석 가능 + 인젝션 면역 + 룰 변경 코드 무수정 |
| D2 | LLM 은 *근거 자연어* 만 (선택) | 인과 자체는 결정론 — LLM 인젝션이 왜곡 불가 |
| D3 | Report 단계에서 체인 빌드 | 그래프 위상 무변. Investigation 결과 + alert 신호 입력 |
| D4 | OSCAL evidence 에 임베드 | 방산 컴플라이언스 점수 |

## 4. Architecture

```text
   Report 노드 (alert + investigation + ensemble + ...)
              │
              ▼
   CausalReasoner.build(alert, investigation)
              │
              ├──→ rules.yaml 로드 (캐시)
              ├──→ alert.signals + alert.mitre.techniques 매칭 룰 추출
              └──→ chain = [step1, step2, ..., stepN] 빌드
                          │
                          ▼
              (선택) LLM 근거 생성 — 각 step.explanation
                          │
                          ▼
   SOCReport.causal_summary = chain
   OscalEvidence.causal_chain = chain
```

## 5. Components

### 5.1 신규
| 경로 | 책임 |
|---|---|
| `core/causal.py` | `CausalReasoner` 클래스 + `load_rules()` + `build_chain(alert, inv) -> CausalChain` |
| `core/policy/causal-rules.yaml` | 결정론 인과 룰 — UAV 도메인 시드 (S1 GNSS, S5 RAG 등) |
| `tests/__tests__/test_causal_reasoner.py` | 매칭 / 체인 빌드 / LLM 근거 mock / 빈 매치 |

### 5.2 수정
| 경로 | 변경 |
|---|---|
| `core/models.py` | 신규 `CausalStep(signal, effect, next_step, mitre_technique, explanation)`, `CausalChain(steps, basis_rules)`; `SOCReport.causal_summary: CausalChain \| None`; `OscalEvidence.causal_chain: CausalChain \| None` |
| `agents/report_agent.py` | 생성자에 `reasoner: CausalReasoner \| None`. `_build_causal(alert, inv)` 호출 |
| `agents/graph.py` | `_default_reasoner(settings, llm)` factory |
| `core/oscal.py` | `build_evidence` 가 causal_chain 직렬화 |
| `core/settings.py` | `causal_rules_path: str = "core/policy/causal-rules.yaml"`, `causal_llm_explain: bool = False` |

## 6. Data Model

```python
class CausalStep(BaseModel):
    signal: str                                    # 입력 신호 (e.g., "EKF_DIVERGENCE")
    effect: str                                    # 결과 효과 (e.g., "POSITION_LOSS")
    next_step: str = ""                            # 다음 단계 (체인 연결, 마지막은 빈값)
    mitre_technique: str = ""                      # 매핑 ATT&CK technique (있으면)
    explanation: str = ""                          # LLM 생성 자연어 (선택, 빈값 가능)

class CausalChain(BaseModel):
    steps: list[CausalStep] = Field(default_factory=list)
    basis_rules: list[str] = Field(default_factory=list)  # 매치된 룰 ID 목록

class SOCReport(BaseModel):
    # 기존 ...
    causal_summary: CausalChain | None = None

class OscalEvidence(BaseModel):
    # 기존 ...
    causal_chain: CausalChain | None = None
```

## 7. 룰 yaml 형식

```yaml
# core/policy/causal-rules.yaml
version: 1
rules:
  - id: S1-GNSS-SPOOF
    when_signal: ["GPS_GLITCH_FLAG", "EKF_HIGH_VARIANCE"]
    chain:
      - signal: GPS_GLITCH_FLAG
        effect: GNSS_INTEGRITY_LOSS
        next_step: EKF_DIVERGENCE
        mitre_technique: T0830
      - signal: EKF_DIVERGENCE
        effect: POSITION_UNCERTAINTY
        next_step: FLIGHT_PATH_DEVIATION
        mitre_technique: T0843
      - signal: FLIGHT_PATH_DEVIATION
        effect: MISSION_ABORT
        next_step: ""
        mitre_technique: T0815

  - id: S5-RAG-POISON
    when_signal: ["SUGGESTED_SEVERITY_DROP"]
    chain:
      - signal: SUGGESTED_SEVERITY_DROP
        effect: SEVERITY_DOWNGRADE_ATTEMPT
        next_step: GUARDRAIL_TRIGGER
        mitre_technique: ATLAS-AML-T0051
      - signal: GUARDRAIL_TRIGGER
        effect: POLICY_LOCK
        next_step: ""
        mitre_technique: ""
```

## 8. Reasoner 로직

```python
# core/causal.py
class CausalReasoner:
    def __init__(self, rules_path: Path, llm: LLMClient | None = None,
                 explain: bool = False) -> None:
        self._rules = self._load(rules_path)
        self._llm = llm
        self._explain = explain

    @staticmethod
    def _load(path: Path) -> list[dict]:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("rules", [])

    async def build_chain(self, alert: Alert, inv: InvestigationResult | None
                          ) -> CausalChain:
        matched: list[dict] = []
        signals = set(alert.signals)
        for rule in self._rules:
            triggers = set(rule.get("when_signal", []))
            if triggers & signals:
                matched.append(rule)
        if not matched:
            return CausalChain()
        # 첫 매칭 룰의 chain 사용 (단순화 — 멀티 매칭은 후속)
        rule = matched[0]
        steps = [CausalStep(**s) for s in rule.get("chain", [])]
        if self._explain and self._llm is not None:
            for step in steps:
                try:
                    step.explanation = await self._llm.acomplete(
                        _SYS, _user(alert, step),
                    )
                except LLMError:
                    pass                        # 설명 누락 허용
        return CausalChain(steps=steps, basis_rules=[m["id"] for m in matched])
```

## 9. Report 통합

```python
async def run(self, state):
    # 기존 report 빌드 후
    if self._reasoner is not None:
        chain = await self._reasoner.build_chain(
            state["alert"], state.get("investigation"),
        )
        if chain.steps:
            report.causal_summary = chain
    evidence = oscal.build_evidence(state, evidence_level)
    if report.causal_summary is not None:
        evidence.causal_chain = report.causal_summary
    return {"report": report, "oscal_evidence": evidence, "trace": ["report"]}
```

## 10. Error Handling

| 시나리오 | 처리 |
|---|---|
| 룰 yaml 파싱 실패 | `PolicyError` → reasoner 생성 시점 강제 종료 (운영 가이드) |
| 룰 빈 리스트 | 모든 alert 빈 체인 |
| 신호 매칭 없음 | 빈 체인 |
| LLM 설명 실패 | 해당 step.explanation 빈값 — 체인 자체는 보존 |
| `causal_rules_path` 미존재 | reasoner 생성 안 함 (graph factory None) |

## 11. Testing

| 테스트 | 케이스 |
|---|---|
| `test_load_rules_yaml` | 정상 파싱 / 형식 오류 → PolicyError |
| `test_build_chain_match` | S1 신호 → 3 step 체인 / S5 신호 → 2 step / 신호 없음 → 빈 체인 |
| `test_build_chain_llm_explain` | LLM mock → explanation 채워짐 / LLM 실패 → 빈 explanation, 체인 보존 |
| `test_report_causal_summary` | reasoner 주입 + 매칭 alert → SOCReport.causal_summary 채워짐 / OscalEvidence.causal_chain 노출 |
| `test_no_reasoner` | reasoner 미주입 → causal_summary=None, 기존 거동 |

## 12. Settings

```bash
CAUSAL_RULES_PATH=core/policy/causal-rules.yaml
CAUSAL_LLM_EXPLAIN=false                       # opt-in
```

## 13. YAGNI

- ❌ 멀티 룰 매칭 결합 (첫 매칭만)
- ❌ LLM 단독 인과 추론
- ❌ 룰 자동 학습 / discovery
- ❌ 베이지안 네트워크
- ❌ 인과 그래프 시각화 (Grafana 패널 별도)
- ❌ 후속 alert 와 체인 연결 (incident chain)

## 14. 마이그레이션

- `causal_summary` / `causal_chain` 디폴트 `None` — 기존 코드 무영향
- reasoner 미주입 시 거동 보존
- 룰 yaml 미존재 시 reasoner 미생성 (graph factory)
- 기존 `OscalEvidence` 직렬화 호환 (Optional 필드)

## 15. 후속

- **멀티 룰 결합** — 여러 매칭 룰 → DAG 빌드
- **LLM 인과 추론 보조** — 룰 빈 매치 시 LLM 폴백
- **인과 룰 자동 학습** — 정탐 누적 → 룰 후보 자동 생성 → 운영자 검토 PR
- **incident chain** — 같은 actor / 캠페인의 다중 alert 연결

## 16. 참조

- `core/policy/severity-policy.yaml` — yaml 정책 패턴
- `core/oscal.py` — evidence 빌더
- `agents/report_agent.py` — 통합 지점
- MITRE ATT&CK technique 참조
