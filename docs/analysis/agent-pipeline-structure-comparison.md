# 에이전트 파이프라인 구조 비교 분석

> 작성: 2026-06-25 · 평가 하니스: `benchmarks/run_structure_comparison.py`
> (라벨셋 정탐 11[S1~S11] + 오탐 6, run_kpi.py 평가셋 재사용)
> 환경: RAGFlow 라이브 + 로컬 Ollama(qwen2.5:14b, bge-m3), LLM=live
> 결과 원본: `benchmarks/results/structure_comparison.json`

---

## 0. 배경 — 현재 설계의 본질

파이프라인 전체에서 **LLM 호출은 Investigation 요약 1곳뿐**이며 그건 사람이 읽는
**서술**이다. 실제 의사결정(심각도·신뢰도·정탐/오탐 판정·플레이북·OSCAL)은 전부
**결정론적 규칙**이다 — "판정권을 LLM에 주지 않음"(KPI 검증성 + S5 RAG 포이즈닝 방어).

이 사실이 분석을 규정한다:
- **효율**: 거의 모든 단계가 <1ms 규칙이라 **총 지연·비용은 Investigation의 RAG+LLM이 지배**.
- **품질**: 판정은 `signal_judge` 규칙이 정하므로 **토폴로지를 바꿔도 FPR/FNR은 불변**.
- 핵심 의존 사슬: Investigation 내부는 `RAG → LLM요약`이 **순차 의존**, 독립적인 건 TI뿐.
- **결정적 통찰**: `signal_judge` 는 RAG의 `similar_cases`·`confidence` 만 보고 **LLM 요약은 안 본다**
  → LLM 요약(지연의 대부분)은 **판정에 무관**.

---

## 종합 결과 (실측, LLM=live, 17케이스)

| 구조 | Precision | Recall | FPR | FNR | 총 지연(ms) | RAG 호출 | LLM 호출 | vs Baseline |
|---|---|---|---|---|---|---|---|---|
| **0 Baseline** | 1.0 | 1.0 | 0.0 | 0.0 | 2737.68 | 17 | 17 | — |
| **1 Parallel** | 1.0 | 1.0 | 0.0 | 0.0 | 2447.68 | 17 | 17 | ≈ baseline (무효) |
| **2 Router** | 1.0 | 1.0 | 0.0 | 0.0 | 1778.71 | 11 | 11 | **−35%** |
| **3 Supervisor** | 1.0 | 1.0 | 0.0 | 0.0 | **342.54** | 17 | **0** | **−87.5% (8×)** |
| **4 WizBlue(레퍼런스)** | 1.0 | 1.0 | 0.0 | 0.0 | 2614.47 | 17 | 17 | ≈ baseline (이득 없음) |

> 혼동행렬은 5구조 모두 동일: TP 11 · FP 0 · FN 0 · TN 6. **품질 완전 동률, 차이는 전부 효율.**
> 절대 지연은 라이브 LLM/RAG 타이밍 jitter로 실행마다 ±10% 흔들린다(예: Baseline 2517→2738ms).
> 견고한 신호는 **상대 패턴**: Supervisor 8×↓, Router ~35%↓, Parallel·WizBlue ≈ baseline, 품질 항상 동일.

---

## 구조 0 — Baseline (순차 DAG)

### 아키텍처
```
Triage(심각도 규칙) → Investigation(RAG→출처검증→TI→LLM요약→신뢰도)
   → Validation(signal_judge) ─┬─(정탐)→ [Approval/HITL] → Response ─┐
                              └─(오탐)→ RuleUpdate ─────────────────┴→ Report(OSCAL) → END
```

### 분석결과
- P/R = 1.0/1.0, FPR/FNR = 0/0. 총 지연 **2517.82ms**, RAG×17, LLM×17.
- 지연의 ~99.99%가 Investigation의 RAG+LLM(나머지 단계 합 0.2ms). **LLM 요약이 단일 최대 비용.**

---

## 구조 1 — Parallel-Investigation (병렬 조사)

### 아키텍처
```
Triage → Investigation{ (RAG→LLM요약)  ∥  TI조회 } 병합 → Validation → ... → Report
```
독립 하위작업(TI)을 RAG+LLM 사슬과 `asyncio.gather`로 동시 실행.

### 분석결과
- P/R = 1.0/1.0, FPR/FNR = 0/0. 총 지연 **2562.27ms (+1.8%, 오히려 느림)**, RAG×17, LLM×17.
- **결론: 효과 없음.** RAG→LLM은 의존 사슬이라 병렬화 불가, 독립 작업 TI는 IOC 없어 빈
  작업 → 겹칠 게 없고 `gather` 오버헤드만 추가됨. **"에이전트를 병렬로 늘리면 빨라진다"는
  직관이 의존성 앞에서 무력함을 보여주는 반례.**

---

## 구조 2 — Router 조기탈출 (early-exit)

### 아키텍처
```
Triage → Router┬─(매칭 룰 없음=양성노이즈)──────────────→ RuleUpdate → Report   (RAG·LLM 스킵)
               └─(룰 있음)→ Investigation → Validation → ... → Report
```
`signal_judge`의 has_rule 게이트를 triage 직후로 앞당겨, 룰 없는 경보(어차피 오탐)는
RAG+LLM 통째로 스킵.

### 분석결과
- P/R = 1.0/1.0, FPR/FNR = 0/0. 총 지연 **1648.62ms (−34.5%)**, RAG×11, LLM×11.
- 오탐 6건이 investigation을 건너뛰어 **호출수 17→11**. 품질 무손실(룰 없는 건 어차피 오탐).
- **결론: 안전한 효율 개선.** 다만 "룰 있는 11건"은 여전히 풀 RAG+LLM이라 단축폭 제한.

---

## 구조 3 — Supervisor 적응형 (★ 최적)

### 아키텍처
```
Triage → Supervisor-Investigation{
            RAG 검색(신뢰도·유사사례 — 판정에 필요) 수행,
            LLM 요약은 '근거 약한 모호 케이스'에만 (결정-무관이므로 평소 스킵)
         } → Validation → ... → Report
```
판정에 쓰이는 RAG는 유지하되, **판정-무관한 LLM 요약을 조건부로 뺀다**(근거 충분 시 생략).

### 분석결과
- P/R = 1.0/1.0, FPR/FNR = 0/0. 총 지연 **340.23ms (−86.5%, 7.4×)**, RAG×17, **LLM×0**.
- 17케이스 모두 근거 충분(similar_cases 있음/confidence≥0.5) → LLM 요약 전부 생략, 품질 동일.
- **결론: 압도적 최적.** LLM 요약이 지연의 대부분이었고 판정에 무관했으므로, 빼는 순간
  품질 무손실로 86% 단축. 남은 340ms는 RAG 검색(17회).

---

## 구조 4 — Wiz-Blue 서브에이전트 분해 (★ 레퍼런스 기반, pic/)

Google Cloud × Wiz "Securing the AI Era"의 **Blue Agent** 패턴을 실제 코드로 구현한 구조.
(레퍼런스 사진: `pic/KakaoTalk_*.jpg`)

### 아키텍처
```
Triage → WizBlue-Investigation{
            Forensics/RAG 서브에이전트   ┐
            Threat-intel 서브에이전트     ├─ asyncio.gather(동시) → 병합
            Signal-correlation 서브에이전트┘
         } → LLM 구조화 종합(조사과정·근거·권고, Wiz 'Generates')
         → Validation → ... → Report
```
Wiz Blue 의 'Code analysis + Forensics 서브에이전트' 분해를 우리 도메인(Forensics/RAG ·
Threat-intel · Signal-correlation)으로 옮겼다. 3개 전문 렌즈를 동시 실행 후 병합.

### 분석결과
- P/R = 1.0/1.0, FPR/FNR = 0/0. 총 지연 **2614.47ms (≈ Baseline)**, RAG×17, LLM×17.
- **결론: 레퍼런스 구조를 충실히 재현했으나, 이 평가셋에선 Baseline 대비 품질·효율 이득 없음.**
  ① 품질이 이미 천장(완벽)이라 분해가 더 올릴 여지가 없고, ② Wiz 'Generates'의 LLM 종합이
  매 케이스 돌아 지연을 지배(서브에이전트 병렬화가 LLM 비용을 못 줄임).
- **교훈: "업계 레퍼런스 구조 = 자동으로 더 낫다"가 아니다.** 분해형의 가치(깊이·다관점
  커버리지·풍부한 구조화 출력)는 **판정이 이미 완벽한 쉬운 평가셋이 아니라, 어려운/적대적
  평가셋**(S5 포이즈닝·모호 경보·다단계 공격)에서만 측정 가능하게 드러난다.

---

## 결론 및 권고

1. **이 아키텍처에서 "베스트 구조"는 Supervisor(#3)** — 품질 동률(완벽)에 지연 8× 단축.
   근본 원인: **LLM은 의사결정이 아니라 서술이므로 핫패스에서 빼야 한다.**
2. **실행 권고**: LLM 요약을 **lazy/on-demand**로 — 판정 후 사람이 실제로 리포트를 열람할
   때(또는 정탐 확정 건)만 생성. 핫패스(자동 판정·대응)에선 RAG 근거만으로 충분.
3. **Router + Supervisor 결합**이 이론적 최적: 룰 없는 6건은 RAG도 스킵(→RAG×11) +
   나머지는 LLM 스킵 → ~200ms대 예상. (후속 측정 후보)
4. **반(反)직관 교훈 둘**:
   (a) 병렬화(#1)는 **의존 사슬 앞에서 무효**.
   (b) **업계 레퍼런스 구조(WizBlue #4)도 자동으로 더 낫지 않다** — 쉬운/천장 평가셋에선
   Baseline과 동일 비용에 이득 0. 효율은 "더 많은/정교한 에이전트"가 아니라
   **"불필요한 비싼 단계(LLM)를 식별해 빼는 것"**에서 나온다.
5. **품질 한계 & 다음 단계**: 본 라벨셋(17건)에서 품질이 이미 천장이라 토폴로지로 더 올릴 수
   없음. 분해형(WizBlue)·LLM-판정·critic의 가치를 보려면 **더 어려운/적대적 평가셋**(S5
   포이즈닝·모호 경보·다단계 공격)이 필요하며, 이는 S5 강건성과의 트레이드오프를 동반.

---

## 관련 연구 / 확장 방향 — Google Cloud × Wiz "Securing the AI Era"

(레퍼런스 사진: `pic/KakaoTalk_*.jpg`)

업계 레퍼런스가 본 실험 방향을 검증하고 확장 축을 제시한다. 핵심 명제 **"The graph is
the foundation"** — Wiz 보안 그래프(노드=자산·발견 across CODE/CLOUD/RUNTIME, 엣지=공격경로)를
공유 기반으로 3개 역할 에이전트가 순환한다:

| Wiz 에이전트 | 미션 | 내부 구조 | 지표 |
|---|---|---|---|
| 🔴 Red(Offensive) | 악용가능 리스크 선제 발굴 | 그래프 순회→reason | 공격면↓ |
| 🔵 Blue(Defensive) | 실시간 탐지·조사·대응 | **Code분석 + Forensics 서브에이전트** | MTTR Hours→Minutes |
| 🟢 Green(Remediation) | 크리티컬→0 | Risk/Prioritization 컨텍스트 | Weeks→Days |

**우리 실험과의 매핑**
- **Blue = 서브에이전트 분해** → 우리 **Supervisor(#3)** 의 정당성을 직접 검증(역할별 적응 호출).
- **그래프가 기반(GraphRAG)** → 우리 Investigation은 flat RAG. 그래프 공격경로 기반 검색은
  corroboration 품질을 올릴 수 있는 **품질 축 확장(#5 GraphRAG-grounded)** 후보.
- **Red↔Blue↔Green 루프** → 우리는 선형 방어 체인. 부품(PyRIT red·RuleUpdate remediation)은
  보유 → 루프를 닫으면 상위 구조 확장 가능.
- **MTTR/confidence/우선순위 지표** → 우리 KPI 하니스(MTTT/MTTC/confidence/precision)와 정렬.

**확장 로드맵(품질 축)**
1. ✅ **구현·측정 완료** — Wiz Blue 서브에이전트 분해형(구조 4, 위 참조). 단, 쉬운 평가셋에선
   이득이 안 드러나 **어려운/적대적 평가셋이 다음 필수 단계**임을 확인.
2. GraphRAG-grounded Investigation (flat RAG → 공격경로 검색) — 품질 측정. (미구현)
3. Red↔Blue↔Green 폐루프(탐지→remediation→재공격→탐지 보강). (미구현)
