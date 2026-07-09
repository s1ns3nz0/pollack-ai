# ZTMM self-attested 통제 매핑 — NIST 800-207 / CISA ZTMM 2.0

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-09 |
| 상태 | Approved (Codex Crit+2H+2M+L 반영 → 구현) |
| 근거 | NIST 800-207, CISA Zero Trust Maturity Model 2.0(2023-04): 5 기둥 + 3 교차역량, 4 성숙도 |
| base | main(CI green) |

## 1. 배경 & 동기
플랫폼이 다수 ZT 통제를 구현했으나 ZTMM 정형 매핑이 없다. 단 **측정이 아닌 self-attested
선언**이므로(근거 없이 advanced/optimal 주장 = 거버넌스 씨어터 위험, Codex Crit) —
**auditable evidence 를 강제**하는 self-attested 통제 매핑으로 설계한다. "측정된 posture"가
아님을 라벨로 명시(measurement_status="not_measured").

## 2. 목표 / 비목표
### 목표
- `core/zero_trust.py` — 결정론 self-attested 매핑(자문·읽기전용):
  - 정책 `zt-maturity.yaml`: 항목별 {name, kind(pillar|cross_cutting), declared_maturity,
    control_ref(실제 구현 경로), evidence(verified_runtime|implemented_static|self_attested)}.
  - **evidence-gated(Crit)**: declared 가 advanced/optimal(≥2)인데 evidence=self_attested 면
    **effective_maturity 를 initial 로 cap** + `unverified_maturity_claim` finding. verified/
    implemented 근거 있으면 declared 인정. → 근거 없는 고등급 주장 봉쇄.
  - `ZtAttestation(name, kind, declared, effective, control_ref, evidence)`.
  - `ZtMapping(capabilities, minimum_declared, minimum_effective, findings, measurement_status,
    assessment_basis)` — **단일 overall 없음(H1)**, 기둥/교차역량별 matrix + 보수적 rollup은
    `minimum_effective`(사슬 최약, "overall" 아님).
- **5 기둥 + 3 교차역량 분리(Med)**: kind 로 구분(8 pillars 라 안 부름).
- metric `ztmm_self_attested_*` — cato/cpcon 과 네임스페이스 분리(거버넌스 context, severity/
  authorization/CPCON 아님). report 노출: 정적 1회 캐시(AIBOM 패턴).
### 비목표
- 자동 측정(telemetry-backed) — 별. PDP/PEP 시행. 성숙도 자동 격상.

## 3. 트러스트/견고성
- 결정론·읽기전용·자문. **정직 라벨**(self_attested/not_measured — overclaim 방지, H2/H3).
- **씨어터 방지(Crit)**: 근거 없는 advanced/optimal → effective cap + finding(거버넌스 감사).
- graceful(Low): 정책 실패 → "ztmm_assessment_unavailable" finding + metric(정상 아님, AIBOM M-b).

## 4. 설계
- 성숙도 순서값: traditional=0/initial=1/advanced=2/optimal=3.
- evidence-gate: effective = declared, 단 declared≥advanced and evidence==self_attested →
  effective=initial. minimum_effective = min(effective 전체).
- 정책 8 항목(정직 매핑): Identity(actor gates, implemented), Applications&Workloads(인젝션가드
  +inbound-trust, implemented), Data(AIBOM+SBOM, implemented), Visibility(metrics+SLO,
  implemented), Automation(LangGraph+BAS, implemented), Governance(cATO+OSCAL, implemented),
  Devices(자산tier, self_attested initial), Networks(self_attested initial).

## 5. 테스트
- pillar/cross_cutting 분리, evidence-gate(self_attested advanced→effective initial+finding),
  verified 근거→declared 유지, minimum_effective=최약, measurement_status 라벨, graceful degraded.

## 6. 롤아웃
1. 모델 + core/zero_trust.py + 정책 + metric + report 배선 + 테스트. 2. Codex → 게이트.
