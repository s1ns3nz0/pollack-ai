# 분석 엔진 배선 — cato/diamond/bda 를 파이프라인에 연결(dead code → live)

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-08 |
| 상태 | Approved (구현 완료, Codex diff 검증 대기) |
| 작성자 | s1ns3nz0 |
| 근거 | 고도화 감사 — cato/diamond/bda assessor 가 만들어졌으나 **실호출부 0**(dead code) |
| base | `feat/inbound-trust-boundary`(스택 최상단) |

## 1. 배경 & 동기
`CatoAssessor`·`DiamondAnalyzer`·`BdaAssessor` 는 테스트만 있고 파이프라인에서 안 돌았다.
각 통합지점이 다르다(신호 성격 상이) — per-alert(diamond) vs aggregate(cato) vs
post-observation(bda). 각자 맞는 표면에 배선한다.

## 2. 배선
| 엔진 | 표면 | 근거 |
|---|---|---|
| **diamond** | ReportAgent → `SOCReport.diamond` | per-alert 4정점 사상(mission_risk 동형, actor 프로필 접근 재사용) |
| **cato** | app/metrics.py `_cato_metrics()` | BAS 이미 여기서 돎 — BAS+SLO aggregate → 인가 게이지 |
| **bda** | OutcomeProbeAgent `_assess_bda` | effect(ProbeDecision)+obs 가 워커에 존재 — 피해평가·복구권고 로깅 |

## 3. 상세
- **diamond**: `ReportAgent.__init__(diamond=DiamondAnalyzer())`, `_build_diamond(alert)` 가
  actor 프로필 회상 후 `build`. graph 가 `DiamondAnalyzer()` 주입. 미주입 시 None(무영향).
- **cato**: `_cato_metrics()` = BASRunner.run + SLOMonitor.evaluate(collect_snapshot) →
  CatoAssessor.assess → `soc_cato_authorization`(0/1/2) + `soc_cato_poam_total`. SBOM 은
  per-alert 라 제외. 로드 실패 시 빈 목록(스크레이프 graceful, 기존 _bas_metrics 패턴).
- **bda**: worker 루프에서 `BdaAssessor.assess(decision.effect, obs)`, 피해 있으면 로깅,
  복구권고 수를 사이클 집계. 기본 배선(미주입도 자동 생성).

## 4. 트러스트/견고성
- 전부 읽기전용 산출. diamond 는 순수함수, cato 는 신뢰 내부신호 aggregate, bda 는
  신뢰 관측 기반. 정책/의존 부재 시 graceful(None/빈목록).

## 5. 테스트 (`tests/__tests__/test_wire_analysis_engines.py`)
- diamond: graph end-to-end → report.diamond 노출(victim/capability/infra 정점).
- cato: `_cato_metrics()` 게이지 방출 + 의존실패 graceful.
- bda: worker 사이클 BDA 계산 정상 + 기본 배선.

## 5.1 Codex diff 검증 반영
- **Medium 중복 recall**: report 노드가 profile 을 5회(coa·diamond·campaign·recovery·
  pb_scores) 회상하던 걸 **run() 1회 회상 → 전 helper 전달**로 통합(`_recall_profile`).
  RAGFlow 백엔드 시 네트워크 호출 5→1. diamond 는 순수 build 라 async 불필요(동기 전환).
- **Medium BDA 예외 격리**: `_assess_bda` 를 try/except(SOCPlatformError/ValueError/
  TypeError)로 감싸 워커 사이클 보호 — 다른 gate 제출과 동일 방침(errors 누적).
- **Low 순환(metrics↔monitoring)**: lazy(함수내 import)라 크래시 없음 + 기존 `_bas_metrics`
  동일 패턴 → 수용.

## 6. 롤아웃
1. SOCReport.diamond + ReportAgent/graph 배선.
2. _cato_metrics + OutcomeProbeAgent._assess_bda.
3. Codex diff 검증 → black/ruff/mypy/pytest(652).
4. 브랜치 `feat/wire-analysis-engines`, 커밋 `feat(wiring): cato/diamond/bda 파이프라인 배선(dead→live)`.
