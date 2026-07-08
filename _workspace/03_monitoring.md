# CI/CD + AI-SOC + OSCAL 컴플라이언스 모니터링 설계

**작성자**: monitoring-specialist
**버전**: 1.0 (Phase 1, DORA + AI-SOC + OSCAL 통합)
**원칙**: 기존 ServiceMonitor/Grafana 재사용·확장 · 라벨 카디널리티 통제 · 알림 피로 방지 ·
추세 우선 · AnalysisTemplate 메트릭 이름 절대 불변
**선행 문서**: `00_input.md`, `01_pipeline_design.md`, `02_infra_config.md`,
`04_security_scan.md`, `04c_test_strategy.md`, `04d_ai_redteam.md`

---

## 0. 요약 (TL;DR)

| 구분 | 산출 |
|------|------|
| 메트릭 분류 | DORA 4 + AI-SOC 도메인 7 + G2 게이트 3 + OSCAL 4 + AI 레드팀 5 + 공급망 3 = **26종** |
| 알림 규칙 | 6 그룹 / **27개 알림** (critical 9, warning 16, info 2) |
| Grafana 대시보드 | 기존 `uav-soc-kpi` 유지 + 신규 4종 추가 (DORA, AI-SOC, Gates, OSCAL) |
| 수집 경로 | ServiceMonitor 5종 (hotpath/learning/toolserver/pushgateway/argocd) + nightly CronJob 1종 |
| 신규 코드 | `scripts/oscal_to_metrics.py` (검증 완료) |
| 신규 매니페스트 | 7종 (ServiceMonitor·PrometheusRule·대시보드 4·CronJob) |
| SLO | 5종 (P99 트리아지·가용성·RAGAS·OSCAL 비율·MTTR) |

> **OSCAL 메트릭 실측 검증 결과** (2026-06-29 빌드 기준):
> `controls=implemented:15 / partial:19 / planned:1` `poam_open=high:1, medium:19` `ratio=0.4286` —
> SLO 50% 미달, OSCAL 비율 알림(< 0.40) **임박 단계** (1건 추가 partial→planned 시 발화).

---

## 1. 메트릭 카탈로그 (4 + α 분류)

### 1.1 DORA 메트릭 4종

| 메트릭 | 타입 | 라벨 | 목표 | 출처 |
|--------|------|------|------|------|
| `deployment_frequency_total` | Counter | `environment` | 일 1회+ | GitHub Actions workflow_run exporter (cd-prod success) |
| `lead_time_for_changes_seconds_bucket` | Histogram | `environment` | P50 < 1일 | 동일 exporter (commit_time → ArgoCD sync_time) |
| `change_failure_total` | Counter | `environment` | 7일 누적 실패율 < 15% | cd-prod failure + Argo Rollouts abort |
| `mean_time_to_restore_seconds` | Gauge (24h 평균) | `environment` | < 1시간 | Alertmanager incident open → close |

### 1.2 AI-SOC 도메인 메트릭 7종 (앱 노출)

| 메트릭 | 타입 | 라벨 | 임계/SLO | 출처 |
|--------|------|------|---------|------|
| `agent_latency_seconds_bucket` | Histogram | `agent`, `phase`, `track` | hotpath P99 ≤ 2s | 앱 컨테이너 `:8080/metrics` |
| `llm_tokens_total` | Counter | `model`, `direction` (in/out), `deployment` | 추세 (예산) | 앱 |
| `llm_cost_usd_total` | Counter | `model`, `deployment` | 24h 비율 < 2배 | 앱 (토큰 × 단가 계산) |
| `triage_accuracy_ratio` | Gauge | `severity` | ≥ 0.85 | 앱 (TP 라벨 비교 결과) |
| `ragas_faithfulness_score` | Gauge | `component` (`triage`, `investigation`, `rule_update`) | 5분 평균 ≥ 0.80 / 일 평균 ≥ 0.85 | 앱 (인플라이트 평가) |
| `ragas_relevancy_score` | Gauge | `component` | 5분 평균 ≥ 0.80 | 앱 |
| `mttt_seconds_bucket` | Histogram | `track` | P99 ≤ 30s (트랙 A SLO) | 앱 (트리아지 시작→완료) |

### 1.3 G2 게이트 메트릭 3종 (Pushgateway — test-engineer §6 합의)

| 메트릭 | 타입 | 라벨 | 임계 | 출처 |
|--------|------|------|------|------|
| `g2_gate_pass_total` | Counter | `name` (gate 이름) | — | `benchmarks/check_gates.py` → Pushgateway |
| `g2_gate_fail_total` | Counter | `name`, `severity` (critical/high/medium) | critical 즉시 차단 | 동 |
| `g2_gate_value` | Gauge | `name` | 게이트별 임계 | 동 (게이트 측정값) |

> **계약**: `g2_summary.json` 의 `gates[].name|severity|value|passed` 를 nightly + cd-prod 가
> Pushgateway 로 push. 라벨 카디널리티 = 게이트 종류 한정(현재 5~7개).

### 1.4 OSCAL 컴플라이언스 메트릭 4종 (신규, nightly CronJob)

| 메트릭 | 타입 | 라벨 | 임계/SLO | 출처 |
|--------|------|------|---------|------|
| `oscal_controls_total` | Gauge | `status` (implemented/partial/planned), `framework` (`ai-rmf`) | implemented ↑ | `scripts/oscal_to_metrics.py` |
| `oscal_poam_open_total` | Gauge | `severity` (critical/high/medium/low), `framework` | critical=0, high≤3 | 동 |
| `oscal_compliance_ratio` | Gauge | `framework` | ≥ 0.50 | 동 (implemented / 채택 35) |
| `oscal_last_build_timestamp` | Gauge | `framework` | 36h 이내 | 동 (unix epoch) |

### 1.5 AI 레드팀 메트릭 5종 (Pushgateway — ai-redteam-engineer §7.3 합의)

| 메트릭 | 타입 | 라벨 | 임계 | 출처 |
|--------|------|------|------|------|
| `ai_redteam_ttp_fail_total` | Counter | `atlas_id`, `owasp_llm` | 0 목표 | `ai-redteam.yml` → Pushgateway |
| `ai_redteam_determinism_check` | Counter | `result` (pass/fail) | fail=0 | 동 (ATLAS 2회 SHA-256 비교) |
| `ai_redteam_regression_block_total` | Counter | — | =0 (회귀 무) | 동 (`passing_ttps.json` diff) |
| `ai_redteam_attack_success_rate` | Gauge | `vector` (memory_poison/prompt_inject/sev_downgrade) | ≤ 0.05 | 동 |
| `garak_probe_fail_rate` | Gauge | `probe` (promptinject/dan/latentinjection) | ≤ 0.05 | 동 |

### 1.6 공급망 무결성 메트릭 3종 (Pushgateway — security-scanner 인계)

| 메트릭 | 타입 | 라벨 | 임계 | 출처 |
|--------|------|------|------|------|
| `supply_chain_unsigned_image_total` | Counter | — | =0 | Kyverno verifyImages admission (audit) |
| `supply_chain_sbom_missing_total` | Gauge | — | =0 | `release-signing.yml` 결과 push |
| `slsa_provenance_level` | Gauge | — | ≥ 2 (목표 3) | 동 |

### 1.7 보조 메트릭 — 기존 유지

기존 `grafana-dashboard.yaml` 에 정의된 `soc_attack_coverage_ratio`,
`soc_attack_addressable_ratio`, `soc_attack_gap_total`, `soc_verdict_total`,
`soc_alerts_total`, `soc_node_latency_avg_ms`, `soc_attack_tactic_uncovered` 는
**유지**. AI-SOC Operations 대시보드의 verdict 패널에서 재사용.

---

## 2. 메트릭 출처·수집 방법 매트릭스

| 분류 | 메트릭 | 출처 | 수집 방법 | 라벨 |
|------|--------|------|----------|------|
| AI-SOC 도메인 | `agent_latency_seconds_bucket` 외 6 | 앱 컨테이너 `:8080/metrics` | ServiceMonitor → Prometheus 30s | track, agent, phase, model, component |
| AI-SOC 기존 | `soc_*` 7 | 앱 컨테이너 | ServiceMonitor (위와 동일 endpoint) | tactic, archetype, verdict, node |
| G2 게이트 | `g2_gate_*` 3 | `benchmarks/check_gates.py` (PR/cd-prod/nightly) | GitHub Actions step → Pushgateway HTTP push | name, severity |
| OSCAL | `oscal_*` 4 | `scripts/oscal_to_metrics.py` (nightly CronJob 02:00 KST + cd-prod) | CronJob → `prometheus_client.push_to_gateway()` → Pushgateway | status, severity, framework |
| AI 레드팀 | `ai_redteam_*` 5, `garak_probe_fail_rate` | `ai-redteam.yml` (PR/nightly/cd-prod 사전) | GitHub Actions step → Pushgateway | atlas_id, owasp_llm, vector, probe, result |
| 공급망 | `supply_chain_*`, `slsa_provenance_level` | `release-signing.yml`, Kyverno admission | GitHub Actions step + Kyverno reporter | — |
| DORA | `deployment_frequency_total`, `lead_time_*`, `change_failure_total` | GitHub workflow_run + ArgoCD `argocd_app_sync_total` + Argo Rollouts `analysis_run_metric_phase` | ServiceMonitor (argocd + rollouts) + GitHub exporter | environment, phase, metric |
| DORA MTTR | `mean_time_to_restore_seconds` | Alertmanager API (incident open→close) | Pushgateway exporter (별도 CronJob) | environment |
| 카나리 분석 | `analysis_run_metric_phase` 등 | argo-rollouts metrics | ServiceMonitor (argo-rollouts) | rollout, metric, phase |
| 플레이키 | `pytest_flaky_total`, `pytest_quarantine_total` | `ci.yml` test step | Pushgateway | — |

### 2.1 ServiceMonitor 5종 (`servicemonitor.yaml`)

| 이름 | namespaceSelector | selector | interval | metricRelabelings keep |
|------|-------------------|----------|----------|------------------------|
| `soc-hotpath` | `dah-soc` | `app.kubernetes.io/name=soc-hotpath, monitoring=enabled` | 30s | http_*, agent_latency_*, llm_*, triage_*, ragas_*, mttt_*, soc_* |
| `soc-learning` | `dah-soc` | `app.kubernetes.io/name=soc-learning` | 60s | (전체 — 버스티) |
| `soc-kagent-toolserver` | `dah-soc` | `app.kubernetes.io/name=kagent-toolserver` | 30s | (기본) |
| `soc-pushgateway` | `monitoring` | `app.kubernetes.io/name=prometheus-pushgateway` | 60s + honorLabels=true | g2_*, oscal_*, ai_redteam_*, garak_*, supply_chain_*, slsa_*, dora |
| `soc-argocd-metrics` | `argocd` | `argocd-application-controller` | 30s | argocd_app_sync_total, argocd_app_info, argocd_app_health_status |
| `soc-argo-rollouts` | `argo-rollouts` | `argo-rollouts` | 30s | rollout_*, analysis_run_*, experiment_info |

> **라벨 카디널리티 통제**: 화이트리스트 외 메트릭은 `metricRelabelings.action=keep` 으로 drop.
> 사용자/세션/alert-id 라벨 금지 — `track`, `agent`, `phase`, `model`, `direction`, `component`,
> `severity`, `framework`, `status` 만 허용.

---

## 3. 알림 규칙 (PrometheusRule CRD)

### 3.1 알림 매트릭스 (총 27개, 6 그룹)

| 그룹 | 알림 | 임계 | for | severity | 채널 | runbook |
|------|------|------|-----|----------|------|---------|
| **ci-cd-pipeline** | CIBuildFailureRateHigh | 1h 실패율 ≥ 10% | 30m | warning | #ci | runbooks/ci-build-failure.md |
| | CIBuildFailureRateCritical | 30m 실패율 ≥ 30% | 15m | critical | #ops-critical | 동 |
| | CDProdDeploymentFailed | cd-prod failure ≥ 1 | 0m | critical | #ops-critical + PagerDuty | runbooks/cd-prod-failure.md |
| | CanaryRollbackOccurred | `analysis_run_metric_phase=Failed` ≥ 1 | 0m | warning | #deploy | runbooks/canary-rollback.md |
| | DeploymentFrequencyDrop | 24h 배포 0건 | 6h | warning | #ci | — |
| | MTTRBudgetExceeded | 1일 평균 MTTR > 3600s | 0m | warning | #ops-critical | — |
| **g2-regression** | G2GateCriticalFailure | `g2_gate_fail_total{severity="critical"}` 증가 | 0m | critical | #ops-critical | runbooks/g2-regression.md |
| | G2GateHighFailure | `g2_gate_fail_total{severity="high"}` 증가 (1h) | 0m | warning | #ai-quality | 동 |
| | G2RecallDegrading | `g2_gate_value{name="kpi_recall"}` < 0.85 30m | 30m | warning | #ai-quality | — |
| | G2FPRecurrenceHigh | FP 재발률 > 0.05 1h | 30m | warning | #ai-quality | — |
| **ai-redteam** | AIRedTeamRegressionDetected | `ai_redteam_regression_block_total` 증가 | 0m | critical | #ops-critical + PagerDuty | runbooks/ai-redteam-regression.md |
| | AIRedTeamDeterminismViolation | `ai_redteam_determinism_check{result="fail"}` 증가 | 0m | critical | #ops-critical | — |
| | AIRedTeamNewTTPFailure | `ai_redteam_ttp_fail_total` 1h 증가 | 0m | warning | #security | — |
| | GarakProbeFailRateHigh | `garak_probe_fail_rate` > 0.05 6h max | 30m | warning | #security | — |
| **oscal-compliance** | OSCALPOAMCriticalOpen | `oscal_poam_open_total{severity="critical"}` > 0 | 0m | critical | #compliance + Slack #ops | runbooks/oscal-poam-block.md |
| | OSCALPOAMHighOver3 | `oscal_poam_open_total{severity="high"}` > 3 | 30m | critical | #compliance | 동 |
| | OSCALComplianceRatioLow | `oscal_compliance_ratio` < 0.40 | 1h | warning | #compliance | — |
| | OSCALBuildStale | 마지막 빌드 > 36h | 0m | warning | #compliance | — |
| **ai-soc-runtime** | HotpathAgentLatencyP99High | `agent_latency p99` > 5s 5분 | 5m | warning | #ai-quality | — |
| | TriageMTTTHigh | `mttt_seconds` P99 > 30s | 10m | warning | #ai-quality | — |
| | LLMCostBurstHigh | 1h 비용 / 24h offset > 2배 | 30m | warning | #ai-quality | — |
| | RAGASFaithfulnessLow | 5분 평균 < 0.80 | 5m | warning | #ai-quality | — |
| | RAGASRelevancyLow | 5분 평균 < 0.80 | 5m | warning | #ai-quality | — |
| | TriageAccuracyRegress | 1h 평균 < 0.85 | 30m | warning | #ai-quality | — |
| | HotpathAvailabilitySLO | 1h 5xx > 0.5% | 30m | warning | #ops-critical | — |
| **supply-chain** | UnsignedImageDeployAttempt | `supply_chain_unsigned_image_total` 증가 | 0m | critical | #security + PagerDuty | — |
| | SBOMMissingHigh | `supply_chain_sbom_missing_total` > 0 | 30m | warning | #security | — |
| | SLSAProvenanceDowngrade | `slsa_provenance_level` < 2 | 0m | critical | #security | — |

### 3.2 알림 라우팅 (Alertmanager) 및 피로 방지

| severity | 1차 채널 | 2차 (page) | silence 가능 시간 |
|----------|----------|------------|-------------------|
| critical | Slack `#ops-critical` + PagerDuty (선택적) | on-call | 즉시 page, 1시간 silence |
| warning | Slack 분야별(`#ai-quality` / `#compliance` / `#security` / `#deploy` / `#ci`) | 없음 | 4시간 silence |
| info | Slack 로그만 | 없음 | 24시간 silence |

**피로 방지 원칙**:

1. 모든 알림에 `runbook_url` 또는 명확한 description 첨부 (액션 가능).
2. `for:` 절로 노이즈 차단 (5분 이상 지속만 발화 — RAGAS/지연/Recall 등).
3. 동일 그룹 내 묶음 (`group_by: ['alertname','severity','channel']`).
4. 가용성/RAGAS/지연 등 추세성 알림은 **추세 패널 확인 후 발화**(낮은 빈도).
5. `OSCAL` 그룹 알림은 `compliance` 채널 분리 — 운영 채널 노이즈 방지.

---

## 4. Grafana 대시보드 설계 (기존 1 + 신규 4)

### 4.1 기존 — `uav-soc-kpi` (보존)

`deploy/monitoring/grafana-dashboard.yaml` — ATT&CK 커버리지, archetype별 갭, verdict 비율,
경보 처리율, 노드 평균 지연. **변경 없음**. AI-SOC Operations 대시보드에서 verdict 패널을
재사용 (cross-link).

### 4.2 신규 1 — DORA Dashboard (`grafana-dashboard-dora.yaml`)

| 패널 | 종류 | 쿼리 |
|------|------|------|
| 배포 빈도 24h | stat | `sum(increase(deployment_frequency_total[24h]))` |
| 변경 리드타임 P50/P95 | stat | `histogram_quantile(...)` over 24h |
| 변경 실패율 7d | stat | `change_failure_total / deployment_frequency_total` |
| MTTR 24h 평균 | stat | `avg_over_time(mean_time_to_restore_seconds[24h])` |
| 배포 추세 (일별) | timeseries | success / failure 분리 |
| Canary abort 카운트 | timeseries | `analysis_run_metric_phase{phase="Failed"}` |
| ArgoCD sync (성공/실패) | timeseries | `argocd_app_sync_total` by phase |

### 4.3 신규 2 — AI-SOC Operations (`grafana-dashboard-ai-soc.yaml`)

| 패널 | 핵심 메트릭 |
|------|------------|
| Agent Latency P99 by Phase | `agent_latency_seconds_bucket` (track variable) |
| MTTT P50/P95/P99 | `mttt_seconds_bucket` |
| LLM Tokens by model | `llm_tokens_total{direction}` |
| LLM Cost USD/h by model | `llm_cost_usd_total` |
| Triage Accuracy by severity | `triage_accuracy_ratio` |
| RAGAS Faithfulness by component | `ragas_faithfulness_score` |
| RAGAS Relevancy by component | `ragas_relevancy_score` |
| Verdict 추세 (TP/FP/IR/Esc) | `soc_verdict_total` (기존 메트릭 재사용) |
| 5xx 비율 (SLO 시각화) | `http_requests_total` |

### 4.4 신규 3 — Gates Dashboard (`grafana-dashboard-gates.yaml`)

| 패널 | 핵심 메트릭 |
|------|------------|
| G2 통과/실패 7d | `g2_gate_pass_total` / `g2_gate_fail_total` |
| G2 실패 분포 by severity | piechart `g2_gate_fail_total` |
| AI 레드팀 결정론 회귀 (=0 정상) | `ai_redteam_regression_block_total` |
| G2 게이트 값 추세 | `g2_gate_value{name=...}` (precision/recall/FP/RAGAS) |
| AI 레드팀 TTP별 실패 | bargauge `ai_redteam_ttp_fail_total` |
| AI 레드팀 공격 성공률 by vector | `ai_redteam_attack_success_rate` |
| Garak Probe Fail Rate | `garak_probe_fail_rate` |
| 공급망 무결성 (table) | `supply_chain_*`, `slsa_provenance_level` |
| 플레이키 테스트 추세 | `pytest_flaky_total`, `pytest_quarantine_total` |

### 4.5 신규 4 — OSCAL Compliance (`grafana-dashboard-oscal.yaml`)

| 패널 | 핵심 메트릭 |
|------|------------|
| 컴플라이언스 비율 (현재) | `oscal_compliance_ratio` (목표 ≥ 0.50) |
| 통제 상태 분포 (도넛) | `oscal_controls_total{status=...}` |
| POAM Open by Severity | `oscal_poam_open_total` (critical/high/medium/low) |
| 컴플라이언스 비율 시계열 30일 | `oscal_compliance_ratio` |
| 통제 상태 추세 | `oscal_controls_total` |
| POAM Open 추세 | `oscal_poam_open_total` |
| 마지막 빌드 시각 | `oscal_last_build_timestamp` |
| 관련 링크 (text) | OSCAL repo, POAM JSON, runbook, SLO 가이드 |

---

## 5. SLO 정의

| 항목 | SLO | 측정 | 위반 시 |
|------|-----|------|--------|
| 트리아지 처리 시간 P99 (트랙 A) | ≤ 30s | `mttt_seconds_bucket{track="hotpath"}` | TriageMTTTHigh 알림 + AI 팀 검토 |
| 가용성 (hotpath) | ≥ 99.5% | 5xx 비율 ≤ 0.5% | HotpathAvailabilitySLO + RCA |
| RAGAS faithfulness 일 평균 | ≥ 0.85 | `avg_over_time(ragas_faithfulness_score[1d])` | RAGASFaithfulnessLow + 모델/RAG 재튜닝 |
| OSCAL 컴플라이언스 비율 | ≥ 0.50 (점진 상향) | `oscal_compliance_ratio` | OSCALComplianceRatioLow (40% 미만 시) + 거버넌스 |
| 카나리 자동 롤백 MTTR | ≤ 5분 | abort → revert merge 시간 | RCA + 임계 재조정 |
| 파이프라인 가용성 | ≥ 99.5% | GitHub Actions 성공률 | CIBuildFailureRateHigh + 점검 |
| 배포 성공률 | ≥ 99% | cd-prod success / total | CDProdDeploymentFailed + RCA |

> **현재 OSCAL 비율**: 0.4286 (15/35). SLO 50% 미충족. 4건 추가 partial→implemented 시 SLO 충족.

---

## 6. AnalysisTemplate 정합 검증

infra-engineer 산출물 `_workspace/02_pipeline_config/deploy/k8s/analysistemplates/
hotpath-success-rate-latency.yaml` 의 5종 메트릭과 본 설계의 정합:

| AnalysisTemplate 메트릭 | 본 설계 정합 | 검증 |
|------------------------|------------|------|
| `http_requests_total{job="soc-hotpath",code=~"5.."}` | ServiceMonitor relabeling 으로 `job=soc-hotpath` 강제 | OK |
| `http_request_duration_seconds_bucket{job="soc-hotpath"}` | 동일 ServiceMonitor scrape | OK |
| `agent_latency_seconds_bucket{job="soc-hotpath"}` | metricRelabelings keep 화이트리스트 포함 | OK |
| `kube_pod_container_status_restarts_total{namespace="dah-soc",pod=~"soc-hotpath-.*"}` | kube-state-metrics 가 노출 (kube-prometheus-stack 기본) | OK — 별도 ServiceMonitor 불요 |
| `ragas_faithfulness_score{job="soc-hotpath"}` | 화이트리스트 포함 — **앱 노출 필수** | **앱 노출 요청 필요** (§9) |

**AnalysisTemplate 메트릭 이름 절대 불변** — 본 설계의 어떤 산출물도 위 쿼리 라벨/이름을
변경하지 않는다. 변경이 필요한 경우 AnalysisTemplate 우선 PR 후 본 산출물 갱신.

---

## 7. OSCAL 컴플라이언스 게이트 ↔ 모니터링 연동

### 7.1 흐름

```
[02:00 KST nightly]                  [push main → cd-prod 사전]
       │                                    │
       ▼                                    ▼
oscal-metrics-export CronJob       cd-prod step
  (deploy/monitoring/                "OSCAL 메트릭 갱신"
   oscal-export-cronjob.yaml)         (compliance.yml 호출 후
       │                              scripts/oscal_to_metrics.py)
       ▼                                    │
build_oscal.py 실행                          │
  (compliance/oscal/ JSON 갱신)              │
       │                                    │
       ▼                                    │
oscal_to_metrics.py                         │
  ├── parse_ssp (15/19/1)                   │
  ├── parse_poam (open by severity)         │
  ├── compliance_ratio (0.4286)             │
  └── last_build_timestamp                  │
       │                                    │
       ▼                                    ▼
prometheus-pushgateway.monitoring:9091
       │ (ServiceMonitor soc-pushgateway scrape, honorLabels=true)
       ▼
Prometheus  ←  oscal_compliance_ratio < 0.40 → AlertManager → #compliance
Grafana    ←  oscal-dashboard 패널 7종
```

### 7.2 알림 변화 → Slack/Teams

| 이벤트 | 알림 | 메시지 |
|--------|------|--------|
| 신규 critical POAM (=0 위반) | OSCALPOAMCriticalOpen | "critical 1건 발생 → cd-prod 차단" |
| high POAM > 3 | OSCALPOAMHighOver3 | "high 4건 — 방산 임계 초과" |
| critical → closed 전환 | (역방향 알림 미설정) | Grafana 시계열 추세로 확인 (대시보드 패널 6) |
| 36h 미빌드 | OSCALBuildStale | "CronJob 점검" |

> **양방향 알림은 의도적으로 미설정** — closed/resolved 는 추세 대시보드(Grafana) 와 PR 머지
> 코멘트로 충분히 가시화. 알림 노이즈 방지.

### 7.3 대시보드 ↔ PR 연결

OSCAL 대시보드 "관련 링크" 패널이 `pulls?q=is%3Apr+label%3Acompliance` 검색으로 최근 변경 PR
링크 제공. AI 레드팀 nightly 가 생성한 compliance 라벨 PR 도 자동 노출.

---

## 8. 산출물 일람

| 경로 | 종류 | 상태 |
|------|------|------|
| `_workspace/03_monitoring.md` | 본 설계 문서 | 작성 완료 |
| `_workspace/02_pipeline_config/deploy/monitoring/servicemonitor.yaml` | ServiceMonitor 6종 (강화) | 작성 완료 |
| `_workspace/02_pipeline_config/deploy/monitoring/prometheusrule.yaml` | PrometheusRule 6 그룹 27 알림 | 작성 완료 |
| `_workspace/02_pipeline_config/deploy/monitoring/grafana-dashboard-dora.yaml` | DORA 대시보드 | 작성 완료 |
| `_workspace/02_pipeline_config/deploy/monitoring/grafana-dashboard-ai-soc.yaml` | AI-SOC Operations 대시보드 | 작성 완료 |
| `_workspace/02_pipeline_config/deploy/monitoring/grafana-dashboard-gates.yaml` | G2 + AI 레드팀 + 공급망 대시보드 | 작성 완료 |
| `_workspace/02_pipeline_config/deploy/monitoring/grafana-dashboard-oscal.yaml` | OSCAL 컴플라이언스 대시보드 | 작성 완료 |
| `_workspace/02_pipeline_config/deploy/monitoring/oscal-export-cronjob.yaml` | nightly OSCAL CronJob + ServiceAccount | 작성 완료 |
| `_workspace/02_pipeline_config/scripts/oscal_to_metrics.py` | OSCAL → Prometheus 변환기 | **작성 완료 + 실측 검증 통과** |

### 8.1 실측 검증

```text
$ python3 _workspace/02_pipeline_config/scripts/oscal_to_metrics.py \\
    --oscal-dir compliance/oscal --textfile /tmp/oscal.prom
[INFO] 수집 결과: controls={'implemented': 15, 'partial': 19, 'planned': 1}
                  poam_open={'critical': 0, 'high': 1, 'medium': 19, 'low': 0}
                  ratio=0.4286
[INFO] textfile 출력: /tmp/oscal.prom

oscal_controls_total{status="implemented",framework="ai-rmf"} 15
oscal_controls_total{status="partial",framework="ai-rmf"} 19
oscal_controls_total{status="planned",framework="ai-rmf"} 1
oscal_poam_open_total{severity="critical",framework="ai-rmf"} 0
oscal_poam_open_total{severity="high",framework="ai-rmf"} 1
oscal_poam_open_total{severity="medium",framework="ai-rmf"} 19
oscal_poam_open_total{severity="low",framework="ai-rmf"} 0
oscal_compliance_ratio{framework="ai-rmf"} 0.428571
oscal_last_build_timestamp{framework="ai-rmf"} 1782659382
```

> 04_security_scan.md §3.4 실측치(critical=0, high=1, partial=19)와 정확히 일치.

---

## 9. 앱 측에 노출 요청해야 할 메트릭 (application engineer 협업 필요)

본 설계의 모니터링 매니페스트는 다음 메트릭이 **앱 컨테이너 `:8080/metrics` 에서 노출됨을
가정**한다. 미노출 시 AnalysisTemplate·알림·대시보드 다수가 결손된다.

| 메트릭 | 라벨 | 출처 권장 | 우선순위 |
|--------|------|-----------|---------|
| `http_requests_total` | `code`, `method`, `path` (path 카디널리티 통제 필요) | FastAPI middleware (prometheus_fastapi_instrumentator) | **최상** (AnalysisTemplate 의존) |
| `http_request_duration_seconds_bucket` | 동 | 동 | **최상** |
| `agent_latency_seconds_bucket` | `agent`, `phase`, `track` | LangGraph 노드 래퍼 (직접 instrumentation) | **최상** (AnalysisTemplate 의존) |
| `ragas_faithfulness_score` | `component` | 인플라이트 평가 모듈 (별도 작업) | **최상** (AnalysisTemplate 의존) |
| `ragas_relevancy_score` | `component` | 동 | 상 |
| `llm_tokens_total` | `model`, `direction`, `deployment` | Azure OpenAI 응답 wrapper | 상 |
| `llm_cost_usd_total` | `model`, `deployment` | 동 (`tokens × 단가`) | 상 |
| `triage_accuracy_ratio` | `severity` | TP/FP 라벨 비교 결과 (지연 측정 — 일/시간 단위 갱신) | 중 |
| `mttt_seconds_bucket` | `track` | 트리아지 시작→완료 측정 | 상 |

**제안 — 별도 작업으로 분리**:

1. `core/observability/metrics.py` 모듈 신규 — 앱 전역에서 임포트.
2. `prometheus_client` 의존 추가 (`pyproject.toml` `[project.dependencies]`).
3. `agents/base.py` 의 `run()` 데코레이터에 자동 `agent_latency_seconds` 측정 주입.
4. `core/llm/wrapper.py` 에서 `llm_tokens_total`/`llm_cost_usd_total` 측정.
5. RAGAS 평가는 `core/evaluation/inflight_ragas.py` 별도 작업 — sample rate 10% 권장.

이 노출 작업은 본 작업 범위를 넘어선다. **별도 application-engineer 영역 PR** 로 분리.

---

## 10. 팀 통신 — 수신/송신 매트릭스

### 수신 (다른 에이전트로부터)

| 출처 | 받은 정보 | 반영 위치 |
|------|----------|----------|
| pipeline-designer | AnalysisTemplate 5종 임계, Slack 채널 컨벤션 | PrometheusRule, 대시보드 임계 |
| infra-engineer | Service 라벨 (`monitoring: enabled`), AnalysisTemplate 위치, Prometheus 주소 | ServiceMonitor 정합 |
| test-engineer §6, 7 | `g2_summary.json` Pushgateway 메트릭 정의(`g2_gate_pass/fail_total`, `g2_gate_value`) | servicemonitor pushgateway keep 리스트, gates 대시보드, g2-regression 알림 |
| security-scanner | OSCAL 게이트 흐름, POAM 임계(critical=0, high≤3), 공급망 무결성 메트릭, `check_poam_thresholds.py` 호환 | OSCAL 알림, oscal_to_metrics.py 의 SEVERITY_ALIASES/CLOSED_TRACKING_KEYWORDS |
| ai-redteam-engineer §7.3 | `ai_redteam_*`, `garak_probe_fail_rate`, 라벨(ttp, vector, mode, regression) | servicemonitor pushgateway keep, ai-redteam 알림, gates 대시보드 |

### 송신 (pipeline-reviewer 에게)

다음 절(§11) 참조.

---

## 11. pipeline-reviewer 점검 항목 (5개)

1. **AnalysisTemplate 메트릭 라벨 정합** — `servicemonitor.yaml` 의 `relabelings` 가
   `job=soc-hotpath` 를 강제하고, `metricRelabelings` keep 화이트리스트에 5종 메트릭
   (`http_requests_total`, `http_request_duration_seconds_bucket`,
   `agent_latency_seconds_bucket`, `ragas_faithfulness_score`, kube-state-metrics 의
   `kube_pod_container_status_restarts_total`) 가 모두 포함되어 있는지 검증. 누락 시
   Canary 자동 분석 무력화 — 단일 실패점.

2. **앱 측 메트릭 노출 의존성** — `agent_latency_seconds_bucket`, `ragas_faithfulness_score`,
   `mttt_seconds_bucket`, `llm_tokens_total`, `llm_cost_usd_total`, `triage_accuracy_ratio` 가
   현재 앱(`agents/`, `core/`)에서 미노출 가능성. §9 "앱 측 노출 요청" 목록을 별도
   application-engineer PR 로 분리할지, 본 모니터링 산출물의 일부로 stub instrumentation
   을 포함할지 결정.

3. **Pushgateway 신설 의존성** — 본 설계는 `monitoring` 네임스페이스에
   `prometheus-pushgateway` 가 이미 설치되어 있다고 가정. kube-prometheus-stack 의
   subchart 로 활성화 또는 별도 Helm install 필요. ArgoCD Application 추가 PR 가 별도로
   필요한지 infra-engineer 와 확인.

4. **라벨 카디널리티 통제 효과** — `metricRelabelings.keep` 화이트리스트가 너무 좁아
   `soc_*` 기존 메트릭 일부(예: `soc_attack_tactic_uncovered` 의 `tactic` 라벨,
   `soc_verdict_total` 의 `verdict` 라벨)가 의도와 다르게 drop 되지 않는지 확인. 첫 배포
   직후 `up{job=~"soc-.*"}` 와 `topk(20, count by (__name__)(...))` 로 실측 확인 필요.

5. **OSCAL CronJob 의 이미지 의존성** — `oscal-export-cronjob.yaml` 가
   `ghcr.io/s1ns3nz0/uav-ai-soc:prod` 이미지 안에 `compliance/oscal/build_oscal.py` 와
   `scripts/oscal_to_metrics.py` 가 모두 포함됨을 가정. Dockerfile 의 COPY 가 `scripts/`
   디렉토리를 포함하는지 검증 (현재 `_workspace/02_pipeline_config/deploy/Dockerfile`
   확인). 누락 시 ConfigMap 마운트 또는 별도 sidecar 빌드 결정.

---

## 12. 보류·결정 필요 사항

| # | 항목 | 결정 주체 |
|---|------|---------|
| 1 | 앱 측 메트릭 노출 별도 PR 분리 vs 본 작업 stub 포함 | application-engineer + pipeline-reviewer |
| 2 | Pushgateway 설치 — kube-prometheus-stack subchart vs 별도 Application | infra-engineer |
| 3 | OSCAL 비율 SLO 50% 도달 로드맵 (현재 0.4286, 추가 4건 partial→implemented 필요) | governance |
| 4 | DORA 의 `deployment_frequency_total` 등을 노출할 GitHub Actions exporter 도구 (`cdevents` vs custom Pushgateway step) | infra-engineer |
| 5 | Alertmanager → PagerDuty 통합 시점 | 사용자 |
| 6 | OSCAL 대시보드의 "최근 변경 PR" 패널을 정적 링크가 아닌 GitHub plugin 으로 동적화 | 옵션 |

---

**문서 끝.**
