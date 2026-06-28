# KPI 모니터링 — Prometheus + Grafana

`/metrics`(Prometheus 텍스트) → ServiceMonitor 스크레이프 → Prometheus → Grafana
대시보드. 전부 ArgoCD GitOps 로 배포(로드맵 5).

## 노출 메트릭 (`app/metrics.py`, `/metrics`)

| 메트릭 | 타입 | 라벨 | 의미 |
|---|---|---|---|
| `soc_alerts_total` | counter | — | 처리된 경보 수 |
| `soc_verdict_total` | counter | `verdict` | 판정별(정탐/오탐) 수 |
| `soc_node_latency_avg_ms` | gauge | `node` | 파이프라인 노드 평균 지연(MTTT/MTTC 원천) |
| `soc_attack_coverage_ratio` | gauge | — | ATT&CK 커버리지 비율 |
| `soc_attack_addressable_ratio` | gauge | — | 대응가능 커버리지(pre-compromise 제외) |
| `soc_attack_technique_total` | gauge | `status` | covered/planned/uncovered 기법 수 |
| `soc_attack_gap_total` | gauge | `archetype` | archetype(A~E)별 갭 수 |
| `soc_attack_tactic_uncovered` | gauge | `tactic` | 전술별 미탐지 기법 수 |

- 런타임 카운터는 핫패스가 경보 처리 시 갱신(`metrics().record_alert/observe_node`).
- 커버리지 게이지는 스크레이프 시점에 `tools.coverage` 리포트로 계산.
- `prometheus_client` 의존 없이 텍스트 exposition 직접 렌더(표준 라이브러리).

## 스크레이프 (`deploy/monitoring/servicemonitor.yaml`)
`monitoring: enabled` 라벨이 붙은 Service(soc-hotpath/soc-learning)의 `http` 포트
`/metrics` 를 30s 간격 스크레이프. Prometheus 는 `release: kube-prometheus-stack`
라벨로 ServiceMonitor 를 선택한다.

## 대시보드 (`deploy/monitoring/grafana-dashboard.yaml`)
`grafana_dashboard: "1"` ConfigMap → Grafana 사이드카 자동 적재. 패널:
커버리지 stat / archetype 갭 / 판정 비율 / 전술별 갭 / 경보 처리율 / 노드 지연.

## 배포 (ArgoCD)
```bash
# app-of-apps 가 아래 둘을 sync-wave 순서로 동기화:
#  wave 0: kube-prometheus-stack(helm) — Operator/Prometheus/Grafana + CRD
#  wave 1: soc-monitoring             — ServiceMonitor + 대시보드(CRD 의존)
kubectl apply -n argocd -f deploy/argocd/apps/kube-prometheus-stack.yaml
kubectl apply -n argocd -f deploy/argocd/apps/soc-monitoring.yaml
```
(이미 `dah-soc-root` app-of-apps 를 apply 했다면 git push 만으로 자동 추가된다.)

## SLO 후보 (알람 룰로 승격 가능)
- `soc_attack_coverage_ratio` < 0.6 → 커버리지 회귀 경보.
- `rate(soc_alerts_total[5m])` 급증 → 부하/공격 파동.
- `soc_node_latency_avg_ms{node="investigation"}` 상승 → RAG/LLM 지연.

## 라이브 KPI 벤치마크 연계
정밀 MTTT/MTTC/Precision/Recall 은 `benchmarks/run_kpi.py`(나이틀리, RAGFlow 라이브)
가 산출 → `docs/benchmarks-ci.md`. 런타임 `/metrics` 는 *상시 추세*, 벤치마크는
*정밀 측정*으로 상호 보완.
