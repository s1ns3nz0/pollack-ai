---
name: deployment-strategies
description: "AKS + ArgoCD GitOps 배포 전략 카탈로그. Rolling/Canary(Argo Rollouts)/Blue-Green 전략, GitOps 동기화·자동 롤백, 트랙 A(hotpath)/B(learning) 배포 분리, 헬스체크/프로브, DORA 메트릭을 제공하는 pipeline-designer 확장 스킬. '배포 전략', 'Canary', 'Argo Rollouts', 'ArgoCD', '롤백', '무중단 배포', 'AKS 배포' 등에 사용한다."
---

# Deployment Strategies — AKS/ArgoCD 배포 전략 카탈로그

pipeline-designer 에이전트가 배포 설계 시 활용하는 전략·롤백·헬스체크·DORA 레퍼런스.
이 저장소는 **AKS + ArgoCD GitOps** 전제이며, 이미지 태그 bump 커밋 → ArgoCD 폴링 동기화 방식.

## 대상 에이전트

`pipeline-designer` — 이 스킬의 전략·롤백 패턴을 파이프라인 설계에 직접 적용한다.

## 트랙별 전략 (이 프로젝트)

| 트랙 | 성격 | 권장 전략 | 이유 |
|------|------|----------|------|
| A (hotpath) | 저지연 실시간 추론 | **Canary** (Argo Rollouts) | 점진 노출 + 자동 분석 롤백, 미션 크리티컬 |
| B (learning) | 비동기 학습/배치 | **Rolling** | 무중단 불필요, 비용 최소 |

## 배포 전략 비교

| 전략 | 다운타임 | 위험 | 비용 | 롤백 | 적합 |
|------|---------|------|------|------|------|
| Rolling | 없음 | 중 | 낮음 | 중 | 트랙 B, 일반 |
| Canary | 없음 | 매우 낮음 | 약간 | 즉각 | 트랙 A hotpath |
| Blue-Green | 없음 | 낮음 | 2배 | 즉각 | 대규모 전환 |
| Recreate | 있음 | 높음 | 없음 | 느림 | dev/staging |

## GitOps 배포 흐름 (ArgoCD)

```
CI(G2 게이트 통과) → 이미지 build/push(GHCR, 불변 SHA 태그)
  → deploy/k8s 이미지 태그 bump 커밋 push
  → ArgoCD가 git 폴링 → 클러스터 동기화(self-heal, prune)
  → (트랙 A) Argo Rollouts Canary 분석 → 자동 승격/롤백
```

롤백 = **git revert(태그 bump 되돌리기)** → ArgoCD가 이전 형상으로 동기화. 형상이 git에
남아 감사 추적 가능(방산 이점).

## Argo Rollouts Canary (트랙 A)

```yaml
# 개념 예시 — 실제 매니페스트는 deploy/k8s 에 맞춰 작성
strategy:
  canary:
    steps:
      - setWeight: 10
      - pause: { duration: 10m }   # 분석: 에러율/p99/agent_latency
      - setWeight: 50
      - pause: { duration: 30m }
      - setWeight: 100
    analysis:
      templates: [{ templateName: success-rate-latency }]
```

자동 롤백 조건:
| 지표 | 임계 | 대기 |
|------|------|------|
| HTTP 5xx | > 1% | 2분 연속 |
| agent_latency p99 | > 2초 | 5분 연속 |
| Pod 재시작 | > 3회 | 10분 |

## 헬스체크 (Kubernetes Probe)

| 유형 | 대상 | 엔드포인트 | 주기 |
|------|------|----------|------|
| Liveness | 프로세스 생존 | /healthz | 10s |
| Readiness | 트래픽 수신 | /readyz | 5s |
| Startup | 초기화(모델 로드) | /healthz | 1s(최대 300s) |

```yaml
livenessProbe:  { httpGet: { path: /healthz, port: 8080 }, periodSeconds: 10, failureThreshold: 3 }
readinessProbe: { httpGet: { path: /readyz,  port: 8080 }, periodSeconds: 5,  failureThreshold: 3 }
```

## 브랜치 전략과 환경 매핑

| 브랜치 | 환경 | 동기화 |
|--------|------|--------|
| feature/* | preview(ephemeral) | PR 시 |
| develop | staging | push 자동 |
| main | production | G2 게이트 후 자동(prod는 승인) |

## DORA 메트릭

| 메트릭 | Elite | High | 측정 |
|--------|-------|------|------|
| 배포 빈도 | 일 다회 | 일~주 | ArgoCD sync 이벤트 |
| 리드 타임 | < 1h | 1d~1w | 커밋→prod sync |
| 변경 실패율 | < 5% | 6~15% | 롤백/전체 배포 |
| MTTR | < 1h | < 1d | 감지→복구 |

## 방산 배포 고려사항

- 모든 배포 산출물은 SBOM·서명 동반(security-scanner 연계)
- GitOps 형상 변경은 git 이력으로 감사 추적 — 누가/언제/무엇을 배포했는지 추적 가능
- prod 배포는 수동 승인 게이트 + 2인 검토(가능 시 CODEOWNERS) 권장
