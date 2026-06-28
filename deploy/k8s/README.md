# 배포 — AKS 네이티브 하이브리드 (ADR 0002 D6)

워크로드 성격이 정반대인 두 경계로만 분리한다.

| 구성 | 역할 | 스케일 | 매니페스트 |
|---|---|---|---|
| **Deployment A** `soc-hotpath` | 지연민감 SOC 핫패스(경보→판정) | single-replica(상태 보유) | `30-deployment-a-hotpath.yaml` |
| **Deployment B** `soc-learning` | 버스티 경험/학습 루프(exp 적립→RuleUpdate) | HPA 1~4 | `40-deployment-b-learning.yaml` |
| **공유 상태** `ragflow` | exp/ 경험메모리 + KB(영속) | StatefulSet+PVC | `20-ragflow.yaml` |
| (선택) kagent | 운영 MCP 도구 등록 | — | `50-kagent-toolserver.yaml` |

A/B 는 **동일 이미지**(`deploy/Dockerfile`)에서 `command` 로 분기한다.

## 사전 준비
- AKS 클러스터 + `kubectl` 컨텍스트
- 컨테이너 이미지 빌드·푸시: `docker build -f deploy/Dockerfile -t ghcr.io/s1ns3nz0/uav-ai-soc:latest . && docker push ...`
- RAGFlow: `20-ragflow.yaml` 은 단일노드 dev 스텁. 운영은 공식 RAGFlow 배포로 교체하고 Service 이름(`ragflow`)만 맞춘다.
- (HPA) metrics-server 설치.

## 시크릿 — 절대 평문 커밋 금지
`15-secret.example.yaml` 은 **템플릿**(전부 `REPLACE_ME`). 실제 주입:
```bash
kubectl -n dah-soc create secret generic soc-secrets \
  --from-literal=RAGFLOW_API_TOKEN=... \
  --from-literal=GITHUB_TOKEN=... \
  --from-literal=EXP_SIGNING_KEY=...
```
운영 권장: sealed-secrets 또는 Azure Key Vault CSI.

## 적용 순서
```bash
kubectl apply -f deploy/k8s/00-namespace.yaml
kubectl apply -f deploy/k8s/10-configmap.yaml
# 시크릿은 위 create secret 명령으로(예제 파일 apply 금지)
kubectl apply -f deploy/k8s/20-ragflow.yaml
kubectl apply -f deploy/k8s/30-deployment-a-hotpath.yaml
kubectl apply -f deploy/k8s/40-deployment-b-learning.yaml
# (선택) kagent CRD 설치돼 있으면
kubectl apply -f deploy/k8s/50-kagent-toolserver.yaml
```

## 헬스/관측
- `/healthz`(liveness) · `/readyz`(readiness) · `/metrics`(커버리지 KPI 스냅샷 JSON)
- KPI 모니터링(로드맵 5단계)은 `/metrics` 의 `tools.coverage` 리포트를 수집한다.

## GitOps
룰 변경(Watch List PR)은 G2 회귀게이트 통과 후 argoCD 로 머지·배포한다(자동 머지 없음).
