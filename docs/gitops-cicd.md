# GitOps / CI-CD 참고 — ArgoCD + 2-트랙 배포

전체를 GitOps 로 굴린다. **두 트랙**이 분리돼 있고, 각각 git 머지가 곧 배포 트리거다.

| 트랙 | 대상 | 동기화 주체 | 소스 |
|---|---|---|---|
| **A. 워크로드** | SOC 핫패스/학습/RAGFlow (K8s) | **ArgoCD** | `pollack-ai` repo `deploy/` |
| **B. 탐지 콘텐츠** | Sentinel 룰/Watch List | **Sentinel Repo 커넥터**(GitHub Actions) | `dah-sentinel-content` repo |

> 둘을 굳이 나눈 이유: 워크로드는 K8s 선언배포(ArgoCD), 탐지콘텐츠는 Sentinel 전용
> 배포 경로(ARM 템플릿)라 도구가 다르다. RuleUpdateAgent 의 PR 은 트랙 B 로 흐른다.

---

## 트랙 A — 워크로드 (ArgoCD)

### 부트스트랩 (1회)
```bash
# ArgoCD 설치 후, 프로젝트 + app-of-apps 루트만 apply.
kubectl apply -n argocd -f deploy/argocd/project.yaml
kubectl apply -n argocd -f deploy/argocd/root-app.yaml
```
이후 모든 앱은 **git 으로만** 추가/변경된다(`deploy/argocd/apps/` 에 Application 추가).
`dah-soc-workloads` 가 `deploy/k8s/` 를 `dah-soc` 네임스페이스로 자동 동기화한다
(prune + selfHeal). 시크릿 예제(`15-secret.example.yaml`)는 동기화 제외.

### 이미지 승격 (GitOps 의 핵심)
`deploy/k8s` 의 이미지 태그가 **선언적 진실**이다. `:latest` 가 아니라 **불변 태그
(git SHA)** 로 핀 고정하고, CI 가 새 SHA 로 태그를 bump 하는 커밋을 올리면 ArgoCD 가
그 diff 를 감지해 롤아웃한다. 두 방식 중 택1:

1. **CI 커밋 방식(권장, 명시적)**: CI 가 이미지 push 후 `deploy/k8s` 의 `image:` 를
   새 SHA 로 치환하는 커밋을 push → ArgoCD sync. (아래 예제 워크플로)
2. **ArgoCD Image Updater**: 레지스트리를 폴링해 태그 자동 bump. Deployment 에
   `argocd-image-updater.argoproj.io/image-list` 어노테이션 추가.

### 파이프라인 흐름
```
PR ─▶ CI 게이트(lint·mypy·test + G2 결정론 benchmark) ─▶ 머지(main)
   ─▶ 이미지 build/push (ghcr, tag=SHA)
   ─▶ deploy/k8s 이미지 태그 bump 커밋
   ─▶ ArgoCD 자동 sync ─▶ AKS 롤아웃(헬스 프로브 통과까지)
```
- **CI 게이트** = 기존 `.github/workflows/ci.yml`(lint/test/CodeQL/dep-review)
  + `docs/benchmarks-ci.md` 의 **트랙 A 결정론 게이트**(`run_fp_recurrence` +
  `run_atlas_redteam`). 통과 못 하면 머지 차단 = **G2 회귀게이트**.

---

## 트랙 B — 탐지 콘텐츠 (Sentinel 커넥터)

RuleUpdateAgent 가 오탐 개선을 `dah-sentinel-content` 에 **Watch List PR** 로 올린다
(KQL 불변). 흐름:
```
RuleUpdateAgent ─▶ PR(fix/watchlist) ─▶ G2 회귀게이트(benchmarks: 알려진 TP 무손실)
   ─▶ 1인 승인 ─▶ squash 머지(main) ─▶ Sentinel Repo 커넥터가 워크스페이스로 배포
```
- **자동 머지 없음**(ADR 0002 D6/G2). 탐지를 *느슨하게* 하는 방향이라 사람 승인 게이트.
- Sentinel 배포 워크플로는 `dah-sentinel-content/.github/workflows/` 에 이미 존재
  (Sentinel Repositories 커넥터가 생성).

---

## 모니터링 연동 (로드맵 5)
KPI 대시보드는 별도 Application(`deploy/argocd/apps/monitoring.yaml`, 5단계에서 추가)
으로 kube-prometheus-stack 을 동기화하고, `/metrics`(커버리지 KPI)와 OTel 메트릭을
스크레이프한다.

---

## 예제 빌드/배포 워크플로
복사해서 `.github/workflows/cd.yml` 로 쓸 수 있는 참고본: `deploy/ci/build-deploy.example.yml`.
요지(트랙 A):

```yaml
# main push 시: 결정론 게이트 → 이미지 build/push(SHA) → deploy/k8s 태그 bump 커밋
on:
  push: { branches: [main] }
jobs:
  gate:        # G2 — 통과 못 하면 배포 안 함
    run: |
      python benchmarks/run_fp_recurrence.py
      python benchmarks/run_atlas_redteam.py
  build-deploy:
    needs: gate
    steps:
      - docker build/push ghcr.io/s1ns3nz0/uav-ai-soc:${{ github.sha }}
      - sed -i "s|uav-ai-soc:.*|uav-ai-soc:${{ github.sha }}|" deploy/k8s/3*.yaml deploy/k8s/4*.yaml
      - git commit -am "ci: bump image to ${{ github.sha }}" && git push
      # ArgoCD 가 이 커밋을 감지해 자동 동기화
```

전체본은 예제 파일 참조. 시크릿(레지스트리 자격, ArgoCD 토큰)은 GitHub Actions Secrets
로 주입하고 평문 커밋 금지.
