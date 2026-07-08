# UAV AI SOC CI/CD 인프라 구성 문서

**작성자**: infra-engineer
**선행 문서**: `_workspace/00_input.md`, `_workspace/01_pipeline_design.md`
**산출물 경로**: `_workspace/02_pipeline_config/`

---

## 0. 산출물 일람

| 파일 | 종류 | 상태 |
|------|------|------|
| `_workspace/02_pipeline_config/.github/workflows/ci-enhanced.yml` | CI 강화 (ci.yml 대체) | 신규 |
| `_workspace/02_pipeline_config/.github/workflows/cd-staging.yml` | develop → staging | 신규 |
| `_workspace/02_pipeline_config/.github/workflows/cd-prod.yml` | main → prod Canary | 신규 |
| `_workspace/02_pipeline_config/.github/workflows/release-signing.yml` | 재사용 워크플로 (cosign + SBOM) | 신규 |
| `_workspace/02_pipeline_config/deploy/Dockerfile` | 멀티스테이지 강화 | 강화 |
| `_workspace/02_pipeline_config/deploy/k8s/30-deployment-a-hotpath.yaml` | Blue-Green 대안(옵션 B) | 강화 |
| `_workspace/02_pipeline_config/deploy/k8s/argo-rollout-hotpath.yaml` | Argo Rollouts Canary(옵션 A 권고) | 신규 |
| `_workspace/02_pipeline_config/deploy/k8s/analysistemplates/hotpath-success-rate-latency.yaml` | AnalysisTemplate 5종 메트릭 | 신규 |

> `compliance.yml`, `ai-redteam.yml` 은 본 작업 범위 밖 — 각각 security-scanner / ai-redteam-engineer 가 작성.

---

## 1. 러너 구성

| 워크플로 | 잡 | 러너 | 사유 |
|----------|----|------|------|
| ci-enhanced.yml | lint, secret-scan, oscal-schema, test, semgrep, pip-audit | `ubuntu-latest` | 경량 |
| ci-enhanced.yml | codeql, build, container-scan, sbom | `ubuntu-latest`  | 표준(향후 `ubuntu-latest-4-cores` 검토) |
| cd-staging.yml | 모든 잡 | `ubuntu-latest` | OIDC + GHCR/AKS 호출만 |
| cd-prod.yml | 모든 잡 | `ubuntu-latest` | 동일 |
| release-signing.yml | sign-and-attest | `ubuntu-latest` | cosign keyless OIDC 필수 |

**self-hosted 러너 불요**. GPU/대규모 PyRIT 도입 시점 재평가 (설계서 §10 #4).

---

## 2. Dockerfile 강화안 (deploy/Dockerfile)

| 항목 | 기존 | 강화 |
|------|------|------|
| 스테이지 | 단일 (`FROM python:3.11-slim AS base`) | **멀티 (builder + runtime)** |
| 베이스 핀 | 태그 (`python:3.11-slim`) | **digest 핀** (`@sha256:...`), Dependabot 자동 갱신 |
| 비루트 | `useradd uid 10001` (기존 OK) | 유지 + `USER 10001:10001` 숫자 명시 (K8s securityContext 정합) |
| HEALTHCHECK | 없음 | **추가** (curl /healthz, 30s 주기) |
| OCI 라벨 | 없음 | **추가** (title, source, licenses, base.name, vendor) |
| PID 1 | python 직접 실행 | **tini** ENTRYPOINT (SIGTERM 전파, graceful shutdown) |
| 런타임 패키지 | 없음 | tini, ca-certificates, curl 만(최소) |
| 빌드 도구 | runtime 에 잔존 | **builder 격리** (gcc, libffi-dev, libssl-dev) |
| 캐시 효율 | pyproject 먼저 복사 (OK) | 유지 + venv 분리 |

`compliance.yml` 또는 ai-redteam 시 distroless 마이그레이션 옵션 검토 (PyRIT/GraphRAG native deps 검증 후).

---

## 3. Azure 인증 (OIDC, federated credentials)

### 3.1 PAT 제거 로드맵

| 제거 대상 | 대체 |
|----------|------|
| `GHCR_PAT` (build-deploy.example.yml) | **GITHUB_TOKEN + `packages: write` + `id-token: write`** (PR/push 분리) |
| `AZURE_CREDENTIALS_JSON` (서비스 주체 시크릿) | **azure/login@v2 + federated credential** (subject claim 기반) |
| `COSIGN_PRIVATE_KEY` | **cosign keyless** (Sigstore Fulcio + Rekor, OIDC) |

### 3.2 Azure AAD 사전 작업 (사용자 작업 필요)

| 단계 | 동작 | 명령(참고) |
|------|------|-----------|
| 1 | AAD App Registration 생성 | `az ad app create --display-name uav-soc-cicd` |
| 2 | Federated credential 등록 (GitHub OIDC) | `az ad app federated-credential create` — subject = `repo:s1ns3nz0/pollack-ai:environment:production`, `:environment:staging`, `:ref:refs/heads/main`, `:ref:refs/heads/develop` |
| 3 | Service Principal + RBAC | AKS `Azure Kubernetes Service Cluster User Role`, Key Vault `Key Vault Secrets User` |
| 4 | GitHub Variables 등록 (시크릿 아님 — 식별자만) | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AKS_CLUSTER_NAME`, `AKS_RESOURCE_GROUP` |

> 본 작업 범위는 워크플로 작성. AAD 자원 프로비저닝은 사용자 수행.

### 3.3 cosign keyless OIDC

- GitHub Actions OIDC 토큰 → Fulcio 단명 인증서 발급(약 10분 유효).
- Rekor 투명성 로그에 서명 기록 → 사후 감사 가능.
- 검증 시 `--certificate-identity-regexp "^https://github\.com/s1ns3nz0/pollack-ai/"` + `--certificate-oidc-issuer https://token.actions.githubusercontent.com` 필수.

---

## 4. 시크릿 관리

### 4.1 GitHub Actions Secrets (최소)

| 시크릿 | 범위 | 용도 | 비고 |
|--------|------|------|------|
| `GITHUB_TOKEN` | 워크플로 자동 | GHCR push, gh CLI | 잡 단위 `packages: write` 필요 |
| `ARGOCD_AUTH_TOKEN` | repo or env=production | ArgoCD CLI sync 대기 | 옵션 (OIDC 미연동 시) |
| `SLACK_WEBHOOK_OPS` | repo | 배포 알람 (monitoring-specialist 영역) | 옵션 |

### 4.2 GitHub Actions Variables (시크릿 아님 — 식별자)

| 변수 | 범위 | 값 예 |
|------|------|-------|
| `AZURE_CLIENT_ID` | env=staging, production | OIDC App ID |
| `AZURE_TENANT_ID` | repo or env | AAD tenant ID |
| `AZURE_SUBSCRIPTION_ID` | repo or env | 구독 ID |
| `AKS_CLUSTER_NAME` | env | 예: `dah-soc-aks` |
| `AKS_RESOURCE_GROUP` | env | 예: `rg-dah-soc` |
| `ARGOCD_SERVER` | env | 예: `argocd.dah-soc.example.com` |
| `STAGING_HEALTH_URL` | env=staging | 예: `https://staging.dah-soc.example.com` |
| `PROD_HEALTH_URL` | env=production | 예: `https://dah-soc.example.com` |

### 4.3 Azure Key Vault (런타임 시크릿)

| 시크릿 | 저장소 | 접근 방식 | 비고 |
|--------|--------|----------|------|
| `azure-openai-key` | Key Vault | AKS 워크로드 ID + CSI Secrets Store | 컨테이너 안 `/mnt/secrets/` 마운트 |
| `sentinel-workspace-id` | Key Vault | 동일 | configmap 옮길 수도 (비밀 아님) |
| `ragflow-api-token` | Key Vault | 동일 | |
| `github-token-content-bot` | Key Vault | 동일 (탐지 룰 PR 봇) | |

> 시크릿 매니페스트(`deploy/k8s/15-secret.example.yaml`) 는 placeholder 유지.
> 실제 배포 시 `kubectl apply -f` 대신 **External Secrets Operator** 또는 **Secrets Store CSI Driver (Azure provider)** 권장. 본 작업 범위 외.

---

## 5. GHCR 아티팩트 정책

| 아티팩트 | 태그/식별 | 보존 |
|---------|-----------|------|
| 이미지 (CI/dev) | `sha-<short_sha>` (불변), `latest` 미사용 | 기본 (GHCR 무제한) |
| 이미지 (staging) | `sha-<short_sha>` + `staging` 이동 태그 | 무기한 |
| 이미지 (prod) | `sha-<short_sha>` + `prod` 이동 태그 + `v<semver>` (릴리스 시) | **무기한** (감사) |
| SBOM (SPDX-JSON) | `sbom-sha-<git-sha>` GitHub Artifact + 이미지 cosign attest | Artifact 90일 + attest 영구 |
| 서명 (cosign.sig + cosign.pem) | GitHub Artifact + Rekor 로그 | Artifact 365일 + Rekor 무기한 |
| Provenance (SLSA L3) | OCI artifact `.intoto.jsonl` (이미지 옆) | 무기한 |
| coverage.xml | GitHub Artifact | 30일 |
| Trivy SARIF | GitHub Security tab | 90일+ |

---

## 6. GitOps (ArgoCD) 연동

### 6.1 태그 bump 정책

| 트리거 | 대상 매니페스트 | 커밋 메시지 |
|--------|----------------|------------|
| push develop → cd-staging | `deploy/k8s/30-deployment-a-hotpath.yaml`, `40-deployment-b-learning.yaml` | `ci(staging): bump image to sha-<short>` |
| push main → cd-prod (수동 승인 후) | `deploy/k8s/argo-rollout-hotpath.yaml`, `40-deployment-b-learning.yaml` | `ci(prod): bump image to sha-<short>` |
| 카나리 자동 롤백 | `cd-prod` 가 위 bump 커밋 `git revert` 후 push | `Revert "ci(prod): bump image to sha-<short>"` |

### 6.2 ArgoCD Application 신규

- `deploy/argocd/apps/soc-staging.yaml` 필요 (사용자 승인 — 설계서 §10 #2).
  - 대상 ns: `dah-soc-staging`
  - syncPolicy.automated: prune=true, selfHeal=true
  - 동일 `deploy/k8s/` path 사용 (현재 overlay 미사용)
- `deploy/argocd/apps/argo-rollouts.yaml` (옵션 A 채택 시) — Argo Rollouts 컨트롤러 설치 Application.
- `deploy/k8s/analysistemplates/` 디렉터리는 기존 `dah-soc-workloads` Application 이 자동 sync.

### 6.3 sync 정책 (재사용)

```yaml
syncPolicy:
  automated:
    prune: true
    selfHeal: true
  syncOptions:
    - CreateNamespace=true
    - ApplyOutOfSyncOnly=true
  retry:
    limit: 3
    backoff:
      duration: 10s
      maxDuration: 2m
      factor: 2
```

---

## 7. GitHub Environments

| 환경 | 보호 규칙 | 변수 |
|------|----------|------|
| `staging` | 보호 없음, develop 만 배포 | `STAGING_HEALTH_URL`, AKS 자격, ArgoCD 정보 |
| `production` | **required reviewers ≥ 1** (가능 시 2), wait timer 5분, main 만 | `PROD_HEALTH_URL`, AKS 자격, ArgoCD 정보 |

---

## 8. GitHub Actions SHA 핀 매핑

> 공급망 무결성(방산 / NIST SP 800-204D). 모든 third-party action 은 SHA 고정 + `# v<semver>` 주석. Dependabot `package-ecosystem: github-actions` 로 갱신 PR 자동화 권장.

| 액션 | SHA (2025-06 기준) | 버전 주석 |
|------|-------------------|----------|
| actions/checkout | `11bd71901bbe5b1630ceea73d27597364c9af683` | v4.2.2 |
| actions/setup-python | `a26af69be951a213d495a4c3e4e4022e16d87065` | v5.6.0 |
| actions/upload-artifact | `ea165f8d65b6e75b540449e92b4886f43607fa02` | v4.6.2 |
| actions/cache | `1bd1e32a3bdc45362d1e726936510720a7c30a57` | v4.2.0 |
| actions/dependency-review-action | `da24556b548a50705dd671f47852072ea4c105d9` | v4.7.1 |
| github/codeql-action/(init\|analyze\|upload-sarif) | `4e828ff8d448a8a6e532957b1811f387a63867e8` | v3.29.4 |
| gitleaks/gitleaks-action | `ff98106e4c7b2bc287b24eaf42907196329070c7` | v2.3.6 |
| docker/setup-buildx-action | `b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2` | v3.10.0 |
| docker/login-action | `9780b0c442fbb1117ed29e0efdff1e18412f7567` | v3.3.0 |
| docker/build-push-action | `4f7cdeb0f1f2ac4233f0f24355a1838a86b54a9b` | v6.10.0 |
| aquasecurity/trivy-action | `dc5a429b52fcf669ce959baa2c2dd26090d2a6c4` | v0.32.0 |
| anchore/sbom-action/download-syft | `7b36ad622f042cab6f59a75c2ac24ccb256e9b45` | v0.20.4 |
| sigstore/cosign-installer | `d7d6bc7722e3daa8354c50bcb52f4837da5e9b6a` | v3.8.1 |
| azure/login | `a65d910e8af852a8061c627c456678983e180302` | v2.2.0 |
| slsa-framework/slsa-github-generator (workflow_call) | `@v2.0.0` (태그 — generator 는 SHA 핀 미지원) | v2.0.0 |

> **주의**: SHA 핀 값은 본 문서 작성 시점 추정(검증 필요). pipeline-reviewer 가 `gh api /repos/<owner>/<repo>/git/ref/tags/<ver>` 로 actual SHA 일괄 확인하고 patch PR 권장. `python -m venv` 캐시키 변경 등 사이드이펙트 없음.

---

## 9. 설계와 다르게 결정한 항목

| 항목 | 설계 | 본 작업 결정 | 사유 |
|------|------|-------------|------|
| 30-deployment-a-hotpath.yaml 폐기 vs 잔존 | 설계서는 Rollout 마이그레이션 권고 | **양쪽 모두 산출** (옵션 A=Rollout 신규, 옵션 B=Deployment 강화) | 상태 분리 결정(§10 #1)이 사용자 승인 대기 — 둘 다 제공해 빠른 전환 가능 |
| ci-enhanced 의 `oscal-schema` 잡 | 설계서 5.1 표는 PR=경고/main=차단 | **CI 에서는 모두 경고 (`continue-on-error`)** | main 차단은 `cd-prod.yml` 의 `oscal-gate` 가 더 강하게 수행. CI 중복 차단은 ROI 낮음 |
| Semgrep 러너 컨테이너 SHA 핀 | 명시 없음 | digest 핀 사용 | 방산 공급망 — third-party container 도 핀 권장. 실제 SHA 는 reviewer 검증 필요 |
| cd-prod 의 `rollouts-monitor` AKS 연동 조건 | 설계서는 ArgoCD CLI 가정 | `vars.AZURE_CLIENT_ID != ''` 조건 — AKS 자격 미세팅 시 자동 skip | OIDC 미준비 환경에서도 워크플로 import 가능 |
| `sign-attest` 의 GHCR 로그인 방식 | OIDC 우선 명시 | cosign sign 자체는 OIDC, 단 GHCR registry auth 는 `GITHUB_TOKEN` 사용 | cosign 의 keyless 는 서명 인증서만 OIDC. registry write 는 별개 — packages:write 권한이면 충분 |

---

## 10. 다른 에이전트 인계 사양

### 10.1 security-scanner 인계

| 항목 | 위치 | 비고 |
|------|------|------|
| 빌드 잡 위치 | `ci-enhanced.yml#jobs.build`, `cd-staging.yml#jobs.build-push`, `cd-prod.yml#jobs.build-push` | 이미지 다이제스트는 `outputs.image_ref` |
| Dockerfile 베이스 | `python:3.11-slim-bookworm@sha256:...` | 실제 digest 갱신 PR 필요 (Dependabot) |
| 의존성 파일 | `pyproject.toml` (단일 진실) | `pyproject.toml` 에 `[project.optional-dependencies].dev` + `eval` + `sim` |
| SBOM 포맷 | SPDX-JSON (`sbom.spdx.json`) | CycloneDX 필요 시 `release-signing.yml` 입력 `sbom_format=cyclonedx-json` |
| 서명 검증 명령 | `cosign verify --certificate-identity-regexp "^https://github\.com/s1ns3nz0/pollack-ai/"` | OIDC issuer = `https://token.actions.githubusercontent.com` |
| compliance.yml 신규 작성 | security-scanner 영역 | `build_oscal.py` + `check_poam_thresholds.py` 가 prereq |

### 10.2 monitoring-specialist 인계

| 항목 | 위치 | 비고 |
|------|------|------|
| 메트릭 엔드포인트 | 컨테이너 `:8080/metrics` (Prometheus) | Service 라벨 `monitoring: enabled` 로 ServiceMonitor 선택 |
| AnalysisTemplate Prometheus 쿼리 | `deploy/k8s/analysistemplates/hotpath-success-rate-latency.yaml` | 5종 메트릭 — Prometheus job 라벨 `soc-hotpath` 가정 |
| Prometheus 주소 | `http://prometheus-operated.monitoring.svc.cluster.local:9090` | kube-prometheus-stack 기본 |
| 알림 웹훅 | `secrets.SLACK_WEBHOOK_OPS` (옵션) | cd-prod 미사용 — Alertmanager 측 통합 권고 |
| 새 메트릭 필요 | `agent_latency_seconds_bucket`, `ragas_faithfulness_score`, `http_requests_total{code}` | 앱 측 구현 필요 — application engineer 와 협의 |
| DORA 4지표 | ArgoCD `argocd_app_sync_total`, GitHub workflow_run, Alertmanager incident open/close | 별도 워크플로 또는 Pushgateway exporter |

### 10.3 pipeline-reviewer 인계

| 항목 | 보류/누락 |
|------|----------|
| SHA 핀 실제값 | 본 문서 §8 표는 추정. `gh api` 로 실제 SHA 일괄 확인 PR 필요 |
| `compliance.yml` | 본 작업 범위 외 — security-scanner 작성 |
| `ai-redteam.yml` | ai-redteam-engineer 작성 — `cd-prod#ai-redteam-check` 가 의존 |
| `benchmarks/check_gates.py` | test-engineer 신규 작성 — `--profile=staging|prod` 인자 지원 필수 |
| `compliance/oscal/check_poam_thresholds.py` | security-scanner/test-engineer 협업 — `--mode block|warn`, `--critical-max`, `--high-max` 인자 |
| Dockerfile digest 핀 실제값 | `docker pull python:3.11-slim-bookworm && docker inspect --format='{{index .RepoDigests 0}}'` 로 확정 필요 — 본 산출물의 sha256 값은 placeholder |
| `deploy/argocd/apps/soc-staging.yaml` | 사용자 승인 후 신규 작성 — 설계서 §10 #2 |
| Argo Rollouts 컨트롤러 설치 매니페스트/Application | 본 작업 범위 외 — ops 작업 |
| Semgrep container digest | placeholder. 실제 `returntocorp/semgrep:latest` digest 확인 후 patch |

---

## 11. 마이그레이션 절차 요약

1. `_workspace/02_pipeline_config/` 산출물 reviewer 승인 후 `.github/workflows/` + `deploy/` 로 복사.
2. 기존 `.github/workflows/ci.yml` 을 `ci-enhanced.yml` 로 대체 (또는 이름 유지 + 내용 교체).
3. `deploy/ci/build-deploy.example.yml` 폐기 (`cd-staging.yml`/`cd-prod.yml` 가 대체).
4. Argo Rollouts 컨트롤러 설치 (`kubectl create ns argo-rollouts && kubectl apply -k 'https://github.com/argoproj/argo-rollouts/manifests/install?ref=v1.7.2'`).
5. AAD App + federated credential 생성 (사용자 작업).
6. GitHub Environments(staging, production) 생성 + 변수/시크릿 등록.
7. 옵션 A 채택 시 `deploy/k8s/30-deployment-a-hotpath.yaml` 삭제 + `argo-rollout-hotpath.yaml` 추가.
8. ArgoCD `dah-soc-workloads` Application 의 `directory.exclude` 에 `30-deployment-a-hotpath.yaml` 추가 (Rollout 채택 시).
9. `deploy/argocd/apps/soc-staging.yaml` 추가 (사용자 승인 후).
10. 첫 develop push 로 cd-staging 검증 → main merge 로 cd-prod 검증.

---

## 12. 라운드 B — 옵션 1(빌더 이미지 핀) 도입

### 12.1 산출물

| 파일 | 종류 | 비고 |
|------|------|------|
| `deploy/Dockerfile.builder` | 신규 — CI/CD 공통 빌더 이미지 | distroless 대안은 §2 노트 참조 |
| `deploy/Dockerfile.builder.README.md` | 신규 — 운영 가이드 | 부트스트랩·갱신·로컬 재현 절차 |
| `.github/workflows/build-builder.yml` | 신규 — 빌더 이미지 빌드·서명·digest PR | monthly + push trigger |
| `.github/workflows/ci-enhanced.yml` | 강화 — `verify-builder` 잡 + container 핀 | lint/secret-scan/oscal/test/semgrep/pip-audit 적용 |
| `.github/workflows/cd-staging.yml` | 강화 — 동일 | g2-gate/oscal-warn/smoke/dora-* 적용 |
| `.github/workflows/cd-prod.yml` | 강화 — 동일 | g2-gate/ai-redteam-check/oscal-gate/post-deploy-smoke/dora-* 적용 |
| `.github/workflows/ci-quality-patch.yml` | 강화 — 동일 | 5개 잡 + quality-gate summary 적용 |
| `.github/workflows/ai-redteam.yml` | 강화 — 동일 | resolve-mode/atlas-deterministic/domain-scenarios 적용 |

### 12.2 빌더 이미지 도구 풀스택 핀 (요약)

| 분류 | 핀 |
|------|-----|
| Python 품질 | black==24.10.0, ruff==0.5.7, mypy==1.11.2, pytest==8.3.3, pytest-cov==5.0.0, pytest-asyncio==0.24.0, interrogate==1.7.0, xenon==0.9.3 |
| 보안(pip) | pip-audit==2.7.3, semgrep==1.85.0, checkov==3.2.255 |
| 보안(binary) | gitleaks==8.18.4, syft==1.14.1, trivy==0.55.2, cosign==2.4.1, gh==2.55.0 |
| OSCAL | compliance-trestle==3.5.1, jsonschema==4.23.0 |
| 유틸 | jq, curl, git, tini, bash (apt 기본) |

### 12.3 워크플로별 container 핀 적용 통계

| 워크플로 | 적용 잡 | 화이트리스트 잡 | 화이트리스트 사유 |
|----------|---------|----------------|-------------------|
| `ci-enhanced.yml` | 7 (lint, secret-scan, oscal-schema, test, semgrep, dependency-review*, pip-audit) | 5 (setup, codeql, build, container-scan, sbom) | setup=actions/setup-python hosttoolcache, codeql=CodeQL CLI 환경, build=docker daemon, container-scan/sbom=공식 action 의 호스트 호출 |
| `cd-staging.yml` | 5 (g2-gate, oscal-warn, smoke, dora-success, dora-failure) | 4 (build-push, container-scan, sign-attest, gitops-bump) | docker daemon · trivy-action · reusable workflow · git push |
| `cd-prod.yml` | 6 (g2-gate, ai-redteam-check, oscal-gate, post-deploy-smoke, dora-success, dora-failure) | 8 (build-push, container-scan, sign-attest, provenance, prod-approval, gitops-bump, argocd-wait, rollouts-monitor) | docker/trivy/reusable/env·승인 게이트/git push/외부 CLI download/kubectl+az |
| `ci-quality-patch.yml` | 5 (lint, typecheck, complexity, docstring, convention) | 1 (quality-gate summary) | 결과 평가만 수행하는 단순 잡 |
| `ai-redteam.yml` | 3 (resolve-mode, atlas-deterministic, domain-scenarios) | 3 (pyrit-campaign, garak-campaign, report-and-poam) | azure/login + az CLI · azure/login + REST · peter-evans/create-pull-request |
| `release-signing.yml` | 0 | 1 (sign-and-attest) | cosign-installer + docker/login + GHCR 인증 — 호스트 권장 |
| **합계** | **26** | **22** | — |

*dependency-review 는 `actions/dependency-review-action` 공식 JS action — 호스트 권장으로 분류(컨테이너 적용 가능하나 비포함)*

### 12.4 cosign 검증 패턴 (모든 워크플로)

각 워크플로 첫 잡 `verify-builder` 가 다음을 수행 — 모든 후속 잡이 `needs: verify-builder` 로 의존:

```yaml
verify-builder:
  runs-on: ubuntu-latest
  steps:
    - uses: sigstore/cosign-installer@d7d6bc7722e3daa8354c50bcb52f4837da5e9b6a # v3.8.1
    - run: |
        if [ -z "${{ vars.BUILDER_IMAGE_DIGEST }}" ]; then
          echo "::error::vars.BUILDER_IMAGE_DIGEST 미설정 — build-builder.yml 부트스트랩 필요."
          exit 1
        fi
    - run: |
        cosign verify \
          --certificate-identity-regexp 'https://github\.com/s1ns3nz0/pollack-ai/\.github/workflows/build-builder\.yml@.*' \
          --certificate-oidc-issuer https://token.actions.githubusercontent.com \
          ghcr.io/s1ns3nz0/uav-soc-builder@${{ vars.BUILDER_IMAGE_DIGEST }}
```

> 컨테이너 잡의 첫 step 에 cosign verify 를 넣지 않은 이유: `container:` 가 지정되면 steps 가 컨테이너 안에서 실행되므로 verify 가 검증 대상 이미지 내부에서 일어나 닭-달걀. → 별도 `verify-builder` 잡으로 분리(호스트 실행).

### 12.5 컨테이너 옵션(공통)

```yaml
container:
  image: ghcr.io/s1ns3nz0/uav-soc-builder@${{ vars.BUILDER_IMAGE_DIGEST }}
  options: --user 10001 --read-only --tmpfs /tmp:rw,nosuid,nodev,size=<128|256|512>m --cap-drop=ALL
```

- `--user 10001` : Dockerfile.builder USER 와 동일
- `--read-only`  : rootfs 변경 금지 — 공급망 변조 방어
- `--tmpfs /tmp` : 임시 산출물(coverage.xml, sarif 등)용. 잡 특성에 맞게 64m/128m/256m/512m
- `--cap-drop=ALL`: Linux capabilities 모두 박탈(CI 잡은 raw socket 등 불요)

### 12.6 부트스트랩 순서(요약)

1. `deploy/Dockerfile.builder` + `.github/workflows/build-builder.yml` 만 머지(다른 워크플로의 container 핀 패치는 보류)
2. `gh workflow run build-builder.yml --ref main` 으로 첫 빌드 + cosign 서명
3. 산출 digest 확보 (`gh run view <run_id> --log`)
4. `gh variable set BUILDER_IMAGE_DIGEST --body sha256:<digest>` 등록
5. 다운스트림 5개 워크플로 patch 머지
6. 첫 PR/push 가 모든 잡에서 cosign verify 통과하는지 확인

상세 절차는 `deploy/Dockerfile.builder.README.md` §9 참조.

### 12.7 pipeline-reviewer 재검토 항목(라운드 B)

| 항목 | 검증 방법 |
|------|----------|
| 1. Dockerfile.builder 베이스 digest placeholder | 사용자 환경에서 `docker pull python:3.11-slim-bookworm` 후 실측 sha256 치환 PR 확인 |
| 2. binary 도구 sha256 placeholder(gitleaks/syft/trivy/cosign/gh) | release 페이지 *_checksums.txt 대조 후 ARG 값 치환 확인 |
| 3. cosign 검증의 certificate-identity-regexp 가 build-builder.yml 경로와 정확히 일치 | regex 의 `\.github/workflows/build-builder\.yml` 부분 검증 |
| 4. container 옵션 read-only rootfs 에서 도구가 /tmp 외 경로에 쓰는지 여부 | smoke-test 잡 또는 lint/test 첫 실행에서 IO 실패 확인 |
| 5. `vars.BUILDER_IMAGE_DIGEST` 미설정 시 verify-builder 명확한 에러 메시지 출력 | YAML 의 `BUILDER_IMAGE_DIGEST 존재 검증` step 본문 확인 |
