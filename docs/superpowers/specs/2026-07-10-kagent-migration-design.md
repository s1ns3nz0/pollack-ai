# kagent 운영 마이그레이션 + 대시보드 외부 노출

| 항목 | 값 |
|---|---|
| 작성일 | 2026-07-10 |
| 상태 | 설계(사용자 승인 대기 → 구현 계획) |
| 참조 | `fried-pollack-ai` (kagent+ArgoCD+AKS+judge-deploy 패턴) |
| 근거 | 예선 심사 배포 — kagent 네이티브 운영 + 판정단 도메인 무관 접속 |
| 선행 | `agents/graph.py` LangGraph, `app/hotpath.py`·`app/learning.py`·`app/dashboard.py`, `deploy/k8s/*`, `deploy/argocd/*` |

## 목표

pollack-ai UAV AI SOC를 **kagent(AKS)로 운영**한다. 단, 기존 in-process
LangGraph 엔진은 재작성하지 않고 `fried-pollack-ai`처럼 kagent를 **LLM
오케스트레이터**로 얹어 coarse MCP 툴을 통해 기존 SOC 표면을 호출한다.
동시에 대시보드를 `soc.pollak.store/dashboard`로 외부 노출하되, 도메인이 없는
심사위원도 **Azure 기본 호스트명**으로 접속 가능하게 만든다. 도메인은 배포
시점 인자(`DOMAIN`)로 주입한다.

## 핵심 원칙

- **엔진 불변**: LangGraph 그래프·hotpath(A)/learning(B) 배포·이미지·SOC 자체
  LLM(`llm_provider`)은 그대로. kagent는 그 위의 오케스트레이션 계층이다.
- **kagent-비종속 유지(ADR 0002 D6)**: kagent CRD가 없어도 SOC는 AKS 네이티브로
  돈다. kagent는 추가 계층이지 대체가 아니다.
- **정직한 노출**: 대시보드는 read-only replay 계층(신규 verdict 미생성). 외부
  공개는 대시보드만. 도메인 없는 폴백은 평문 HTTP로 정직하게 표기(가짜 TLS 없음).
- **coarse MCP 툴**: LangGraph 노드를 개별 CRD로 쪼개지 않는다. MCP 툴 1개가
  기존 hotpath HTTP 표면을 감싼다(fried-pollack `run_engagement` 미러).

## 아키텍처

### 불변 (기존)
- `agents/graph.py` LangGraph `StateGraph(SOCState)`
- `soc-hotpath` Deployment(A, single-replica, `POST /alert`)
- `soc-learning` Deployment(B, 백그라운드 루프)
- `deploy/argocd` app-of-apps, `deploy/k8s` 워크로드

### 신규
```
kagent 플랫폼 (Helm 0.9.9, ns=kagent)          ← ArgoCD sync-wave 0
  ├─ ModelConfig(AzureOpenAI)                  ← kagent 오케스트레이터 전용 LLM
  └─ Agent(Declarative) soc-orchestrator
       └─ RemoteMCPServer(SSE) → soc-toolserver

soc-toolserver (Deployment + ClusterIP:8080)  ← 신규. MCP over SSE
  └─ tool analyze_alert(alert_json)
       → HTTP POST soc-hotpath.dah-soc.svc:80/alert → verdict/severity 반환

soc-dashboard (Deployment + ClusterIP:80→8791) ← 신규. 대시보드 컨테이너화
  └─ FastAPI, root_path=/dashboard, 무인증, read-only

Ingress (app-routing managed nginx)            ← 신규. 대시보드만 외부 노출
  host=${DOMAIN}, path /dashboard → soc-dashboard
```

hotpath / learning / toolserver = ClusterIP(외부 차단). 대시보드만 Ingress 경유.

## 컴포넌트

### 1. soc-toolserver (신규 MCP 서버)
- **책임**: SOC ops를 MCP 툴로 노출. 최초 coarse 툴 `analyze_alert(alert: json)`
  — 내부적으로 `soc-hotpath.dah-soc.svc.cluster.local:80/alert`에 HTTP POST하고
  verdict/severity JSON을 그대로 반환.
- **의존**: hotpath Service(in-cluster). kagent Agent가 SSE로 이 서버를 호출.
- **인터페이스**: MCP over SSE, `/sse` 엔드포인트, port 8080. `MCP_TRANSPORT=sse`.
  hardened securityContext(runAsNonRoot, drop ALL, seccomp) — fried-pollack 미러.
- **구현**: 신규 `app/toolserver.py` (또는 `tools/mcp/`), 같은 이미지에 새 command
  `python -m app.toolserver`. 결정론: hotpath 응답을 가공 없이 전달.
- **불확실**: 설치된 kagent CRD가 SSE vs STREAMABLE_HTTP 어느 쪽을 요구하는지 —
  설치 시 CRD 스키마 확인 후 protocol 확정.

### 2. soc-dashboard (컨테이너화 + /dashboard prefix)
- **현재 gap**: `app/dashboard.py`는 라우트가 `/`·`/static`·`/api`·`/events`이고
  Dockerfile CMD·k8s 매니페스트 어디에도 없다(standalone 실행).
- **컨테이너화**: 같은 이미지, 새 Deployment `command: [python,-m,app.dashboard]`.
  Service ClusterIP 80→`dashboard_port`(8791). healthz/readyz 추가(`app/health.py`
  패턴 대시보드에도 결선).
- **`/dashboard` prefix 처리**:
  - Ingress path `/dashboard(/|$)(.*)` + nginx `rewrite-target: /$2`
  - FastAPI `root_path` 신규 설정 `dashboard_root_path`(기본 `/dashboard`) →
    생성 링크·openapi prefix 정합
  - `app/dashboard_static/index.html` 자산 참조를 상대경로/`root_path` 기준으로
    확인·수정(구현 단계 verify). SSE `/events`·`/api/*` fetch도 prefix 기준.
- **무인증**: read-only replay(`demo_snapshots/`)만 서빙. write 엔드포인트 없음,
  시크릿 노출 없음. 심사 공개 특성상 인증 미적용.

### 3. kagent 플랫폼 + CRD
- Helm `ghcr.io/kagent-dev/kagent/helm` 0.9.9(`kagent-crds` + `kagent`),
  `deploy/kagent/values.yaml` — 내장 에이전트 전부 비활성, Azure OpenAI provider.
- `ModelConfig`(AzureOpenAI): `apiKeySecret: kagent-azure-openai`, endpoint/deployment
  는 Settings/시크릿에서. **SOC 엔진 LLM과 별개** — 오케스트레이터 전용.
- `Agent`(Declarative) `soc-orchestrator`: system message로 SOC 트리아지 범위 한정,
  tool = `soc-toolserver`의 `analyze_alert`만.
- 기존 `deploy/k8s/50-kagent-toolserver.yaml`(v1alpha1, 죽은 `soc-learning/mcp`
  가리킴)은 **신규 soc-toolserver를 가리키도록 교체**하고 설치 CRD 버전에 정합.

## 도메인 파라미터 + 판정단 폴백

`DOMAIN` 변수 하나로 두 경로 커버:

| | `DOMAIN=soc.pollak.store` | `DOMAIN` 미지정(판정단) |
|---|---|---|
| Ingress host | soc.pollak.store | app-routing LB 공인 IP의 `*.cloudapp.azure.com`(dns-label 부여) |
| TLS | cert-manager + Let's Encrypt HTTP-01 | HTTP only(인증서 없음, 정직한 평문) |
| 접속 URL | https://soc.pollak.store/dashboard | http://\<azure-hostname\>/dashboard |

- 배포 스크립트 `deploy/scripts/deploy-soc.sh`가 `DOMAIN` env를 읽어 Ingress
  매니페스트를 `envsubst`(fried-pollack의 sed 주입 패턴). 미지정 시 LB 공인 IP에
  DNS 라벨을 부여해 Azure 기본 호스트명을 도출하고 TLS 블록을 생략.
- **GitOps 정합**: Ingress host는 kustomize overlay 변수로 커밋. 스크립트가 overlay를
  패치 후 apply/commit. 판정단은 자기 `DOMAIN`(또는 미지정)으로 재패치.
- `deploy/JUDGE-DEPLOY.md` + `deploy/judge.env.example`: 도메인 없이
  `./deploy-soc.sh`만으로 Azure 기본값 접속. 자기 구독·AOAI 키만 채우면 됨.

## 배포 흐름 (deploy/scripts/deploy-soc.sh)

```
1. az aks get-credentials -g dah-soc-rg -n <aks>        # 기존 클러스터 재사용
2. az aks approuting enable -g dah-soc-rg -n <aks>       # managed nginx
3. helm upgrade -i kagent-crds / kagent (0.9.9, values)
4. kubectl create secret generic kagent-azure-openai \  # AOAI 키(git 미커밋)
     --from-literal=... --dry-run=client -o yaml | kubectl apply -f -
5. DOMAIN 해석 → Ingress envsubst → kubectl apply(또는 overlay 패치→ArgoCD)
6. soc-toolserver / soc-dashboard / kagent CRD ArgoCD sync-wave 반영
7. 대시보드 URL 출력(DOMAIN 유무에 따라 https/http)
```

## 시크릿 / 신규 Settings

- `kagent-azure-openai`(AOAI 키) — imperative 생성, git 미커밋(fried-pollack 패턴).
  `kagent` + `dah-soc` 양 네임스페이스.
- 신규 Settings: `dashboard_root_path`(기본 `/dashboard`). 기존
  `dashboard_public_url`/`dashboard_host`/`dashboard_port` 재사용.
- `.env.example`에 `AZURE_OPENAI_*`(kagent ModelConfig용) + `dashboard_root_path`,
  `DOMAIN` 예제 추가.

## 테스트 / 게이트

- soc-toolserver → hotpath 왕복 스모크(mock hotpath로 `analyze_alert` 검증).
- 대시보드 `/dashboard` prefix rewrite 정합 정적 테스트(root_path 하 링크·fetch 경로).
- 대시보드 healthz/readyz 결선 테스트.
- Ingress 매니페스트 `envsubst`(DOMAIN 유/무) 렌더 스냅샷 테스트.
- 기존 CLAUDE.md 게이트(black/ruff/mypy/pytest) 통과.

## 미검증 가정 (구현 초입 verify)

1. **dah-soc AKS 존재/이름** — `az aks get-credentials` 첫 스텝에서 드러남
   (memory azure-infra: `dah-soc-rg` + `dah-soc-rg-aks-nodes`).
2. **app-routing addon 활성 가능** — 기존 클러스터에 addon enable 가능 여부.
3. **설치 kagent CRD 버전/스키마** — SSE vs STREAMABLE_HTTP, v1alpha1 vs v1alpha2.
   Helm 설치 후 `kubectl get crd` 로 확정.
4. **index.html 자산 참조 형태** — 절대경로면 root_path 하 깨짐. 구현 시 수정.

## 범위 밖 (YAGNI)

- LangGraph 노드의 kagent-네이티브 CRD 분해(재작성).
- 대시보드 외 서비스의 외부 노출.
- 신규 AKS Bicep 프로비저닝(기존 클러스터 재사용).
- 인증/RBAC 대시보드(심사 공개 무인증 채택).
- Argo Rollouts canary(`_workspace` 제안은 별건).
