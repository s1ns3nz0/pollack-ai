# UAV AI SOC CI/CD — Phase 1 Input

## 사용자 요청

UAV 대상 AI SOC 플랫폼의 CI/CD 파이프라인을 만든다. 핵심 요구:

- Azure AI(Azure OpenAI/Sentinel) 인프라 사용
- 인프라는 **kagent**를 통해 **GitOps**(ArgoCD)로 관리
- AI 프레임워크 준수 여부를 **OSCAL**(NIST AI RMF 1.0 → OSCAL 1.1.2)로 추적·게이트화

## 사용자 결정 사항

| 항목 | 결정 |
|------|------|
| 범위 | 풀 파이프라인 강화 + OSCAL 통합 (8명 전원) |
| OSCAL 게이트 차단 정책 | 스키마 검증 + POAM 미해결 위험 임계값 차단 |
| OSCAL 산출물 생성 위치 | CI에서 `compliance/oscal/build_oscal.py` 실행해 산출 |
| `check_gates.py` | test-engineer가 신규 작성 |

## 프로젝트 사실

| 항목 | 값 |
|------|-----|
| 언어/프레임워크 | Python 3.11+, LangGraph, Azure OpenAI, GraphRAG |
| CI 도구 | GitHub Actions |
| 배포 | AKS + ArgoCD GitOps (트랙 A=hotpath, B=learning), kagent toolserver |
| 레지스트리 | `ghcr.io/s1ns3nz0/uav-ai-soc` |
| 브랜치 | `main`(prod), `develop`(staging), `feature/*` |
| 규약 | `CLAUDE.md`, `.claude/rules/python-conventions.md`, `pyproject.toml` |

## 기존 자산 인벤토리

### CI (`.github/workflows/ci.yml`) — 존재

스테이지: `lint(black/ruff/mypy)` → `test(pytest)` → `codeql(SAST security-extended)` → `dependency-review(fail-on-severity: high)`

- `permissions: contents: read` (최소권한 OK)
- PR/push to main·develop 트리거
- **갭**: 시크릿 탐지(Gitleaks), 컨테이너 스캔(Trivy), SBOM(Syft), 공급망 무결성(action SHA 핀/OIDC/cosign/SLSA), 커버리지 임계, OSCAL 검증 게이트, AI 레드팀 게이트, G2 회귀게이트

### CD 예시 (`deploy/ci/build-deploy.example.yml`) — example 상태, 미승격

- `G2 게이트 → build/push GHCR → deploy/k8s 이미지 태그 bump (ArgoCD 폴링 트리거)`
- `check_gates.py` **미구현** — 현재는 벤치마크 비정상 종료에 의존
- **갭**: OIDC(현재 PAT 시크릿), 컨테이너 스캔, SBOM/서명, 트랙 A/B 분리 배포, 카나리/롤백, 환경 분리(staging/prod)

### 인프라

- `deploy/Dockerfile`: 1개 (정밀 검토 필요)
- `deploy/k8s/`: 00-namespace, 10-configmap, 15-secret.example, 20-ragflow, 30-deployment-a-hotpath, 40-deployment-b-learning, 50-kagent-toolserver
- `deploy/argocd/`: project.yaml, root-app.yaml, apps/{kube-prometheus-stack, soc-monitoring, soc}.yaml
- `deploy/monitoring/`: servicemonitor.yaml, grafana-dashboard.yaml
- `deploy/sentinel-tables/`: Azure DCR + deploy.sh

### Benchmarks

- `run_atlas_redteam.py`, `run_fp_recurrence.py`, `run_benchmarks.py`, `run_kpi.py`, `run_redteam_skeleton.py`
- **`check_gates.py` 미구현** — test-engineer가 신규 작성

### Compliance (OSCAL) — 이미 구축됨

- `compliance/oscal/build_oscal.py` (44KB 단일 소스 생성기)
- `catalog/nist-ai-rmf-catalog.json` (AI RMF 72 서브카테고리)
- `profile/uav-soc-ai-rmf-profile.json` (35개 채택)
- `component-definition/uav-soc-components.json` (8개 컴포넌트)
- `ssp/uav-soc-ssp.json` (구현 15/부분 19/계획 1)
- `poam/uav-soc-poam.json` (미해결 갭)
- `dashboard/index.html` + `data.js`

**컴포넌트 → 통제 매핑**:
- AI Red Team Gate (PyRIT/ATLAS) → MEASURE 2.7, 2.6, 3.1, 3.2, GOVERN 4.3
- Supply Chain Integrity (SBOM/OIDC/서명) → GOVERN 6.1, MAP 4.1, MANAGE 3.1
- Observability → MEASURE 2.4, MANAGE 4.1, 3.2
- Deployment & GitOps → MANAGE 2.4, MAP 3.5
- Runtime Defense Guardrails → MAP 4.2, MEASURE 2.6, 2.9
- CI/CD Pipeline → MEASURE 2.1, 2.3, MANAGE 1.3
- Incident Response → MANAGE 4.3, 2.3, GOVERN 4.3
- Governance & Policy → GOVERN 1.x, 2.1, MAP 1.x

## 본 작업의 핵심 목표

1. **기존 CI 강화** — 시크릿/컨테이너/SBOM/공급망 무결성/커버리지/AI 레드팀 게이트 추가
2. **CD example 승격** — `cd.yml`로 본격 배포 워크플로 작성 (OIDC + 컨테이너 스캔 + SBOM + 서명 + 카나리)
3. **OSCAL 통합** — `build_oscal.py`를 CI에서 실행해 산출물 생성, 스키마 검증 + POAM high/critical 임계값으로 배포 차단
4. **`check_gates.py` 신규 작성** — FP재발/ATLAS/KPI 임계를 종합한 G2 게이트, 실패 시 OSCAL POAM에 자동 항목 추가
5. **AI 레드팀 게이트** — PyRIT/Garak 캠페인, 결정론 회귀, MITRE ATLAS 매핑
6. **모니터링 확장** — DORA + AI-SOC 메트릭 + OSCAL 컴플라이언스 추세

## 보안·규약 불변 원칙

- 시크릿 하드코딩 금지 → GitHub Secrets / Azure Key Vault / **OIDC 우선**(PAT 제거)
- GitHub Actions SHA 핀 고정 권장 (공급망)
- 최소권한 `permissions:` 명시
- `.claude/rules/python-conventions.md` 및 `CLAUDE.md` 준수
- 방산 컨텍스트 — 공급망 무결성(SBOM·서명·SLSA), 감사 추적성 최우선

## 산출물 경로 규약

- 설계 문서: `_workspace/01_*`, `_workspace/02_*`, `_workspace/03_*`, `_workspace/04*_*.md`
- 파이프라인 설정 초안: `_workspace/02_pipeline_config/` (실제 `.github/workflows/`에는 사용자 승인 후 반영)
- 리뷰: `_workspace/05_review_report.md`
- 코드(예: `check_gates.py`): `_workspace/02_pipeline_config/` 또는 실제 경로 (리뷰 후 결정)
