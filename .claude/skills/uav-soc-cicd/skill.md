---
name: uav-soc-cicd
description: "UAV AI SOC 플랫폼 전용 CI/CD 파이프라인 설계·강화·검증 풀 파이프라인. GitHub Actions + ArgoCD GitOps + AKS + kagent 스택에서 스테이지 설계, YAML 생성, 보안 게이트(SAST/SCA/SBOM/공급망), 품질 게이트(black/ruff/mypy), 테스트 게이트(pytest+G2 벤치), AI 적대 레드팀 게이트(MITRE ATLAS·PyRIT·프롬프트 인젝션·RAG 포이즌), 모니터링(DORA+AI-SOC)을 에이전트 팀이 협업하여 수행한다. 'CI/CD 파이프라인 만들어/강화해줘', 'CD 워크플로 만들어줘', 'GitHub Actions', '배포 자동화', '보안 게이트 추가', 'AI 레드팀 게이트 추가', '파이프라인 리뷰', 'ArgoCD 배포', 'AKS 배포' 등에 사용한다. 단, 실제 클라우드 리소스 프로비저닝과 클러스터 운영은 범위가 아니다."
---

# UAV AI SOC CI/CD — 파이프라인 설계·강화·검증

방산 UAV 보안 SaaS(LangGraph 멀티 에이전트 + Azure Sentinel) 저장소의 CI/CD 파이프라인을
에이전트 팀이 협업하여 설계→설정 생성→보안/품질/테스트 게이트 통합→모니터링까지 수행한다.

**중요 — 이 저장소는 이미 파이프라인이 있다.** 새로 짜는 게 아니라 기존 자산을 인벤토리하고
**강화/확장**하는 것을 기본 전제로 한다. 기존 파일을 무시하거나 덮어쓰지 않는다.

## 실행 모드

**에이전트 팀** — 8명이 SendMessage로 직접 통신하며 교차 검증한다.

## 에이전트 구성

| 에이전트 | 파일 | 역할 | 타입 |
|---------|------|------|------|
| pipeline-designer | `.claude/agents/pipeline-designer.md` | 스테이지/브랜치/배포 전략, ArgoCD GitOps | general-purpose |
| infra-engineer | `.claude/agents/infra-engineer.md` | Dockerfile, GHCR, AKS, kagent, 시크릿, OIDC | general-purpose |
| test-engineer | `.claude/agents/test-engineer.md` | pytest, `__tests__`, Azure mock, 커버리지, G2 벤치 | general-purpose |
| quality-gate | `.claude/agents/quality-gate.md` | black/ruff/mypy 강제 + 코드리뷰 | general-purpose |
| security-scanner | `.claude/agents/security-scanner.md` | SAST/SCA/시크릿/컨테이너/SBOM/공급망 | general-purpose |
| ai-redteam-engineer | `.claude/agents/ai-redteam-engineer.md` | AI/LLM 적대 레드팀(ATLAS·PyRIT·인젝션·포이즌) | general-purpose |
| monitoring-specialist | `.claude/agents/monitoring-specialist.md` | DORA + AI-SOC 메트릭, 알림, 대시보드 | general-purpose |
| pipeline-reviewer | `.claude/agents/pipeline-reviewer.md` | 교차검증, 운영준비성, 방산 컴플라이언스 | general-purpose |

> **레드팀 두 종류 구분**: `ai-redteam-engineer`는 **AI 모델/에이전트 자체**(LLM·RAG·메모리)를
> 공격하고, `security-scanner`(+설치된 `devsecops-redteam` 스킬)는 **워크플로 YAML 공급망
> 컴플라이언스**를 레드팀한다. 둘은 상호 보완이며 역할이 겹치지 않는다.

## 프로젝트 사실 (오케스트레이터가 팀에 항상 전달)

| 항목 | 값 |
|------|-----|
| 언어/프레임워크 | Python 3.11+, LangGraph, Azure OpenAI, GraphRAG |
| CI 도구 | **GitHub Actions** |
| 배포 | AKS + **ArgoCD GitOps** (트랙 A=hotpath, B=learning), kagent toolserver |
| 레지스트리 | `ghcr.io/s1ns3nz0/uav-ai-soc` |
| 브랜치 | `main`(prod), `develop`(staging), `feature/*` |
| 기존 CI | `.github/workflows/ci.yml` (lint→test→CodeQL→dependency-review) |
| 기존 CD(예시) | `deploy/ci/build-deploy.example.yml` (G2 게이트→build/push→GitOps bump) |
| 도메인 게이트 | `benchmarks/run_fp_recurrence.py`, `benchmarks/run_atlas_redteam.py`, `benchmarks/check_gates.py` |
| 모니터링 | `deploy/monitoring/` (Prometheus ServiceMonitor + Grafana) |
| 규약 | `CLAUDE.md`, `.claude/rules/python-conventions.md`, `pyproject.toml` |

## 워크플로우

### Phase 1: 준비 + 인벤토리 (오케스트레이터 직접 수행)

1. 사용자 요청에서 **범위와 모드**를 판별한다 (아래 "작업 규모별 모드").
2. **기존 자산 인벤토리** — 다음을 읽고 현황을 파악한다:
   - `.github/workflows/*.yml`, `deploy/ci/*`, `deploy/Dockerfile`
   - `deploy/k8s/*`, `deploy/argocd/*`, `deploy/monitoring/*`
   - `pyproject.toml`, `.pre-commit-config.yaml`, `benchmarks/`
3. 저장소 루트에 `_workspace/` 디렉토리를 생성한다 (`.gitignore`에 없으면 추가 권장).
4. 입력 + 기존 파이프라인 인벤토리를 `_workspace/00_input.md`에 정리한다.
5. **기존 설정은 절대 직접 덮어쓰지 않는다.** 변경안은 `_workspace/02_pipeline_config/`에
   새로 쓰고, 최종 단계에서 사용자가 승인한 것만 실제 경로에 반영한다.

### Phase 2: 팀 구성 및 실행

| 순서 | 작업 | 담당 | 의존 | 산출물 |
|------|------|------|------|--------|
| 1 | 파이프라인 설계 | pipeline-designer | 없음 | `01_pipeline_design.md` |
| 2a | 인프라/배포 구성 | infra-engineer | 1 | `02_pipeline_config/`, `02_infra_config.md` |
| 2b | 보안 게이트 설계 | security-scanner | 1 | `04_security_scan.md` |
| 2c | 품질 게이트 설계 | quality-gate | 1 | `04b_quality_gate.md` |
| 2d | 테스트 전략 | test-engineer | 1 | `04c_test_strategy.md` |
| 2e | AI 레드팀 설계 | ai-redteam-engineer | 1 | `04d_ai_redteam.md` |
| 3 | 모니터링 설계 | monitoring-specialist | 1, 2a | `03_monitoring.md` |
| 4 | 파이프라인 리뷰 | pipeline-reviewer | 2a~2e, 3 | `05_review_report.md` |

작업 2a/2b/2c/2d/2e는 **병렬 실행**한다 (모두 작업 1에만 의존).

**팀원 간 소통 흐름:**
- pipeline-designer 완료 → 각 게이트 담당(security/quality/test)에게 스테이지 배치·차단 정책 전달, infra-engineer에게 러너/시크릿/배포 타깃 전달, monitoring-specialist에게 배포 전략·롤백 조건 전달
- infra-engineer 완료 → security-scanner에게 이미지/의존성 경로 전달, monitoring-specialist에게 메트릭 엔드포인트 전달
- test-engineer ↔ quality-gate ↔ security-scanner ↔ ai-redteam-engineer → 게이트 순서/중복 조율 (lint→test→SAST→SCA→build→container scan→SBOM→AI 레드팀/G2 게이트). test-engineer와 ai-redteam-engineer는 `run_atlas_redteam.py`·`check_gates.py`를 공유하므로 중복 잡을 만들지 않도록 조율한다.
- pipeline-reviewer는 모든 산출물을 교차 검증. 🔴 필수 수정 발견 시 해당 에이전트에 수정 요청 → 재작업 → 재검증 (최대 2회)

### Phase 3: 통합 및 최종 산출물

1. `_workspace/` 내 모든 파일을 확인한다.
2. 리뷰 보고서의 🔴 필수 수정이 모두 반영되었는지 확인한다.
3. **실제 반영**: 사용자에게 변경 파일 목록(diff 요약)을 제시하고, 승인받은 항목만
   `.github/workflows/`, `deploy/` 등 실제 경로에 적용한다.
4. 최종 요약을 사용자에게 보고한다.

## 작업 규모별 모드

| 사용자 요청 패턴 | 모드 | 투입 에이전트 |
|----------------|------|-------------|
| "CI/CD 파이프라인 강화/풀 설계해줘" | **풀** | 8명 전원 |
| "CD 워크플로 만들어줘" (example 승격) | **CD** | pipeline-designer + infra-engineer + monitoring-specialist + pipeline-reviewer |
| "보안 게이트 추가해줘" | **보안** | security-scanner + pipeline-reviewer |
| "AI 레드팀/적대 견고성 게이트 추가해줘" | **AI 레드팀** | ai-redteam-engineer + test-engineer + pipeline-reviewer |
| "품질/린트 게이트 강화해줘" | **품질** | quality-gate + pipeline-reviewer |
| "테스트/커버리지 게이트 추가해줘" | **테스트** | test-engineer + pipeline-reviewer |
| "이 파이프라인 리뷰해줘" | **리뷰** | pipeline-reviewer 단독 |

## 데이터 전달 프로토콜

| 전략 | 방식 | 용도 |
|------|------|------|
| 파일 기반 | `_workspace/` | 주요 산출물 저장·공유 |
| 메시지 기반 | SendMessage | 실시간 핵심 정보, 수정 요청 |
| 태스크 기반 | TaskCreate/TaskUpdate | 진행 추적, 의존 관리 |

## 에러 핸들링

| 에러 유형 | 전략 |
|----------|------|
| 배포 대상 모호 | 기존 AKS+ArgoCD 구조를 기본 전제로 |
| 도메인 게이트 미구현(check_gates.py) | benchmarks 비정상 종료를 게이트로 대체, 리뷰에 명시 |
| 에이전트 실패 | 1회 재시도 → 실패 시 산출물 없이 진행, 리뷰에 누락 명시 |
| 기존 YAML 파싱 실패 | 수동 분석 후 신규 파일 제안 |
| 🔴 발견 | 해당 에이전트 수정 요청 → 재검증 (최대 2회) |

## 보안·규약 불변 원칙 (전 에이전트 공통)

- 시크릿 하드코딩 절대 금지 → GitHub Secrets / Azure Key Vault / OIDC
- GitHub Actions는 **SHA 핀 고정** 권장(공급망), 최소 권한 `permissions:` 명시
- 모든 변경은 `.claude/rules/python-conventions.md`와 `CLAUDE.md`를 준수
- 방산 컨텍스트 — 공급망 무결성(SBOM·서명·SLSA), 감사 추적성을 우선한다

## 에이전트별 확장 스킬

| 스킬 | 대상 | 역할 |
|------|------|------|
| `pipeline-security-gates` | security-scanner | SAST/SCA/시크릿/컨테이너/SBOM/공급망 도구·게이트·임계값 |
| `ai-red-teaming` | ai-redteam-engineer | ATLAS TTP·OWASP LLM·PyRIT/Garak·게이트 임계·AI RMF 매핑 |
| `deployment-strategies` | pipeline-designer | AKS/ArgoCD/Argo Rollouts 배포·롤백·DORA |
| `python-quality-gates` | quality-gate, test-engineer | black/ruff/mypy/pytest 설정·임계값·커버리지 |
