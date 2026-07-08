# UAV AI SOC — CI/CD Harness

방산 UAV 보안 SaaS(LangGraph 멀티 에이전트 + Azure Sentinel) 프로젝트 전용 CI/CD 파이프라인
설계·강화·검증 하네스. harness-100의 `20-cicd-pipeline`을 기반으로 `21-code-reviewer`,
`24-test-automation`, `28-security-audit`의 게이트를 통합하고, **이 저장소의 실제 스택**
(GitHub Actions + ArgoCD GitOps + AKS + kagent)에 맞게 커스터마이즈했다.

## 이 하네스가 아는 프로젝트 사실

기존 파이프라인을 새로 짜는 게 아니라 **강화/확장**하는 것을 전제로 한다.

| 항목 | 현재 상태 |
|------|----------|
| CI | `.github/workflows/ci.yml` — lint(black/ruff/mypy) → test(pytest) → CodeQL SAST → dependency-review |
| CD(미채택) | `deploy/ci/build-deploy.example.yml` — G2 회귀게이트 → GHCR build/push → GitOps 태그 bump |
| 배포 | AKS, ArgoCD(GitOps), 트랙 A(hotpath)/B(learning) 이중 디플로이, kagent toolserver |
| 레지스트리 | `ghcr.io/s1ns3nz0/uav-ai-soc` |
| 모니터링 | Prometheus ServiceMonitor + Grafana 대시보드 (`deploy/monitoring/`) |
| 도메인 게이트 | `benchmarks/` — FP-재발률, ATLAS 레드팀(결정론 G2) |
| AI 레드팀 | `benchmarks/run_atlas_redteam.py`(ATLAS), `run_redteam_skeleton.py`(PyRIT/Garak 통합), `docs/benchmarks-ci.md`(트랙 A/B 게이트) |
| 코드 규약 | `CLAUDE.md`, `.claude/rules/python-conventions.md`, `pyproject.toml`(black/ruff/mypy/pytest) |

## 구조

```
.claude/
├── agents/
│   ├── pipeline-designer.md      — 스테이지/브랜치/배포 전략 (GitHub Actions + ArgoCD)
│   ├── infra-engineer.md         — Dockerfile·GHCR·AKS·kagent·시크릿·OIDC
│   ├── test-engineer.md          — pytest·__tests__·Azure mock·커버리지·G2 벤치 게이트
│   ├── quality-gate.md           — black/ruff/mypy 강제 + 코드리뷰(스타일·보안·성능·아키)
│   ├── security-scanner.md       — SAST·SCA·시크릿·컨테이너·SBOM·공급망(SSDF/SLSA)
│   ├── ai-redteam-engineer.md    — AI/LLM 적대 레드팀(ATLAS·PyRIT/Garak·인젝션·포이즌)
│   ├── monitoring-specialist.md  — DORA + AI-SOC 메트릭(에이전트 레이턴시·토큰비용·RAGAS)
│   └── pipeline-reviewer.md      — 교차검증·운영준비성·방산 컴플라이언스
├── skills/
│   ├── uav-soc-cicd/skill.md         — 오케스트레이터 (팀 조율, 워크플로우)
│   ├── pipeline-security-gates/skill.md  — 방산급 보안 게이트(SBOM·OIDC·action 핀)
│   ├── ai-red-teaming/skill.md           — AI 적대 레드팀(ATLAS TTP·OWASP LLM·게이트 임계)
│   ├── deployment-strategies/skill.md    — AKS/ArgoCD/Argo Rollouts 배포·롤백
│   └── python-quality-gates/skill.md     — black/ruff/mypy/pytest 설정·임계값
└── HARNESS.md                    — 이 파일
```

## 사용법 (Claude Code)

자연어로 트리거한다:

- "CI/CD 파이프라인 강화해줘" / "uav-soc-cicd 돌려줘"
- "CD 워크플로 만들어줘" (example를 정식 `.github/workflows/cd.yml`로 승격)
- "보안 게이트 추가해줘" (보안 모드)
- "이 파이프라인 리뷰해줘" (리뷰 모드)

## 산출물

모든 산출물은 저장소 루트의 `_workspace/`에 저장된다 (`.gitignore`에 추가 권장):

- `00_input.md` — 입력 정리 + 기존 파이프라인 인벤토리
- `01_pipeline_design.md` — 파이프라인 설계
- `02_pipeline_config/` — 생성된 YAML (ci.yml, cd.yml, Dockerfile 패치 등)
- `03_monitoring.md` — 모니터링/알림 설계
- `04_security_scan.md` — 보안 게이트 설계 + SBOM 정책
- `04b_quality_gate.md` — 품질/코드리뷰 게이트
- `04c_test_strategy.md` — 테스트 전략 + 커버리지/벤치 게이트
- `04d_ai_redteam.md` — AI 적대 레드팀 게이트(ATLAS·PyRIT, 트랙 A/B)
- `05_review_report.md` — 최종 리뷰 보고서

## 원본 출처

harness-100 (revfactory) `ko/20·21·24·28` 통합·커스터마이즈.
