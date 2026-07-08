---
name: pipeline-security-gates
description: "방산급 CI/CD 보안 게이트 설계 가이드. SAST/SCA/시크릿/컨테이너/IaC 스캔 도구 선택, 게이트 배치·임계값(CVSS), SBOM 생성, 공급망 무결성(GitHub Actions SHA 핀·OIDC·cosign 서명·SLSA provenance), NIST SSDF/800-204D 매핑을 제공하는 security-scanner 확장 스킬. '보안 게이트', 'SAST', 'SCA', '시크릿 탐지', '컨테이너 스캔', 'SBOM', '공급망 보안', 'OIDC', 'action 핀' 등에 사용한다."
---

# Pipeline Security Gates — 방산급 CI/CD 보안 게이트 가이드

security-scanner 에이전트가 보안 설계 시 활용하는 도구·게이트·임계값·공급망 무결성 레퍼런스.
방산 컨텍스트 → **공급망 무결성과 감사 추적성**을 일반 SaaS보다 강하게 요구한다.

## 대상 에이전트

`security-scanner` — 이 스킬의 패턴을 보안 게이트 설계에 직접 적용한다.

## 스캔 유형 & 도구 매트릭스

| 유형 | 대상 | 시점 | 권장 도구(이 프로젝트) |
|------|------|------|----------------------|
| Secret | 코드/이력 | 커밋/PR | **Gitleaks**, detect-secrets(pre-commit) |
| SAST | 소스 | PR/push | **CodeQL**(security-extended) + **Bandit**/Semgrep(Python) |
| SCA | 의존성 | PR/빌드 | **dependency-review** + **pip-audit** / Trivy |
| Container | 이미지 | build 후 | **Trivy** / Grype |
| IaC | deploy/k8s | PR | **Checkov** / kubescape |
| SBOM | 이미지/소스 | build 후 | **Syft**(anchore/sbom-action) |
| 공급망 | workflows | PR | **actionlint** + SHA 핀 검사, **zizmor** |

> Python 특화: Bandit(보안 패턴), pip-audit(PyPI CVE). ruff의 `S`(bandit) 규칙과 중복되니
> quality-gate와 역할 분담(린트=빠른 규칙, Bandit=심층).

## 게이트 배치 (이 프로젝트 파이프라인)

```
[Pre-Commit]   Gitleaks, detect-secrets, ruff-S
[CI: PR/Push]  Gitleaks(diff) → CodeQL+Bandit(SAST) → dependency-review+pip-audit(SCA)
               → Checkov(IaC, deploy/k8s 변경 시)
[CI: build 후] Trivy(image) → Syft(SBOM) → cosign sign+attest
[CD: main]     G2 게이트(benchmarks) → 서명 검증 → ArgoCD 동기화
```

## 차단/경고 정책 (CVSS v3.1)

| 유형 | Critical | High | Medium | Low |
|------|----------|------|--------|-----|
| Secret | 차단 | 차단 | 차단 | 경고 |
| SAST | 차단 | 차단 | 경고 | 무시 |
| SCA(CVE) | 차단 | 차단 | 경고 | 무시 |
| Container | 차단 | 경고 | 무시 | 무시 |
| IaC | 차단 | 경고 | 무시 | 무시 |

| 등급 | 점수 | SLA | 액션 |
|------|------|-----|------|
| Critical | 9.0~10 | 24h | 배포 차단 |
| High | 7.0~8.9 | 7d | 배포 차단 |
| Medium | 4.0~6.9 | 30d | 경고 |
| Low | <4.0 | 90d | 정보 |

## 공급망 무결성 (방산 핵심)

### 1) GitHub Actions SHA 핀
태그(`@v4`)는 변조 가능 → 모든 `uses:`를 **커밋 SHA**로 핀 고정. Dependabot으로 SHA 갱신.
```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
```

### 2) OIDC (장기 자격증명 제거)
Azure/GHCR 인증을 federated OIDC로 — 저장된 시크릿(클라이언트 시크릿) 폐기.
```yaml
permissions: { id-token: write, contents: read }
- uses: azure/login@<SHA>
  with: { client-id: ${{ secrets.AZURE_CLIENT_ID }}, tenant-id: ${{ secrets.AZURE_TENANT_ID }}, subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }} }
```

### 3) 서명 & 증명 (cosign, keyless)
```yaml
- uses: sigstore/cosign-installer@<SHA>
- run: cosign sign --yes ghcr.io/s1ns3nz0/uav-ai-soc@${DIGEST}
- run: cosign attest --yes --predicate sbom.spdx.json --type spdxjson ghcr.io/s1ns3nz0/uav-ai-soc@${DIGEST}
```

### 4) SLSA Provenance
`actions/attest-build-provenance`로 빌드 출처 증명 생성 → 배포 시 검증.

## SBOM

| 도구 | 포맷 | 비고 |
|------|------|------|
| Syft | SPDX, CycloneDX | 가장 포괄적, sbom-action |
| Trivy | SPDX, CycloneDX | 스캔과 통합 |

SBOM 필수 정보: 패키지명·버전·라이선스, 의존성 트리, 해시(무결성), 공급자.

## 핵심 스니펫

```yaml
gitleaks:
  steps:
    - uses: actions/checkout@<SHA>   # with fetch-depth: 0
    - uses: gitleaks/gitleaks-action@<SHA>

bandit:
  steps:
    - run: pip install bandit
    - run: bandit -r agents core tools -ll   # High 이상 차단

trivy-image:
  steps:
    - uses: aquasecurity/trivy-action@<SHA>
      with: { scan-type: image, image-ref: ghcr.io/s1ns3nz0/uav-ai-soc:${{ github.sha }}, severity: CRITICAL, exit-code: '1' }

sbom:
  steps:
    - uses: anchore/sbom-action@<SHA>
      with: { image: ghcr.io/s1ns3nz0/uav-ai-soc:${{ github.sha }}, format: spdx-json }
```

## 허용 목록 (예외 — 사유·만료·승인 필수)
```
# .trivyignore
CVE-2024-12345  # 영향 없음(미사용 기능). 만료: 2026-12-31. 승인: @security-team
```

## 컴플라이언스 매핑 (참고)

| 통제 | SSDF(800-218) | C-SCRM(800-204D) |
|------|---------------|------------------|
| 시크릿 관리/OIDC | PW.1, PS.1 | - |
| SAST/SCA | PW.7, PW.8 | - |
| SBOM | PS.3 | MA-2 |
| action 핀/서명/provenance | PS.2 | PO-1, MA-3 |

> 최종 워크플로는 설치된 `devsecops-redteam` 스킬로 SSDF/800-204D/DoD DevSecOps 기준
> 레드팀 검증을 권장한다.
