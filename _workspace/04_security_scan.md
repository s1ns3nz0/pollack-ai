# CI/CD 보안 게이트 설계 (방산) — UAV AI SOC

**작성자**: security-scanner
**버전**: 1.0 (Phase 1, OSCAL 통합)
**확장 스킬**: `pipeline-security-gates`
**원칙**: Shift-left + 심층 방어, 위험 기반(CVSS v3.1), 공급망 제로트러스트, 감사 추적성 최우선
**컴플라이언스 기준**: NIST SSDF (SP 800-218), NIST SP 800-204D (C-SCRM), DoD DevSecOps Reference Design, NIST AI RMF 1.0 (OSCAL 1.1.2)

---

## 0. 요약 (TL;DR)

본 설계는 기존 `ci.yml`의 `lint → test → CodeQL → dependency-review` 4단계를 **8개 분류 14개 게이트**로 강화하고, **OSCAL 컴플라이언스 게이트** 2종(스키마 검증 + POAM 임계)을 신규 추가한다. 방산 컨텍스트에서 **공급망 무결성**(SHA 핀, OIDC keyless, cosign 서명, SLSA L3 provenance)을 핵심 차별점으로 둔다.

- **차단 게이트**: 14건 — 시크릿/SAST/SCA/컨테이너 Critical/IaC Critical/OSCAL 임계/SBOM 부재/공급망 미핀 등
- **경고 게이트**: 6건 — 컨테이너 High/Medium SAST/Medium SCA/POAM medium 추세 등
- **신규 산출물**: `check_poam_thresholds.py` (구현 완료), `.trivyignore`, `.gitleaks.toml`, `compliance.yml` 워크플로 통합
- **위임**: ai-redteam-engineer(POAM 자동 append), infra-engineer(OIDC/cosign keyless), test-engineer(coverage/G2 게이트)

---

## 1. 보안 스캔 도구 매트릭스

### 1.1 전체 매트릭스

| # | 유형 | 도구 | 대상 | 트리거(스테이지) | 임계값 (CVSS v3.1) | 차단/경고 | SSDF | 800-204D | OSCAL 통제 |
|---|------|------|------|------------------|---------------------|-----------|------|----------|------------|
| 1 | 시크릿 | **Gitleaks** | git 전체 이력 + PR diff | CI 최초(`ci.yml/secret-scan`) | 모든 매치 | **차단** | PS.1, PW.1.1 | — | MAP 4.2, MEASURE 2.7 |
| 2 | 시크릿(보조) | **detect-secrets** | pre-commit + PR | pre-commit / PR | baseline 외 신규 매치 | **차단** | PS.1 | — | MAP 4.2 |
| 3 | 시크릿(보조) | **GitHub Push Protection** | push 시 | repo 설정(Org-level) | — | **차단** | PS.1 | — | MAP 4.2 |
| 4 | SAST | **CodeQL** (security-extended, 기존) | 소스 (Python) | `ci.yml/codeql` | Critical/High | **차단** | PW.7.1, PW.7.2 | — | MEASURE 2.7, MAP 4.2 |
| 5 | SAST | **Semgrep** (`p/python`, `p/owasp-top-ten`) | 소스 (Python) | `ci.yml/semgrep` | ERROR=차단, WARNING=경고 | **차단** (ERROR) | PW.7.1 | — | MEASURE 2.7 |
| 6 | SAST(추가) | **Bandit** (선택) | `agents/ core/ tools/` | `ci.yml/semgrep` 잡 내 | HIGH 이상 | 경고 | PW.7.1 | — | MEASURE 2.7 |
| 7 | SCA | **dependency-review-action** (기존) | PR diff 의존성 | `ci.yml/dependency-review` | `fail-on-severity: high` | **차단** (PR only) | PW.4.1, PW.4.4 | SR-3 | GOVERN 6.1, MANAGE 3.1 |
| 8 | SCA | **pip-audit** | 전체 `pyproject.toml`/lock | `ci.yml/pip-audit` | High 이상 | **차단** | PW.4.1, PW.4.4 | SR-3 | MANAGE 3.1 |
| 9 | SCA | **Trivy fs** | 저장소 파일시스템(language pkgs) | `ci.yml/trivy-fs` | Critical | **차단** | PW.4.4 | SR-3 | MANAGE 3.1 |
| 10 | 컨테이너 | **Trivy image** | GHCR 이미지 (`sha-<git-sha>`) | `ci.yml/container-scan` (build 후) | Critical=차단, High≤5=경고 | **차단** (Crit), 경고 (High) | PW.4.4, PW.9.1 | SR-3, SR-4 | MANAGE 3.1 |
| 11 | 컨테이너(백업) | **Grype** | 동일 이미지 | nightly 재스캔 | Critical | 경고+이슈 발행 | RV.1.1 | SR-3 | MEASURE 3.1 |
| 12 | IaC | **Trivy config** (`--scan-type config`) | `deploy/k8s/`, `deploy/Dockerfile`, `deploy/argocd/` | `ci.yml/iac-scan` | Critical | **차단** | PW.5.1 | — | MAP 4.2 |
| 13 | IaC(보조) | **Checkov** | k8s YAML + Dockerfile | `ci.yml/iac-scan` 잡 내 | HIGH 이상 (CKV_K8S_*) | 경고 | PW.5.1 | — | MAP 4.2 |
| 14 | SBOM | **Syft** (`anchore/sbom-action`) | 이미지 + 저장소 | `ci.yml/sbom` (build 후) | 생성 실패 | **차단** | PS.3.1, PS.3.2 | SR-4, MA-2 | GOVERN 6.1, MANAGE 3.1 |
| 15 | 공급망 | **actionlint** + 자체 핀 검사 | `.github/workflows/*.yml` | `ci.yml/workflow-lint` | 미핀 `uses:` 1건 이상 | **차단** | PS.2.1 | PO-1, MA-3 | GOVERN 6.1 |
| 16 | 공급채 | **zizmor** (보조) | 동일 | `ci.yml/workflow-lint` | High 이상 | 경고 | PS.2.1 | PO-1 | GOVERN 6.1 |
| 17 | 공급망 | **cosign sign** (keyless OIDC) | GHCR 이미지 digest | `cd-*.yml/sign` | 서명 실패 | **차단** | PS.2.2, PS.3.2 | MA-3, SR-4 | GOVERN 6.1, MANAGE 3.1 |
| 18 | 공급망 | **SLSA Provenance L3** (`slsa-github-generator`) | 빌드 산출물 | `cd-*.yml/provenance` | 미생성 | **차단** | PS.2.2, PS.3.2 | PO-1, MA-3 | GOVERN 6.1 |
| 19 | 라이선스 | **Trivy license** + `pip-licenses` | 의존성 + 이미지 | `ci.yml/license-scan` | GPL/AGPL/SSPL/Commons Clause | **차단** | PW.4.1 | SR-2 | MAP 4.1 |
| 20 | OSCAL 스키마 | **compliance-trestle** + `jsonschema` | 5종 산출물 | `compliance.yml/oscal-validate` | 스키마 위반 1건 이상 | **차단** | PO.5.1 | — | GOVERN 6.1 (전체) |
| 21 | OSCAL POAM | **`check_poam_thresholds.py`** (신규) | `poam/uav-soc-poam.json` | `compliance.yml/poam-threshold` | critical=0, high≤3 | PR=경고, main=**차단** | PO.5.1, RV.2.1 | — | GOVERN 1.4, MANAGE 1.3 |

### 1.2 게이트 배치 (파이프라인 흐름)

```
[pre-commit (개발자 로컬)]
  └─ detect-secrets, ruff(S 규칙), black --check
     ↓
[CI: PR/Push — ci.yml]
  └─ setup → ┬─ secret-scan (Gitleaks)         ← 차단
             ├─ workflow-lint (actionlint+zizmor) ← 차단(미핀)
             ├─ lint (black/ruff/mypy)         ← 차단
             └─ oscal-schema (trestle validate) ← PR=경고, main=차단
     ↓
  └─ test (pytest + coverage 80%)              ← 차단
     ↓
  └─ ┬─ codeql (security-extended)             ← 차단(Crit/High)
     ├─ semgrep (p/python, p/owasp-top-ten)    ← 차단(ERROR)
     ├─ dependency-review (PR only)            ← 차단(high+)
     ├─ pip-audit                              ← 차단(high+)
     ├─ trivy-fs                                ← 차단(Critical)
     └─ iac-scan (Trivy config + Checkov)      ← 차단(Critical)
     ↓
  └─ build (docker buildx → GHCR sha-<git-sha>) ← 차단
     ↓
  └─ ┬─ container-scan (Trivy image)           ← 차단(Critical), 경고(High>5)
     ├─ license-scan (Trivy license)           ← 차단(GPL/AGPL)
     └─ sbom (Syft → spdx-json artifact 90일)  ← 차단(미생성)

[CI: compliance.yml — PR/push/nightly]
  └─ build_oscal.py (산출물 생성)
  └─ oscal-validate (trestle x5)               ← 차단
  └─ poam-threshold (check_poam_thresholds.py) ← PR=경고, main=차단

[CD: cd-staging.yml — develop]
  └─ G2 게이트 → cosign sign + SBOM attest → bump → ArgoCD sync → smoke

[CD: cd-prod.yml — main]
  └─ G2 게이트 → OSCAL 임계 강제 차단 → AI 레드팀 검증
  └─ cosign sign + SBOM attest + SLSA Provenance L3 → manual approval
  └─ bump rollouts → Canary 10/50/100 + 자동 분석 + 롤백
```

---

## 2. 게이트 차단 정책 (CVSS v3.1)

| 등급 | 점수 범위 | SLA | CI 액션 | CD 액션 |
|------|-----------|-----|---------|---------|
| Critical | 9.0 – 10.0 | 24h | **차단** (CI fail) | **차단** (배포 불가) |
| High | 7.0 – 8.9 | 7d | **차단** (SAST/SCA/IaC), 경고 (컨테이너 ≤5건) | **차단** (main), 경고 (develop) |
| Medium | 4.0 – 6.9 | 30d | 경고 (PR comment) | 경고 (대시보드) |
| Low | < 4.0 | 90d | 로깅 (artifact) | 로깅 |

> 컨테이너 High 는 OS 패키지 미패치 CVE가 다수 누적되는 현실을 반영해 **5건 초과 시 경고 → 차단으로 단계 전환**. 30일 SLA 내 미해결 시 자동 차단.

---

## 3. OSCAL 컴플라이언스 게이트 설계

### 3.1 사용자 결정 사항

- **차단 정책**: 스키마 검증 + POAM 미해결 위험 임계값 차단 (00_input.md)
- **산출물 생성**: CI에서 `build_oscal.py` 실행 → 산출 후 검증

### 3.2 스키마 검증 도구 선택

| 도구 | 채택 | 사유 |
|------|------|------|
| **compliance-trestle** (`trestle validate`) | **1차 (정식)** | OSCAL 1.1.2 공식 Python 도구. catalog/profile/component-definition/SSP/POAM 5종 모두 지원. NIST-released, 액티브 메인테넌스 |
| **jsonschema** (`pip install jsonschema`) | **2차 (보조)** | trestle 검증 실패 시 정확한 스키마 위반 위치 확인. JSON well-formed sanity |
| OSCAL CLI (Java) | 미채택 | JVM 의존, GitHub 호스티드 러너에서 JVM 부트스트랩 비용. trestle 으로 충분 |
| oscal-js | 미채택 | Node 의존, Python 생태계와 분리 |

**근거**: Python 단일 런타임에서 모두 처리되며 `compliance-trestle` 은 NIST 공식 후원으로 SSDF/AI RMF 통제 매핑 사용 사례가 표준화되어 있음.

### 3.3 검증 대상 5종 및 명령

```bash
# 1. 산출물 생성 (build_oscal.py)
python compliance/oscal/build_oscal.py compliance/oscal

# 2. 스키마 검증 (5종 각각)
trestle validate -f compliance/oscal/catalog/nist-ai-rmf-catalog.json
trestle validate -f compliance/oscal/profile/uav-soc-ai-rmf-profile.json
trestle validate -f compliance/oscal/component-definition/uav-soc-components.json
trestle validate -f compliance/oscal/ssp/uav-soc-ssp.json
trestle validate -f compliance/oscal/poam/uav-soc-poam.json

# 3. JSON well-formed 보조 확인 (sanity)
python -c "import json,glob;[json.load(open(f)) for f in glob.glob('compliance/oscal/**/*.json',recursive=True)]"

# 4. POAM 임계 검증 (신규 스크립트)
python scripts/check_poam_thresholds.py \
    compliance/oscal/poam/uav-soc-poam.json \
    --critical-max 0 --high-max 3 \
    --report-md docs/compliance/poam-report.md \
    --report-json artifacts/poam_summary.json
```

### 3.4 POAM 임계값 정책

| 환경 | critical (미해결) | high (미해결) | medium | 비고 |
|------|-------------------|---------------|--------|------|
| PR (feature/*) | 0 (경고) | 3 (경고) | 추세 (로깅) | PR 코멘트로 갭 노출, 차단 안 함 |
| develop (staging) | 0 (경고) | 5 (경고) | 추세 | staging 통과 |
| **main (prod)** | **0 (차단)** | **3 (차단)** | 추세 | **방산 컨텍스트 절대 임계** |

> **현재 POAM 실측** (`uav-soc-poam.json`, 2026-06-28 빌드):
> - critical=0, **high=1** (GOVERN 1.6 planned — AI 시스템 인벤토리 메커니즘), medium=19 (전부 partial)
> - **현 상태 main 게이트 통과** (high≤3) — 단, `GOVERN 1.6` 을 90일 내 partial 이상으로 승격 권고 (test-engineer/governance와 협업)

> **제안 임계값 사용자 확인 필요**: critical=0(고정), high=3(초기 1개월 운영 후 1로 강화 또는 5로 완화 조정 옵션). 현재 설계는 **high=3 채택**.

### 3.5 신규 스크립트 `check_poam_thresholds.py`

#### 3.5.1 배치 위치

- **개발 단계 (workspace)**: `_workspace/02_pipeline_config/scripts/check_poam_thresholds.py`
- **승인 후 (실제 경로)**: `compliance/oscal/check_poam_thresholds.py` **또는** `scripts/check_poam_thresholds.py`
  - 권장: **`compliance/oscal/`** (OSCAL 산출물과 동일 디렉토리, build_oscal.py 와 짝)
  - 대안: `scripts/` (다른 인프라 스크립트 `gen_table_testdata.py` 와 일관)

#### 3.5.2 인터페이스

```bash
python check_poam_thresholds.py [POAM_PATH] [OPTIONS]

POSITIONAL:
  POAM_PATH                  POAM JSON 경로 (기본: compliance/oscal/poam/uav-soc-poam.json)

OPTIONS:
  --critical-max INT         critical 미해결 허용 최댓값 (기본: 0, ENV: OSCAL_POAM_CRITICAL_MAX)
  --high-max INT             high 미해결 허용 최댓값 (기본: 3, ENV: OSCAL_POAM_HIGH_MAX)
  --medium-max INT           medium 허용 (기본: 9999 = 경고만, ENV: OSCAL_POAM_MEDIUM_MAX)
  --low-max INT              low 허용 (기본: 9999, ENV: OSCAL_POAM_LOW_MAX)
  --report-md PATH           Markdown 리포트 출력 경로
  --report-json PATH         JSON 요약 출력 경로
  --warn-only                임계 초과여도 exit 0 (PR/staging 경고 모드)

EXIT:
  0   임계값 통과
  1   임계값 초과 (CI 게이트 차단)
  2   입력/스키마 오류 (운영 오류)
```

#### 3.5.3 알고리즘

```
1. POAM JSON 파싱 → root["plan-of-action-and-milestones"]["poam-items"] 추출
2. 각 항목에 대해:
   a. props[name=risk] 의 한국어/영어 값(심각/높음/중간/낮음, critical/high/medium/low)을 정규화
   b. risk prop 부재 시 props[name=implementation-status] 로 폴백 (planned→high, partial→medium, implemented→low)
   c. remediation-tracking 의 마지막 entry title/description 에 "closed/completed/종결/완료/해결" 키워드 포함 시 closed 분류
3. open 항목만 심각도별 카운트
4. 임계값과 비교 → 위반 메시지 생성
5. Markdown + JSON 리포트 산출
6. exit code 0/1/2
```

#### 3.5.4 의존성

**표준 라이브러리만** (Python 3.11+): `argparse`, `json`, `os`, `sys`, `dataclasses`, `datetime`, `pathlib`, `typing.TypeGuard`. 추가 pip 설치 불필요.

#### 3.5.5 실행 검증 (2026-06-28 현재 POAM 기준)

```
| critical | 0  | 0    | OK |
| high     | 1  | 3    | OK |
| medium   | 19 | 9999 | OK |
| low      | 0  | 9999 | OK |
[GATE] 통과 (exit 0)
```

### 3.6 게이트 위치 정책

| 트리거 | 실행 | 모드 | 비고 |
|--------|------|------|------|
| `feature/*` PR | oscal-build + oscal-validate + poam-threshold(`--warn-only`) | 경고 (PR comment) | 갭 가시화 |
| push `develop` | oscal-build + oscal-validate + poam-threshold(`--warn-only --high-max 5`) | 경고 | staging 통과 |
| push `main` → `cd-prod` 사전 | oscal-build + oscal-validate + poam-threshold (`--critical-max 0 --high-max 3`) | **차단** | 카나리 전 절대 임계 |
| nightly cron | 위 전체 + 추세 대시보드 publish | 추적 | 컴플라이언스 모니터링 |

### 3.7 AI 레드팀 → POAM 자동 append 인터페이스

ai-redteam-engineer 와 협업할 인터페이스 사양:

#### 입력 (ai-redteam.yml 산출 → compliance.yml 입력)

```json
// failed_ttps.json — ai-redteam.yml 의 PyRIT/Garak/ATLAS 실패 결과
{
  "campaign_id": "nightly-2026-06-28",
  "generated": "2026-06-28T17:00:00+00:00",
  "failed_ttps": [
    {
      "atlas_id": "AML.T0051.001",            // MITRE ATLAS TTP ID
      "name": "LLM Prompt Injection (Direct)",
      "owasp_llm": "LLM01",
      "severity": "high",                      // critical/high/medium/low
      "detection_rate": 0.42,                  // 0.0~1.0
      "samples": 50,
      "first_seen": "2026-06-15T...",
      "evidence_url": "https://github.com/.../actions/runs/...",
      "suggested_controls": ["MEASURE 2.7", "MAP 4.2"]
    }
  ]
}
```

#### 처리 흐름

```
1. ai-redteam.yml 종료 시 failed_ttps.json upload-artifact
2. compliance.yml (또는 별도 poam-update.yml) 다운로드 → 다음 호출:
     python compliance/oscal/build_oscal.py compliance/oscal --append-poam failed_ttps.json
3. build_oscal.py 의 신규 옵션 --append-poam 가 MAPPINGS 에는 없는 ad-hoc POAM 항목으로 추가
   (별도 섹션 "AI Red Team Findings" 로 그룹화)
4. 변경 detect → ci-bot PR 자동 생성:
     - 제목: "compliance: AI 레드팀 캠페인 {campaign_id} → POAM {N}건 추가"
     - 본문: ATLAS TTP ID + 매핑 통제 + evidence URL
     - 라벨: compliance, ai-redteam, automated
5. PR 머지 시 다음 cd-prod 실행에서 갱신된 POAM 임계로 게이트 평가
```

#### 협의 필요 사항 (ai-redteam-engineer 와)

| 항목 | 결정 필요 |
|------|----------|
| failed_ttps.json 스키마 정식화 (위 예시 기준) | 양측 합의 |
| ai-redteam 의 severity 매핑 규칙 (ATLAS impact + 탐지율) | ai-redteam 주도 |
| 자동 PR 의 ci-bot 권한 (contents:write, pull-requests:write) | infra-engineer GHA token 권한 |
| 중복 TTP append 시 dedup 키 (atlas_id 기준 권장) | 양측 합의 |
| 임계 초과로 인한 prod 차단 시 ai-redteam 우선 처리 의무 | 운영 SLA 정의 |

> **현재 `build_oscal.py` 에는 `--append-poam` 옵션이 없다.** 이 옵션 추가는 compliance/governance 담당(또는 ai-redteam-engineer)이 PR 로 작업. 인터페이스는 본 문서가 정의.

---

## 4. 공급망 무결성 (방산 핵심)

### 4.1 GitHub Actions SHA 핀 표

**규칙**: 모든 `uses:` 를 **40자 커밋 SHA** 로 핀, 주석으로 의미 있는 버전 라벨을 기록한다. tag(`@v4`) 사용 금지(변조 위험).

> SHA 는 본 문서에서는 **권장 라벨**만 명시. 실제 워크플로 작성 시 infra-engineer 가 GitHub 상 최신 stable release 의 SHA 를 조회해 핀(예: `gh api repos/actions/checkout/git/refs/tags/v4.1.7 --jq .object.sha`). Dependabot `version-updates` 가 매주 SHA 갱신 PR 생성.

| Action | 권장 버전 | 용도 | SHA 조회 명령 (infra-engineer 실행) |
|--------|-----------|------|--------------------------------------|
| `actions/checkout` | v4.2.x | 코드 체크아웃 (fetch-depth: 0 권장) | `gh api repos/actions/checkout/git/refs/tags/v4.2.2 --jq .object.sha` |
| `actions/setup-python` | v5.3.x | Python 3.11 + pip 캐시 | `gh api repos/actions/setup-python/git/refs/tags/v5.3.0` |
| `actions/cache` | v4.x | pip/Trivy DB 캐시 | `gh api repos/actions/cache/git/refs/tags/v4.1.2` |
| `actions/upload-artifact` | v4.x | SBOM/리포트 artifact | `gh api repos/actions/upload-artifact/git/refs/tags/v4.4.3` |
| `actions/download-artifact` | v4.x | 워크플로 간 산출물 전달 | (동) |
| `github/codeql-action/init` | v3.x | CodeQL 초기화 | `gh api repos/github/codeql-action/git/refs/tags/v3.27.0` |
| `github/codeql-action/analyze` | v3.x | CodeQL 분석 (동일 ref) | (동) |
| `actions/dependency-review-action` | v4.x | PR 의존성 차단 | `gh api repos/actions/dependency-review-action/git/refs/tags/v4.5.0` |
| `gitleaks/gitleaks-action` | v2.3.x | 시크릿 스캔 | `gh api repos/gitleaks/gitleaks-action/git/refs/tags/v2.3.7` |
| `returntocorp/semgrep-action` | v1.x | Semgrep CI | `gh api repos/returntocorp/semgrep-action/git/refs/tags/v1` |
| `aquasecurity/trivy-action` | 0.28.x | 컨테이너/IaC/fs 스캔 | `gh api repos/aquasecurity/trivy-action/git/refs/tags/0.28.0` |
| `anchore/sbom-action` | v0.17.x | Syft SBOM 생성 | `gh api repos/anchore/sbom-action/git/refs/tags/v0.17.7` |
| `sigstore/cosign-installer` | v3.7.x | cosign 설치 | `gh api repos/sigstore/cosign-installer/git/refs/tags/v3.7.0` |
| `actions/attest-build-provenance` | v2.x | SLSA provenance 첨부 | `gh api repos/actions/attest-build-provenance/git/refs/tags/v2.1.0` |
| `slsa-framework/slsa-github-generator` (`generator_container_slsa3.yml`) | v2.0.0 | SLSA L3 generator | (reusable workflow 호출, tag 직접 사용 — SLSA generator 자체가 GHCR 검증 대상이므로 예외 허용) |
| `azure/login` | v2.x | Azure OIDC 로그인 | `gh api repos/Azure/login/git/refs/tags/v2.2.0` |
| `docker/setup-buildx-action` | v3.x | buildx 활성화 | `gh api repos/docker/setup-buildx-action/git/refs/tags/v3.7.1` |
| `docker/build-push-action` | v6.x | 이미지 빌드+push | `gh api repos/docker/build-push-action/git/refs/tags/v6.9.0` |
| `docker/login-action` | v3.x | GHCR 로그인 (OIDC 또는 PAT) | `gh api repos/docker/login-action/git/refs/tags/v3.3.0` |
| `rhysd/actionlint` (또는 native install) | v1.7.x | workflow 린트 | `gh api repos/rhysd/actionlint/git/refs/tags/v1.7.3` |

**자체 핀 검사 잡** (`workflow-lint`):

```bash
# 미핀(uses 가 SHA 가 아닌 곳) 검출
grep -rE "uses:\s+[a-zA-Z0-9._/-]+@(v[0-9]|main|master|latest)" .github/workflows/ \
  && { echo "[FAIL] SHA 미핀 발견"; exit 1; } || echo "[OK] 전 액션 SHA 핀"
```

### 4.2 OIDC keyless 인증 (PAT 제거 로드맵)

**원칙**: 모든 장기 자격증명(PAT/Service Principal Secret)을 제거하고 GitHub OIDC + Federated Identity Credential 로 단일화한다. infra-engineer 가 Azure 측 구성을 담당.

| 시크릿 | 현재 | 목표 | 비고 |
|--------|------|------|------|
| `GHCR_PAT` | PAT (기존 example) | **제거** → `permissions: { id-token: write, packages: write }` + `GITHUB_TOKEN` | docker/login-action 에 `username: ${{ github.actor }}`, `password: ${{ secrets.GITHUB_TOKEN }}` |
| `AZURE_CREDENTIALS_JSON` | Service Principal Secret | **제거** → `azure/login@<SHA>` with `client-id/tenant-id/subscription-id` + Federated Credential | Azure AD 에 GitHub repo OIDC issuer 등록 |
| `COSIGN_PRIVATE_KEY` | (없음, 신규 도입 회피) | **부재 유지** → cosign keyless (`COSIGN_EXPERIMENTAL=1`, Fulcio + Rekor) | OIDC ID-token 사용 |
| `SLACK_WEBHOOK_OPS` | 일반 Secret | 유지 (rotate 6개월) | OIDC 미지원 |
| `OPENAI_API_KEY_TEST` | 일반 Secret | Azure Key Vault Reference 로 전환 | Managed Identity 경유 |

**최소 권한 (워크플로별)**:

```yaml
# ci.yml
permissions:
  contents: read
  security-events: write       # CodeQL upload
  pull-requests: write          # dependency-review comment

# cd-*.yml (별도 워크플로)
permissions:
  contents: write              # gitops bump 커밋
  packages: write              # GHCR push
  id-token: write              # OIDC (Azure, cosign keyless)
  attestations: write          # actions/attest-build-provenance
```

### 4.3 cosign 서명·검증

**서명 (빌드 시, `cd-*.yml`):**

```yaml
- uses: sigstore/cosign-installer@<SHA>  # v3.7.0
- name: cosign sign (keyless)
  env:
    COSIGN_EXPERIMENTAL: "1"
  run: |
    DIGEST=$(docker buildx imagetools inspect ${IMAGE}:${TAG} --format '{{.Manifest.Digest}}')
    cosign sign --yes ${IMAGE}@${DIGEST}
- name: cosign attest SBOM
  run: |
    cosign attest --yes --predicate sbom.spdx.json --type spdxjson ${IMAGE}@${DIGEST}
```

**검증 (배포 시 + AKS Admission):**

- **CI/CD 단계**: `cosign verify --certificate-identity-regexp "https://github.com/s1ns3nz0/pollack-ai/.github/workflows/cd-prod.yml@.*" --certificate-oidc-issuer "https://token.actions.githubusercontent.com" ${IMAGE}@${DIGEST}`
- **클러스터 단계**: **Kyverno `verifyImages`** 정책 도입 권장 (infra-engineer)

```yaml
# deploy/k8s/policies/verify-images.yaml (infra-engineer 작성)
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: { name: verify-soc-images }
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-cosign-signature
      match: { any: [{ resources: { kinds: [Pod] } }] }
      verifyImages:
        - imageReferences: ["ghcr.io/s1ns3nz0/uav-ai-soc:*"]
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/s1ns3nz0/pollack-ai/.github/workflows/cd-prod.yml@*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor: { url: https://rekor.sigstore.dev }
```

### 4.4 SLSA Provenance L3

**1차 권장**: `slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0` reusable workflow 호출 (L3 빌더 자체가 hardened).

**2차 옵션**: `actions/attest-build-provenance@<SHA>` (L2 native, 단순). 우선 L2 부터 시작해 정착되면 L3 로 전환.

**SLSA L3 산출물**:
- `provenance.intoto.jsonl` — in-toto attestation, Rekor 등록
- `cosign verify-attestation` 으로 검증 가능

### 4.5 SBOM 첨부

```yaml
- uses: anchore/sbom-action@<SHA>  # v0.17.7
  with:
    image: ${{ env.IMAGE }}:${{ env.TAG }}
    format: spdx-json
    output-file: sbom.spdx.json
    upload-artifact: true
- name: cosign attest SBOM
  run: cosign attest --yes --predicate sbom.spdx.json --type spdxjson ${IMAGE}@${DIGEST}
- uses: actions/upload-artifact@<SHA>  # v4.4.3
  with:
    name: sbom-${{ github.sha }}
    path: sbom.spdx.json
    retention-days: 90
```

**보존 정책**: SBOM artifact 90일 (CI), GHCR attestation 무기한 (release 태그).

### 4.6 베이스 이미지 핀

`deploy/Dockerfile` 의 `FROM` 을 **digest 로 핀** (infra-engineer 작업):

```dockerfile
# Bad:  FROM python:3.11-slim
# Good: FROM python:3.11-slim@sha256:<digest>   # 정기 갱신 (Dependabot Docker)
```

Dependabot `docker` ecosystem 활성화로 월 단위 자동 갱신.

---

## 5. NIST SSDF · 800-204D × OSCAL 통제 매핑 표

| 게이트 | SSDF Practice (800-218) | C-SCRM (800-204D) | AI RMF OSCAL 통제 ID |
|--------|--------------------------|---------------------|----------------------|
| Gitleaks (시크릿) | PS.1.1, PW.1.1 | — | map-4.2, measure-2.7 |
| CodeQL (SAST) | PW.7.1, PW.7.2, PW.8.1 | — | measure-2.7, map-4.2 |
| Semgrep (SAST) | PW.7.1, PW.7.2 | — | measure-2.7 |
| dependency-review (SCA) | PW.4.1, PW.4.4 | SR-3, SR-4 | govern-6.1, manage-3.1 |
| pip-audit (SCA) | PW.4.1, PW.4.4, RV.1.1 | SR-3 | manage-3.1, measure-3.1 |
| Trivy fs / image (컨테이너) | PW.4.4, PW.9.1, RV.1.1 | SR-3, SR-4 | manage-3.1, govern-6.1 |
| Trivy config + Checkov (IaC) | PW.5.1, PW.9.1 | — | map-4.2, manage-2.4 |
| Syft (SBOM 생성) | PS.3.1, PS.3.2 | SR-4, MA-2 | govern-6.1, manage-3.1, map-4.1 |
| cosign sign (서명) | PS.2.2, PS.3.2 | MA-3, SR-4 | govern-6.1, manage-3.1 |
| SLSA Provenance L3 | PS.2.2, PS.3.2, PO.1.2 | PO-1, MA-3 | govern-6.1, map-4.1 |
| GitHub Actions SHA 핀 + actionlint | PS.2.1, PO.5.1 | PO-1, MA-3 | govern-6.1 |
| OIDC keyless (PAT 제거) | PS.1.1, PO.3.2 | PO-1 | govern-6.1, map-4.2 |
| Trivy license + GPL 차단 | PW.4.1 | SR-2 | map-4.1 |
| **OSCAL 스키마 검증** | PO.5.1, RV.2.1 | — | govern-6.1 (전체) |
| **POAM 임계 차단** | PO.5.1, RV.2.1, RV.3.3 | — | govern-1.4, manage-1.3 |
| Kyverno verifyImages (cluster) | PS.3.2, RV.1.3 | SR-4 | manage-2.4, map-3.5 |

**참고**:
- SSDF Practice 표기: `PO`=Prepare Organization, `PS`=Protect Software, `PW`=Produce Well-secured Software, `RV`=Respond to Vulnerabilities.
- C-SCRM 표기: `SR`=Supply Chain Risk Management family, `PO`=Procurement Oversight, `MA`=Manufacturing Authority (NIST SP 800-161 Rev.1 / 800-204D 통합).
- AI RMF OSCAL 통제 ID 는 `compliance/oscal/build_oscal.py` 의 `cid()` 규약 (예: `MAP 4.2` → `map-4.2`).

---

## 6. devsecops-redteam 자기점검 — 워크플로 컴플라이언스

신규/강화 워크플로 4개에 대해 **`devsecops-redteam` 스킬 호출 항목 리스트**를 사전 정의한다 (infra-engineer 가 실제 YAML 작성 후 본 리스트로 자기점검). 각 항목은 SSDF/800-204D/DoD DevSecOps Reference Design 기준.

### 6.1 점검 대상 워크플로

`_workspace/02_pipeline_config/.github/workflows/` 예정:

- `ci.yml` (강화)
- `cd-staging.yml` (신규)
- `cd-prod.yml` (신규)
- `compliance.yml` (신규)
- `ai-redteam.yml` (신규, ai-redteam-engineer 작성)
- `release-signing.yml` (재사용, 신규)

### 6.2 자기점검 체크리스트 (33항목)

| # | 항목 | 기준 | 적용 워크플로 |
|---|------|------|---------------|
| **공급망 (PS.2 / 800-204D MA-3)** | | | |
| 1 | 모든 `uses:` 가 40자 SHA 로 핀 (tag/branch 금지) | PS.2.1 | 전체 |
| 2 | Dependabot version-updates 활성 (workflows 카테고리) | PS.2.1 | repo 설정 |
| 3 | reusable workflow 호출 시 ref 도 SHA (예외: SLSA generator) | PS.2.1 | cd-* |
| 4 | actionlint + zizmor 가 lint 단계로 존재 | PS.2.1 | ci.yml |
| **권한 최소화 (PO.3 / 800-204D PO-1)** | | | |
| 5 | top-level `permissions:` 명시 (read-all 최소화) | PO.3.2 | 전체 |
| 6 | jobs 별 `permissions:` 가 필요 시점에만 write | PO.3.2 | 전체 |
| 7 | `GITHUB_TOKEN` write 권한이 의도된 job 에만 부여 | PO.3.2 | cd-*, compliance |
| 8 | OIDC (`id-token: write`) 는 서명·Azure 인증 job 에만 | PO.3.2, PS.1.1 | cd-* |
| **시크릿 관리 (PS.1)** | | | |
| 9 | 워크플로에 평문 시크릿/엔드포인트 하드코딩 없음 | PS.1.1 | 전체 |
| 10 | PAT (`GHCR_PAT`, `AZURE_CREDENTIALS_JSON`) 미사용 | PS.1.1 | 전체 |
| 11 | `pull_request_target` 미사용 (또는 사용 시 SHA-checkout) | PS.1.1 | 전체 |
| 12 | 시크릿 마스킹 확인 (echo 로 노출 안 함) | PS.1.1 | 전체 |
| **빌드 무결성 (PS.2.2, PS.3 / 800-204D SR-4)** | | | |
| 13 | 빌드 산출물 digest 캡처 (`docker buildx imagetools inspect`) | PS.3.1 | cd-*, ci(build) |
| 14 | cosign sign keyless (Fulcio + Rekor) | PS.2.2 | cd-* |
| 15 | SBOM 생성 (Syft, spdx-json) | PS.3.1 | ci.yml(build 후), cd-* |
| 16 | cosign attest --predicate sbom.spdx.json | PS.3.2 | cd-* |
| 17 | SLSA Provenance (L2 attest-build-provenance, 점진 L3) | PS.2.2 | cd-* |
| 18 | 베이스 이미지 digest 핀 (`FROM ...@sha256:...`) | PS.3.1 | Dockerfile |
| **검증·게이트 (PW.4, PW.7, PW.8)** | | | |
| 19 | SAST: CodeQL security-extended + Semgrep | PW.7.1, PW.7.2 | ci.yml |
| 20 | SCA: dependency-review + pip-audit + Trivy fs | PW.4.1, PW.4.4 | ci.yml |
| 21 | 시크릿 스캔: Gitleaks (history+diff) | PW.1.1 | ci.yml |
| 22 | 컨테이너 스캔: Trivy image (Critical 차단) | PW.4.4, PW.9.1 | ci.yml |
| 23 | IaC 스캔: Trivy config + Checkov | PW.5.1 | ci.yml |
| 24 | OSCAL 스키마 검증 (5종) | PO.5.1 | compliance.yml |
| 25 | POAM 임계 차단 (main 한정) | PO.5.1, RV.2.1 | compliance.yml |
| **대응·복구 (RV)** | | | |
| 26 | 카나리 자동 분석 + 롤백 (Argo Rollouts) | RV.1.3 | cd-prod (배포 단계) |
| 27 | 실패 시 알림 (Slack/PagerDuty) | RV.1.1 | 전체 |
| 28 | nightly 재스캔으로 신규 CVE 감지 (Grype) | RV.1.1 | nightly cron |
| **거버넌스 (PO / 800-204D PO-1)** | | | |
| 29 | `production` Environment + required reviewers ≥ 1 | PO.3.2 | cd-prod |
| 30 | CODEOWNERS 가 보안 게이트 파일 보호 | PO.3.2 | repo 설정 |
| 31 | Branch protection: main 에 required status checks | PO.3.2 | repo 설정 |
| 32 | 워크플로 변경 시 reviewer ≥ 2 (가능 시) | PO.3.2 | repo 설정 |
| 33 | 감사 로그 보존 (GitHub Audit Log → SIEM) | PO.5.2 | infra |

### 6.3 호출 예시 (실제 YAML 생성 후)

```bash
# infra-engineer 가 워크플로 작성 완료 후 본 디렉토리에서 실행
/devsecops-redteam _workspace/02_pipeline_config/.github/workflows/cd-prod.yml
```

---

## 7. 차단 정책 매트릭스 (트리거 / 차단 / 사유 / 우회)

| # | 트리거 | 차단되는 항목 | 사유 | 우회 절차 |
|---|--------|---------------|------|-----------|
| 1 | Gitleaks 매치 | git push, PR 머지 | 시크릿 노출 시 즉시 회수 필요 | (1) 시크릿 회수 + (2) `git filter-repo` 이력 정리 (3) `.gitleaks.toml` allowlist 명시 사유·만료·승인자 (4) re-push |
| 2 | CodeQL/Semgrep Critical/High | PR 머지 | 익스플로잇 가능 결함 | (1) 수정 PR (2) 불가 시 `.semgrepignore`/`# nosec` + ADR `docs/adr/` 작성 (3) security-scanner 승인 |
| 3 | dependency-review/pip-audit High+ CVE | PR 머지 | 알려진 취약 의존성 | (1) 버전 업데이트 (2) 없을 시 `.pip-audit.toml` ignore + 만료 (3) POAM 등록 |
| 4 | Trivy image Critical CVE | 빌드 산출물 (이미지 폐기), 배포 | OS/앱 패키지 익스플로잇 | (1) 베이스 이미지 갱신 (`apt upgrade`) (2) `.trivyignore` 사유·만료·승인자 (3) 30일 SLA POAM |
| 5 | Trivy config / Checkov HIGH | PR 머지 | k8s/Dockerfile 보안 misconfig | (1) 매니페스트 수정 (2) `--skip-policy` + ADR 사유 (3) infra-engineer 승인 |
| 6 | SBOM 생성 실패 | 빌드, 배포 | 공급망 가시성 부재 | 우회 불가 — 도구 버그 발생 시 Syft 버전 핀백, infra-engineer 대응 |
| 7 | 미핀 `uses:` 검출 | PR 머지 (workflow 변경 시) | 공급망 변조 방어 무력화 | SLSA generator reusable workflow 1건만 예외 — 본 문서 매트릭스 6.2 항목 3 참조 |
| 8 | cosign 서명 실패 | 배포 (cd-prod) | 무서명 이미지 prod 진입 금지 | 우회 불가 — Fulcio/Rekor 장애 시 cd-prod 자체 보류 |
| 9 | OSCAL 스키마 위반 | PR 머지 (compliance.yml) + main 배포 | 컴플라이언스 산출물 무효 | (1) `build_oscal.py` MAPPINGS 수정 (2) trestle 도구 버그 시 격리 jsonschema 우회 + 이슈 발행 |
| 10 | POAM critical ≥ 1 | main 배포 (cd-prod) | 방산 절대 임계 | **우회 불가**. critical 해결 또는 status 변경(planned→partial→implemented) 후 재시도 |
| 11 | POAM high > 3 | main 배포 (cd-prod) | 누적 위험 한계 | (1) high → partial 승격 (2) 사유서 + 위원회 승인 시 임계 ad-hoc 완화 (label `compliance-override` 부여 + 만료 14일) |
| 12 | AI 레드팀 회귀 (24h 게이트 미통과) | main 배포 (cd-prod) | 보안 회귀 차단 | (1) workflow_dispatch 로 `ai-redteam.yml` 재실행 (2) ai-redteam-engineer 검토 (3) 통과 후 cd-prod 재시도 |
| 13 | 카나리 분석 실패 (5xx/p99/RAGAS) | prod 배포 (Argo Rollouts) | 운영 회귀 | 자동 git revert (Argo Rollouts) → 재배포 시 수정 PR 필요 |
| 14 | GPL/AGPL/SSPL 라이선스 의존성 | PR 머지 | 방산 IP 정책 위반 | (1) 대체 라이브러리 (2) 법무팀 검토 후 ADR + license-policy.yaml 명시적 allow |

**일반 우회 원칙**:
- 예외는 항상 **사유 + 만료일 + 승인자** 명시 (`.trivyignore`, `.gitleaks.toml`, `.semgrepignore`)
- 만료된 예외는 nightly job 이 자동 검출 → 이슈 발행
- `--warn-only` 플래그는 PR/staging 에서만 허용, main 차단 우회용 금지

---

## 8. 허용 목록 (예외) 템플릿

`.trivyignore`:
```
# 형식: <CVE-ID>  # 사유. 만료: YYYY-MM-DD. 승인: @user
# CVE-2024-12345  # 미사용 기능. 만료: 2026-12-31. 승인: @security-team
```

`.gitleaks.toml` (저장소 루트, 신규):
```toml
title = "UAV AI SOC Gitleaks Config"
[extend]
useDefault = true
[allowlist]
description = "False positives"
paths = [
    '''compliance/oscal/.*\.json$''',  # UUID 가 시크릿으로 오인됨. 만료: 영구. 승인: @security-team
    '''tests/__tests__/.*fixtures.*''', # 테스트 더미. 만료: 영구. 승인: @security-team
]
```

`.pip-audit.toml` (또는 CLI `--ignore-vuln`):
```toml
# 형식 (CLI):
# pip-audit --ignore-vuln PYSEC-2024-XXX  # 사유. 만료: 2026-09-30. 승인: @security-team
```

| 파일 | 규칙/CVE | 사유 | 만료 | 승인자 |
|------|----------|------|------|--------|
| `.gitleaks.toml` | `compliance/oscal/*.json` | OSCAL UUID 오인 (`uuid.uuid5` 결정론) | 영구 | @security-team |
| `.gitleaks.toml` | `tests/**/fixtures*` | 테스트 더미 데이터 | 영구 | @security-team |
| (초기) — | — | — | — | — |

---

## 9. 신규 산출물 요약

| 경로 | 종류 | 상태 |
|------|------|------|
| `_workspace/02_pipeline_config/scripts/check_poam_thresholds.py` | Python 스크립트 (256 LoC, 표준 라이브러리만) | **작성 완료** + 실측 검증 통과 |
| `_workspace/04_security_scan.md` | 본 설계 문서 | **작성 완료** |
| `.gitleaks.toml` | 시크릿 스캐너 설정 | 워크플로 작성 시 infra-engineer 추가 |
| `.trivyignore` | Trivy 예외 | 빈 파일 초기 생성 |
| `compliance/oscal/check_poam_thresholds.py` | 위 스크립트 정식 배치 (승인 후) | 리뷰 후 이동 |
| `compliance/oscal/build_oscal.py` `--append-poam` 옵션 | 신규 옵션 추가 | ai-redteam-engineer 와 협업 |

---

## 10. 보류·결정 필요 사항

| # | 항목 | 결정 주체 |
|---|------|----------|
| 1 | `check_poam_thresholds.py` 정식 배치 경로 (`compliance/oscal/` vs `scripts/`) | 사용자/pipeline-reviewer |
| 2 | POAM high 임계 `3` 적정성 (현재 GOVERN 1.6 1건) — 초기 1개월 운영 후 1로 강화 검토 | 운영 1-2주 관찰 |
| 3 | `build_oscal.py --append-poam` 옵션 구현 담당 | ai-redteam-engineer 또는 governance |
| 4 | Kyverno verifyImages 도입 시점 (cluster-level cosign 검증) | infra-engineer |
| 5 | SLSA L3 vs L2 채택 (방산 인증 요구사항 확인) | 사용자 |
| 6 | Dependabot docker ecosystem 활성화 (베이스 이미지 SHA 갱신) | infra-engineer |
| 7 | Bandit vs Semgrep 의 Python 규칙 중복 — semgrep `p/python` 만 채택 권장 | quality-gate 와 조율 |

---

## 11. 다음 단계 (인계)

| 수신 에이전트 | 인계 내용 |
|---------------|----------|
| **infra-engineer** | (1) `.github/workflows/ci.yml` 강화 + `cd-staging.yml`/`cd-prod.yml`/`compliance.yml`/`release-signing.yml` 신규 작성 (2) 본 문서 1.1, 4.1, 4.2 표 적용 (3) Azure OIDC + GHCR OIDC + cosign keyless 구성 (4) `.gitleaks.toml`/`.trivyignore`/`.pip-audit.toml` 초기 생성 (5) Dependabot version-updates 활성화 (workflows + docker) (6) `production` GitHub Environment 보호 규칙 설정 |
| **ai-redteam-engineer** | (1) 3.7 절 `failed_ttps.json` 스키마 합의 (2) `ai-redteam.yml` 종료 단계에 artifact upload (3) `build_oscal.py --append-poam` 옵션 구현 협업 (4) ATLAS TTP → AI RMF 통제 매핑 권고안 작성 |
| **quality-gate** | (1) ruff S 규칙 vs Semgrep/Bandit 중복 조율 — ruff 는 fast-feedback, semgrep `p/python` 은 심층 분석 (2) `pyproject.toml` 에 `[tool.ruff.lint] select = [..., "S"]` 적용 |
| **monitoring-specialist** | (1) 보안 스캔 실패 알림 규칙 (Slack `#security-alerts` 채널) (2) OSCAL 추세 메트릭 (`oscal_implemented_total`, `oscal_partial_total`, `oscal_poam_open_critical`, `oscal_poam_open_high`) Prometheus 노출 (3) Trivy nightly 신규 CVE 발견 시 PagerDuty |
| **test-engineer** | (1) `check_gates.py` 작성 시 본 문서 3.7 `failed_ttps.json` 출력 형식 준수 (2) coverage 임계 80% 전체 / 90% 핵심경로 강제 (3) `check_poam_thresholds.py` 의 pytest 단위테스트 추가 |
| **pipeline-reviewer** | 본 문서 검토 — 다음 절 |

---

## 12. pipeline-reviewer 가 점검해야 할 핵심 항목

1. **POAM 임계 `high≤3` 운영 가능성** — 현재 실측 high=1(GOVERN 1.6, planned). 신규 컴포넌트 추가 시 partial→planned 로의 후퇴 가능성. 임계가 너무 빡빡하지 않은지 1-2주 운영 후 재평가 필요.
2. **OSCAL 게이트 PR vs main 모드 분기 일관성** — `--warn-only` 플래그가 PR/develop 에서만 적용되고 main 에서는 반드시 차단 모드로 호출되는지 워크플로 YAML 작성 시 검증.
3. **공급망 무결성 4종 풀스택 종속성** — SHA 핀, OIDC, cosign keyless, SLSA L3 가 한 워크플로 안에서 모두 정합한지 (특히 reusable workflow 인 SLSA generator 호출 시 `permissions: id-token: write` 가 caller 와 callee 양쪽 모두 설정되는지).
4. **AI 레드팀 → POAM 자동 append 의 dedup·infinite-loop 방지** — 동일 ATLAS TTP 가 매 nightly 마다 추가되어 POAM 이 폭증하지 않도록 dedup 키 (atlas_id) 와 ci-bot PR 의 충돌 처리.
5. **`check_poam_thresholds.py` 의 `closed` 판정 신뢰성** — `remediation-tracking` 의 키워드 매칭(closed/completed/종결/완료)이 운영 중 오탐할 가능성. 명시적 `closed` prop 도입을 build_oscal.py 측에 권고할지 결정.

---

**문서 끝.**
