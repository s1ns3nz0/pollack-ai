# CI/CD 파이프라인 리뷰 보고서 — Round 2 (UAV AI SOC)

**리뷰어**: pipeline-reviewer
**대상**: 라운드 A(자동 수정 8건) + 라운드 B(빌더 이미지 도입 + F-013) 후 산출물
**작성일**: 2026-06-29
**참조**: 1차 리뷰(`05_review_report.md` — 13🔴/12🟡/9🔵)

---

## §0. Round 2 Summary

- **라운드 A**: 1차 🔴 13건 중 **8건 해결**(F-001 F-002 F-004 F-005 F-007 F-008 F-011 F-012 F-017 F-020 F-024 — F-005는 호출 경로만 정정), **5건 미해결**(F-003 F-006 F-009 F-010, +라운드 B에서 F-013 해결).
- **라운드 B**: 빌더 이미지 + 25개 잡 `container:` 핀 + 5개 워크플로 `verify-builder` 잡 도입. F-013 해결. 다만 **신규 🔴 5건 / 🟡 4건**을 발생시켰다(아래 §2).
- 운영 준비도: 🔴 → 🟡 (조건부 머지 가능). 부트스트랩 절차 + 사용자 결정 5건 + placeholder 6종 실측 후 머지 권장.
- 방산 컴플라이언스: PS.2.1/PS.2.2/MA-3 강화. 단, cosign verify의 OIDC 신뢰 체인 부트스트랩 갭(§4) 잔존.

---

## §1. 1차 결함 → 라운드 A 정정 매트릭스

### A. 라운드 A에서 손댄 결함 (정정 결과)

| ID | 정정 상태 | 검증 위치 | 비고 |
|----|-----------|----------|------|
| F-001 | ✅ 해결 | `scripts/check_poam_thresholds.py:389-469` build_parser | `--mode {warn,block}`, `--partial-warn N`, positional `poam_path`, `--warn-only` deprecated 별칭 |
| F-002 | ✅ 해결 | `benchmarks/check_gates.py:78-91` PROFILES + L662 argparse + L773 `_resolve_thresholds` | staging/prod 사전 정의, 명시 플래그 우선 |
| F-003 | ❌ 미해결 | (수정 없음) | `build_oscal.py --append-poam` 별도 PR로 분리 — 워크플로는 `ai_redteam_to_poam.py --append-to-poam`(ai-redteam.yml:559)로 우회 중 |
| F-004 | ✅ 해결 | `ai-redteam.yml:252, 539, 554, 562` | 4곳 모두 `scripts/ai_redteam_to_poam.py`, `compliance/oscal/check_poam_thresholds.py` 정식 경로 |
| F-005 | ✅ 해결 | `cd-staging.yml:253`, `cd-prod.yml:236`, `ai-redteam.yml:562` | 모두 `compliance/oscal/check_poam_thresholds.py` 통일 |
| F-006 | ❌ 미해결 | (수정 없음) | 트랙 A 단일 선택(Rollout vs Deployment) 사용자 결정 보류 |
| F-007 | ✅ 해결 | `cd-staging.yml:330-370`, `cd-prod.yml:536-578` | dora-push-success/failure 잡 신설. PUSHGATEWAY_URL 변수 가드 |
| F-008 | ✅ 해결 | `cd-prod.yml:131-170` (g2-gate 끝 push step), `ai-redteam.yml:582-686` (report-and-poam 끝 push step) | gates[] 순회 → `g2_gate_pass/fail_total`, `g2_gate_value`, ai_redteam 메트릭 4종 |
| F-009 | ❌ 미해결 | `Dockerfile:24, 66`, `Dockerfile.builder:43, 155` | placeholder digest 그대로(사용자 환경 실측 필요) |
| F-010 | ⚠️ 부분 해결 | `ci-enhanced.yml:271-273` (semgrep 잡) | 외부 `returntocorp/semgrep` 컨테이너 의존 제거 → 빌더 이미지로 대체(라운드 B). 그러나 빌더의 semgrep 핀(`1.85.0`) 자체는 검증 필요 |
| F-011 | ✅ 해결 | `ci-quality-patch.yml:23, 53, 79, 106, 126, 150, 167` | actions/checkout, setup-python, sigstore/cosign-installer 등 모두 SHA 핀 |
| F-012 | ✅ 해결 | `ai-redteam.yml:336` `azure/login@a65d910e... # v2.2.0` | cd-prod.yml:473과 정합 |
| F-013 | ✅ 해결 | `pyproject.toml.patch:135` (`python_version = "3.11"`), L172-175 (`numpy.*` follow_imports=skip) | 옵션 A 적용 |
| F-017 | ✅ 해결 | `ai-redteam.yml:193, 511` | `dawidd6/action-download-artifact@bf251b5aa9c2f7eeb574a96ee720e24f801b7c11 # v6` 채택, `workflow/branch/name/if_no_artifact_found` 명시 |
| F-020 | ✅ 해결 | `servicemonitor.yaml:63-65` | regex가 3개 메트릭(`http_request_duration_seconds`, `agent_latency_seconds`, `mttt_seconds`)에 `(_bucket\|_count\|_sum)?` 통일 |
| F-024 (🟡) | ✅ 해결 | `cd-staging.yml:291` | 커밋 메시지에 `[skip ci]` 추가 |

### B. 라운드 A에서 손대지 않은 결함 (잔존 상태)

| ID | 분류 | 잔존 상태 | 비고 |
|----|------|----------|------|
| F-003 🔴 | build_oscal --append-poam 미구현 | ❌ 미해결 | ai-redteam.yml은 우회로 작동, 그러나 04 §3.7 인터페이스 단일 출처는 여전히 부재(인터페이스 매트릭스 #7 ⚠️ 잔존) |
| F-006 🔴 | ArgoCD Deployment/Rollout 충돌 | ❌ 미해결 | cd-prod.yml:409가 `argo-rollout-hotpath.yaml` bump하면서 `30-deployment-a-hotpath.yaml`도 동시 존재 — 사용자 결정 보류 |
| F-009 🔴 | Dockerfile base digest placeholder | ❌ 미해결 | 빌더 Dockerfile에도 동일 placeholder 도입(`Dockerfile.builder:43, 155`) — 사용자 환경 실측 필요 |
| F-013 🔴 | mypy python_version 결정 | ✅ 해결 (라운드 B에서 정정) | — |
| F-014 🟡 | SLSA generator 예외 코멘트 | ❌ 미해결 | `cd-prod.yml:355` 라인 상단 코멘트 추가 안 됨 |
| F-015 🟡 | Trivy 이중 호출 | ❌ 미해결 | `ci-enhanced.yml:424-445`, `cd-staging.yml:190-210`, `cd-prod.yml:311-330` 모두 1차 SARIF + 2차 차단 패턴 유지 |
| F-016 🟡 | ci-enhanced ↔ ci-quality-patch lint 중복 | ❌ 미해결 | ci-enhanced.yml에 여전히 `lint` 잡(L104-120, 빌더 이미지) — ci-quality-patch.yml의 `lint`(L70-92)와 같은 PR에 2회 실행 |
| F-018 🟡 | rollouts-monitor OIDC skip | ❌ 미해결 | `cd-prod.yml:454, 486` `if: vars.ARGOCD_SERVER != ''` 그대로 — 환경 미준비 시 묵묵 skip |
| F-019 🟡 | OSCAL CronJob read-only 충돌 | ❌ 미해결 | `oscal-export-cronjob.yaml` 그대로 |
| F-021 🟡 | pip-audit 임계 | ❌ 미해결 | `ci-enhanced.yml:341` `pip-audit --strict --progress-spinner=off --disable-pip -r /tmp/requirements.txt` — severity 필터 부재 |
| F-022 🟡 | oscal-schema continue-on-error | ❌ 미해결 | `ci-enhanced.yml:168` `continue-on-error: true` 그대로 |
| F-023 🟡 | RAGAS no-data SPOF | ❌ 미해결 | AnalysisTemplate 미수정 |
| F-025 🟡 | interrogate 80% 미실측 | ❌ 미해결 | pyproject.toml.patch:195 `fail-under = 80` 그대로(코멘트만 "도입 시 60→70→80 단계" 추가) |
| F-026~F-034 🔵 | 모니터링 | (관찰 항목 — 변경 없음) | |

### C. 라운드 A 자체 정합성 검증

- **F-007 dora-push 잡** — `cd-staging.yml:333` `needs: [verify-builder, gitops-bump, smoke]`. smoke 잡은 `if: vars.STAGING_HEALTH_URL != ''` 라 skip 가능. 그러면 dora-push-success도 항상 skip(needs success 평가). → **🟡 F-035 신규 발견**(§2 참조).
- **F-008 g2-gate Pushgateway push** — cd-prod.yml:131-170 인라인 Python heredoc. `urllib.request.urlopen(req, timeout=10)` — Pushgateway 응답이 200 외(401, 503)일 때 예외 처리 없이 잡 실패. `if: always()` 보호 있으나 후속 잡 의존 분기 영향. → 🟡 권장 수정.
- **F-017 dawidd6 액션** — 코멘트(`ai-redteam.yml:189-190`)는 "v6 tag → commit `bf251b5a...`"라 명시하나 SHA 검증은 사용자 환경에서 1회 실측 필요(F-033 잔여). 코드 자체는 정합.

---

## §2. 라운드 B 자체 결함 신규 카탈로그

라운드 B의 빌더 이미지 도입은 공급망 무결성을 크게 강화하지만, 새로운 보안·운영 위험 9건을 도입했다.

### 🔴 신규 필수 수정 — 5건

#### F-036 🔴 Dockerfile.builder 5종 binary SHA256 placeholder 모두 `0000...0000` + sha256sum `|| true` 무력화
- **위치**: `deploy/Dockerfile.builder:104, 107, 114, 117, 124, 127, 135, 138, 144, 147`
- **현상**:
  ```dockerfile
  ARG GITLEAKS_SHA256=0000000000000000000000000000000000000000000000000000000000000000
  RUN ... && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - || true
  ```
  모든 binary 도구(gitleaks/syft/trivy/cosign/gh)가 동일 패턴. 더 심각한 것은 sha256sum 검증 실패 시 `|| true`로 무력화 — **placeholder 값이라도 빌드는 성공**.
- **영향**: 라운드 B의 핵심 목적인 "공급망 무결성"이 위장 상태. 누군가 GitHub Release를 점거해 악성 binary 배포 시 검증 메커니즘 부재로 빌더 이미지에 침투. 모든 후속 잡이 신뢰 체인 깨짐.
- **수정**:
  ```dockerfile
  ARG GITLEAKS_SHA256=<실측>
  RUN ... && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c -
  #                                                                       ↑ || true 제거
  ```
  Dockerfile.builder.README.md §4 절차에 binary digest 실측 절차 명시 필요.
- **담당**: infra-engineer (사용자 환경에서 5개 binary SHA256 실측 + Dockerfile.builder 갱신)

#### F-037 🔴 부트스트랩 chicken-and-egg — `build-builder.yml` 자체가 cosign-installer 사용
- **위치**: `build-builder.yml:133-145` (sign-attest 잡이 `release-signing.yml` 호출)
- **현상**: 빌더 이미지가 만들어지기 전, `build-builder.yml`은 호스트 runner에서 `release-signing.yml`을 호출해 cosign keyless 서명을 수행한다. `release-signing.yml:70` `sigstore/cosign-installer@d7d6bc77...` 액션이 cosign 바이너리를 받음. 이 자체는 OK이지만, **다운스트림 워크플로(`ci-enhanced.yml:66`, `cd-staging.yml:58`, `cd-prod.yml:72`, `ci-quality-patch.yml:53`, `ai-redteam.yml:105`)의 `verify-builder` 잡도 동일 액션을 호스트에서 사용**. 즉 cosign 신뢰는 sigstore/cosign-installer action에 위임.
- **영향**:
  - sigstore/cosign-installer SHA 핀이 `d7d6bc7722e3daa8354c50bcb52f4837da5e9b6a # v3.8.1`로 고정. 단 GitHub Actions cache hit으로 받은 cosign이 변조되는 공급망 위협 모델은 sigstore 신뢰 도메인. SSDF PS.2.1 만족.
  - 단, `vars.BUILDER_IMAGE_DIGEST`가 미설정되었을 때 `verify-builder`가 즉시 실패 → **모든 다운스트림 잡 차단**. 라운드 B는 이를 부트스트랩 6단계로 해소하나, 부트스트랩 중 사용자가 5개 워크플로 patch를 먼저 머지하면 모든 CI/CD가 정지됨. README §9 절차가 강조되나 "사람이 순서를 지킨다"는 가정에 의존 → 거버넌스 리스크.
- **수정**:
  - `verify-builder` 잡에 `if: vars.BUILDER_IMAGE_DIGEST != ''` 가드를 추가하고 미설정 시 워크플로 **skip + warning** 으로 변경. 이렇게 하면 부트스트랩 진입 가능. 단, 본격 운영 시 가드 제거 권장(설정 강제).
  - 또는 `BUILDER_IMAGE_DIGEST` 미설정 시 자동으로 `:latest` 태그 fallback(공급망 정책 위반이므로 staging only).
- **권고**: 부트스트랩 위험 완화를 위해 가드 추가 + README §9 절차에 "각 워크플로 patch 머지는 단계별 1개씩, 다음 단계 검증 후 진행" 명시.
- **담당**: infra-engineer + 사용자

#### F-038 🔴 cosign verify의 `certificate-identity-regexp` 부정확
- **위치**: 6개 워크플로 `verify-builder` 잡 — `ci-enhanced.yml:77`, `cd-staging.yml:68`, `cd-prod.yml:82`, `ci-quality-patch.yml:63`, `ai-redteam.yml:115`, `Dockerfile.builder.README.md:140`
- **현상**:
  ```bash
  --certificate-identity-regexp 'https://github\.com/s1ns3nz0/pollack-ai/\.github/workflows/build-builder\.yml@.*'
  ```
  - regex는 `@.*` 종료 — anchor `^...$` 부재. 임의 prefix 매칭 허용. 예를 들어 attacker가 `https://github.com/evil/repo/.../build-builder.yml@x` 경로로 위장된 OIDC 인증서를 발급받을 수 있다면(이론적으로는 GitHub OIDC 토큰이 repo identity로 발급되므로 어렵지만), regex 자체는 차단 못 함.
  - 정밀히는 cosign이 `--certificate-identity-regexp`를 `re2.FullMatch`로 처리하지 않고 `re2.Find`로 처리하는 버전이 있어 prefix만으로 매칭될 위험.
  - 또한 ref(`@.*`)에 main branch 외 임의 tag/branch도 허용 — `feat/*` 브랜치의 build-builder.yml로 빌드된 이미지도 검증 통과. CI 정합상 main에서만 빌드되도록 강제하려면 `@refs/heads/main$` 명시 필요.
- **영향**: 공급망 위협 모델 일부 우회 가능. SSDF PS.2.2 부분 약화.
- **수정**:
  ```bash
  --certificate-identity-regexp '^https://github\.com/s1ns3nz0/pollack-ai/\.github/workflows/build-builder\.yml@refs/heads/main$'
  ```
  (workflow_dispatch 사용 시 `@refs/heads/main` 외 다른 ref도 가능하므로 운영 정책 결정 필요)
- **담당**: infra-engineer (6개 파일 동시 정정)

#### F-039 🔴 ai-redteam.yml 화이트리스트 잡(pyrit-campaign/garak-campaign/report-and-poam)이 Python 환경 불일치
- **위치**: `ai-redteam.yml:307-376` (pyrit-campaign), L382-437 (garak-campaign), L477-686 (report-and-poam)
- **현상**: 3개 화이트리스트 잡이 호스트 runner에서 `actions/setup-python@... # v5.6.0`로 Python을 설치하고 `pip install -e ".[dev]"`로 의존성 설치. 라운드 B는 "빌더 이미지에 도구 풀스택 핀"으로 재현성을 보장한다고 했으나 이 3개 잡은 호스트 Python(시점에 따라 3.11.x patch 버전 변동)을 사용. 더 심각히, `pip install -e ".[dev]"`가 호스트에서 또 다시 실행되어 빌더 이미지가 강조한 "잡 YAML의 pip install 행위 제거" 원칙과 정면 충돌.
- **영향**:
  - 빌더 이미지의 `mypy==1.11.2` 핀과 호스트의 `pip install -e ".[dev]"`로 설치된 mypy(`>=1.10.0,<2`)가 같은 워크플로에서 다른 버전을 사용할 수 있음 → 재현성 깨짐.
  - report-and-poam 잡(`ai-redteam.yml:500`)은 `pip install -e ".[dev]"`를 사용해 ai_redteam_to_poam.py를 import 가능 상태로 만듬. 그러나 호스트 환경에 따라 의존성 해소 결과가 빌더 이미지와 다를 수 있음.
- **수정**: 3가지 옵션.
  - (A) **권고**: pyrit/garak/report-and-poam도 빌더 이미지 위에 추가 docker run으로 실행. azure/login은 OIDC 토큰을 환경변수로 전달 가능 — 컨테이너 안에서도 az CLI 호출 가능(단 빌더에 az CLI 핀 필요).
  - (B) PyRIT/Garak/peter-evans만 호스트, 나머지 Python 호출은 빌더 이미지 안에서 `docker run` 별도 수행.
  - (C) 현 상태 유지하되 호스트 setup-python 버전을 빌더와 동일 patch까지 명시 핀(`python-version: "3.11.10"`) + pip install 후 `pip freeze` 산출물 업로드해 추적성 확보.
- **담당**: ai-redteam-engineer + infra-engineer (빌더 이미지에 az CLI 핀 추가 PR 동반)

#### F-040 🔴 ci-enhanced.yml `lint` 잡과 ci-quality-patch.yml `lint` 잡 충돌 (F-016 재발 + 빌더 핀 차이)
- **위치**: `ci-enhanced.yml:104-120` vs `ci-quality-patch.yml:70-92`
- **현상**: 두 워크플로 모두 같은 PR/push에서 빌더 이미지로 lint 실행. ci-enhanced의 lint는 `black --check . && ruff check . && mypy .`(`ci-enhanced.yml:115-120`)이고 ci-quality-patch의 lint는 `black --check . && ruff check . --output-format=github && ruff format --check .`(L83-92). mypy는 ci-quality-patch의 typecheck 잡에 분리.
  - 두 잡이 동일 도구 핀(빌더 이미지)를 쓰므로 결과는 같음. 그러나 매 PR에 lint가 2회 실행 → 비용 2배. 라운드 A 기대(`[skip ci]` 등으로 중복 회피)와 모순.
  - 1차 F-016이 🟡로 분류되었으나, 라운드 B에서 두 잡 모두 cosign verify + container pull을 거치므로 **잡 1개당 30-60초 추가 부하**. ci-enhanced는 verify-builder + setup + lint 3 hops, ci-quality-patch도 verify-builder + lint 2 hops. PR 1건당 verify-builder가 6회 실행(ci-enhanced + ci-quality-patch + ai-redteam canary 등). → 비용·러너 시간 폭증.
- **영향**: 비용/시간 외에도 F-038 regex 약점이 6회 노출 → 보안 위험 면적 증가.
- **수정**: F-016 권고 따라 ci-enhanced의 lint 제거 + ci-quality-patch가 단독 담당. ci-enhanced는 test/secret-scan/codeql/build/scan만 보존. verify-builder는 동일 워크플로 안에서 1회만 실행되므로 6→3회로 축소.
- **담당**: pipeline-designer + quality-gate

### 🟡 신규 권장 수정 — 4건

#### F-035 🟡 dora-push-success 잡이 smoke skip 시 영구 skip
- **위치**: `cd-staging.yml:333` `needs: [verify-builder, gitops-bump, smoke]` + L334 `if: success()`
- **현상**: `smoke` 잡은 `cd-staging.yml:303` `if: vars.STAGING_HEALTH_URL != ''`로 변수 미설정 시 skip됨. `success()`는 skipped 잡을 success로 평가 → dora-push-success가 실행되나, 사용자가 `STAGING_HEALTH_URL` 미설정 시에도 dora 메트릭은 push되어 가시성은 확보. 단, 같은 패턴을 cd-prod.yml에 적용했을 때 `post-deploy-smoke`가 `vars.PROD_HEALTH_URL`로 가드되며 skip되면 dora-push가 발화 — 이는 의도된 동작이나 운영자가 "smoke 미수행 = 미배포"로 오해 가능.
- **수정**: smoke를 항상 실행하도록 정책 변경(URL 미설정 시 명시적 fail) + dora-push needs에서 smoke 제거. 또는 코멘트로 "smoke skip 시에도 dora는 push됨"을 명시.
- **담당**: monitoring-specialist

#### F-041 🟡 빌더 이미지의 도구가 read-only rootfs와 충돌 가능 (mypy/pytest/semgrep cache)
- **위치**: 모든 컨테이너 잡 `options: --user 10001 --read-only --tmpfs /tmp:rw,...`
- **현상**: 라운드 B는 `XDG_CACHE_HOME=/tmp/.cache`(Dockerfile.builder:174)를 설정해 도구 캐시를 tmpfs로 유도하나 다음 도구가 환경변수 무시:
  - **mypy**: `MYPY_CACHE_DIR`로 제어. `ci-quality-patch.yml:111` 잡은 `MYPY_CACHE_DIR=/tmp/.mypy_cache` 명시 → OK. 단 `ci-enhanced.yml:119` lint 잡은 mypy 명시 환경변수 부재 → 기본 `.mypy_cache`(`/workspace/.mypy_cache`)에 쓰려다 read-only 실패.
  - **pytest**: `.pytest_cache` 디렉터리에 쓰기. `ci-enhanced.yml:215` test 잡이 cwd `/workspace`에서 실행되면 실패. `--cache-dir=/tmp/pytest_cache` 명시 필요.
  - **semgrep**: `~/.semgrep` 캐시. `HOME=/home/builder`(Dockerfile.builder:172)이나 home 디렉터리도 read-only. `--no-rewrite-rule-ids --metrics=off`로 회피 가능하나 명시 안 됨(`ci-enhanced.yml:279`).
  - **gitleaks**: `--report-path=/tmp/gitleaks.sarif`로 명시 → OK.
- **영향**: 첫 실행에서 `[Errno 30] Read-only file system: '.mypy_cache'` 같은 오류로 잡 실패 가능.
- **수정**:
  ```yaml
  # ci-enhanced.yml lint 잡
  env:
    MYPY_CACHE_DIR: /tmp/.mypy_cache
    PYTEST_CACHE_DIR: /tmp/.pytest_cache
  # ci-enhanced.yml test 잡
  run: pytest --cache-dir=/tmp/.pytest_cache ...
  # ci-enhanced.yml semgrep 잡
  run: semgrep ci ... --no-rewrite-rule-ids --metrics=off
  ```
  Dockerfile.builder의 ENV에 `MYPY_CACHE_DIR=/tmp/.mypy_cache`, `PYTEST_CACHE_DIR=/tmp/.pytest_cache` 명시 권고.
- **담당**: infra-engineer + quality-gate

#### F-042 🟡 빌더 이미지 안에 SBOM 도구(syft) 핀이 있으나 release-signing.yml은 호스트에서 syft 별도 설치
- **위치**: `release-signing.yml:76` `anchore/sbom-action/download-syft@7b36ad622f042cab6f59a75c2ac24ccb256e9b45 # v0.20.4`
- **현상**: 빌더에 `syft==1.14.1`이 핀되어 있지만 release-signing.yml은 호스트에서 별도 syft 설치 후 사용. 따라서 **빌더 이미지의 syft 버전과 release-signing의 syft 버전이 다를 수 있음**. 이는 라운드 B의 "도구 풀스택 핀" 의도와 모순. SBOM 산출물의 버전 차이는 SPDX 출력 차이를 야기할 수 있음(추적성 영향).
- **수정**: release-signing.yml의 sign-and-attest 잡도 빌더 이미지 안에서 실행하거나, 호스트 syft 버전을 Dockerfile.builder와 동기화하는 정책 명시.
- **담당**: security-scanner + infra-engineer

#### F-043 🟡 verify-builder 잡 자체에 `BUILDER_IMAGE_DIGEST` 검증 외 cosign 다운로드 실패 fallback 부재
- **위치**: 6개 워크플로 verify-builder
- **현상**: `sigstore/cosign-installer@d7d6bc77...` 액션이 외부 GitHub Releases에서 cosign binary를 받는다. Sigstore 인프라 또는 GitHub Releases 일시 장애 시 모든 CI/CD가 차단됨. 백업 메커니즘 부재.
- **영향**: SPOF — Sigstore가 24시간 장애 발생 시 운영 차단.
- **수정**: 빌더 이미지에 cosign이 핀되어 있으므로 옵션:
  - (A) verify-builder 잡 자체를 빌더 이미지 안에서 실행 (단 chicken-and-egg — verify-builder가 검증하는 빌더를 검증 잡이 신뢰할 수 없음).
  - (B) `sigstore/cosign-installer`를 fallback으로 hardcoded URL + sha256으로 직접 다운로드.
  - (C) 단기 — 운영 상 Sigstore 장애 시 `if: !cancelled()` 흐름과 함께 `--insecure-skip-tlog-verify` fallback(보안 약화, 비추천).
  - 권고: 현 상태 유지하되 Sigstore 장애를 모니터링 항목으로 등록.
- **담당**: infra-engineer (모니터링 항목 추가 — 04 §6.2 항목 신설)

### 🔵 신규 모니터링 — 5건

- **F-044 🔵 `Dockerfile.builder:43, 155` placeholder digest 그대로** — F-009 동일 패턴. 사용자 환경 실측 후 fix-up.
- **F-045 🔵 빌더 이미지 tag :latest 사용 가능성** — Dockerfile.builder.README.md §6 로컬 재현 가이드(`docker run ... ghcr.io/.../uav-soc-builder:latest`)에서 `:latest` 허용. 운영 정책상 prod CI는 digest만 사용해야 — 가이드에 경고 추가됨(L130).
- **F-046 🔵 ai-redteam-check 잡이 `gh CLI`를 빌더 이미지에서 사용** — `cd-prod.yml:175-202` `gh run list` 호출. 빌더 이미지의 `gh==2.55.0` 핀 사용. `gh CLI`가 read-only rootfs에서 config 디렉터리(`~/.config/gh`)에 쓰지 않는지 확인 필요(단 `GH_TOKEN` 환경변수 사용 시 config 미생성). 1회 운영 확인 권장.
- **F-047 🔵 빌더 이미지 월 1회 갱신 PR이 모든 워크플로 영향** — `build-builder.yml:35-37` cron `0 4 1 * *`. 갱신 시 도구 버전 변경(예: ruff 0.5.7 → 0.5.8)이 비호환 변경을 일으키면 모든 CI 차단. README §4가 "수동 머지"를 강조하나 자동화된 호환성 회귀 테스트 부재. → smoke-test 잡이 도구 `--version`만 검증, 실제 코드베이스 lint/test 실행 안 함. CI 회귀 테스트 별도 PR 권장.
- **F-048 🔵 빌더 이미지 1.5GB+ 추정 — Storage 비용** — pytest/black/ruff/mypy/semgrep/checkov/trestle + binary 5종 + venv 모두 포함. GHCR 무료 한도 영향 모니터링 권장.

---

## §3. 인터페이스 정합성 매트릭스 (갱신)

| # | 인터페이스 | 생산자 | 소비자 | 정합 | 1차 → 라운드 2 |
|---|---|---|---|---|---|
| 1 | `g2_summary.json` 스키마 | `check_gates.py --summary-json` | `cd-prod.yml:139-170` Pushgateway push | ✅ | ❌ → ✅ (F-008 해결) |
| 2 | `failed_gates_poam.json` POAM 스키마 | `check_gates.py --emit-poam` | `check_poam_thresholds.py` | ✅ | ✅ → ✅ |
| 3 | `ai_redteam_poam.json` POAM 스키마 | `ai_redteam_to_poam.py --out` | `check_poam_thresholds.py` (✅) + `build_oscal.py --append-poam` (❌) | ⚠️ | ⚠️ → ⚠️ (F-003 잔존) |
| 4 | `previous_pass.json` 스키마 | `ai-redteam.yml`(atlas-deterministic) | `ai_redteam_to_poam.py --previous-pass` | ✅ | ⚠️ → ✅ (F-017 해결, dawidd6 채택) |
| 5 | POAM severity 정규화 | 3가지 생산자 | check_poam_thresholds + oscal_to_metrics SEVERITY_ALIASES | ✅ | ✅ → ✅ |
| 6 | POAM closed 키워드 | 모든 생산자 | `_is_closed` 함수 양쪽 | ✅ | ✅ → ✅ |
| 7 | `failed_ttps.json` 스키마 | `ai-redteam.yml` | `build_oscal.py --append-poam` | ❌ | ❌ → ❌ (F-003 미해결, 04 §3.7 단일 출처 부재) |
| 8 | OSCAL 메트릭 이름 | oscal_to_metrics.py | prometheusrule + grafana | ✅ | ✅ → ✅ |
| 9 | AnalysisTemplate ↔ ServiceMonitor 메트릭 | hotpath-success-rate-latency.yaml | servicemonitor.yaml soc-hotpath | ⚠️ | ⚠️ → ⚠️ (F-020 해결, F-023 잔존) |
| 10 | `image_ref`/`image_tag` | cd-staging/cd-prod build-push | release-signing.yml | ✅ | ✅ → ✅ |
| 11 | AKS 자격 환경변수 | infra-engineer §3.2 | cd-prod rollouts-monitor + ai-redteam pyrit-campaign | ⚠️ | ⚠️ → ⚠️ |
| 12 | DORA 메트릭 | cd-staging/cd-prod dora-push 잡 | grafana-dora + prometheusrule | ✅ | ❌ → ✅ (F-007 해결) |
| 13 | G2/AI Red Team Pushgateway | cd-prod g2-gate + ai-redteam report-and-poam push step | prometheusrule g2-regression/ai-redteam 그룹 | ✅ | ❌ → ✅ (F-008 해결) |
| 14 | SHA 핀 표 (02 §8) ↔ 워크플로 | infra-engineer §8 | 모든 워크플로 `uses:` | ⚠️ | ⚠️ → ✅ (ci-quality-patch SHA 핀 + azure/login 통일 — 단 F-033 일괄 검증 잔존) |
| 15 | quality-gate ↔ check_gates.py 코드 통과 | 04b ruff D/T20/ANN/PT | check_gates.py 842줄 | ✅ | ✅ → ✅ |
| 16 | OSCAL Profile mapped controls ↔ POAM | build_oscal.py:362 | ai_redteam_to_poam ATLAS_TO_AI_RMF | ✅ | ✅ → ✅ |
| **17 (신규)** | **`vars.BUILDER_IMAGE_DIGEST` ↔ 6개 워크플로** | `build-builder.yml` update-digest PR + 사용자 `gh variable set` | ci-enhanced/cd-staging/cd-prod/ci-quality-patch/ai-redteam `container:` 핀 + verify-builder cosign verify | ⚠️ | (신규) ⚠️ (부트스트랩 chicken-and-egg) |
| **18 (신규)** | **빌더 cosign certificate-identity-regexp ↔ build-builder.yml workflow path** | build-builder.yml 빌드 시 OIDC subject | 6개 워크플로 cosign verify | ⚠️ | (신규) ⚠️ (anchor 부재, F-038) |
| **19 (신규)** | **빌더 이미지 도구 핀 ↔ pyproject.toml.patch dev extras** | Dockerfile.builder `pip install` | pyproject.toml.patch optional-dependencies.dev | ⚠️ | (신규) ⚠️ (release-signing의 syft만 호스트, 빌더의 syft 분리 — F-042) |

**요약**: ✅ 12 / ⚠️ 6 / ❌ 1 (1차: ✅ 9 / ⚠️ 4 / ❌ 4)

---

## §4. 운영 준비성 + 방산 컴플라이언스 재평가

### 4.1 운영 준비도 (라운드 A+B 후)

| 항목 | 1차 | 라운드 2 | 비고 |
|------|-----|---------|------|
| 모든 워크플로 timeout 명시 | ✅ | ✅ | verify-builder 3분, 빌더 잡들 ≤ 60분 |
| 모든 워크플로 `permissions:` 최소 | ✅ | ✅ | |
| 자동 롤백 메커니즘 | ⚠️ | ⚠️ | F-018 잔존 |
| 시크릿 OIDC keyless | ✅ | ✅ | |
| SBOM·서명·SLSA | ✅ | ✅ | 빌더 이미지도 cosign + SBOM attest |
| 알림·승인 게이트 | ✅ | ✅ | |
| 의존 리소스 사전 준비 | ⚠️ | ⚠️ | F-031, F-032 + 빌더 부트스트랩 추가 |
| 시크릿 사전 등록 | ⚠️ | ⚠️ | + `vars.BUILDER_IMAGE_DIGEST` 추가 (사용자 작업 필요) |
| 메트릭 instrumentation | ❌ | ⚠️ | F-007/F-008은 해결되었으나 F-023(앱 노출) 잔존 |
| 첫 배포 dry-run | ⚠️ | ⚠️ | 빌더 부트스트랩 단계가 추가됨 → 사용자 절차 복잡도 증가 |
| 감사 추적성 | ✅ | ✅ | + 빌더 digest 갱신 PR 추적성 추가 |
| 비용 상한 | ✅ | ⚠️ | F-040 lint 중복 + verify-builder 6회/PR → 러너 시간 증가 |
| 도메인 G2 게이트 ↔ benchmarks 결과 | ⚠️ | ✅ | F-002 해결 |
| **(신규) 빌더 이미지 신뢰 체인** | — | ⚠️ | F-036/F-037/F-038 잔존 |
| **(신규) 호스트/컨테이너 환경 일관성** | — | ⚠️ | F-039 잔존 (ai-redteam.yml 3개 잡), F-042 (syft 버전 분리) |

**운영 준비도 종합**: 🔴(1차) → 🟡(라운드 2, **조건부 머지 가능**)

조건: ① 부트스트랩 5단계 사용자 수행, ② F-036/F-038 (placeholder + regex anchor) 정정, ③ F-006 트랙 A 단일 선택, ④ F-009 base digest 실측.

### 4.2 방산 컴플라이언스 (NIST SSDF/800-204D/AI RMF)

| Practice | 1차 | 라운드 2 | 비고 |
|---|---|---|---|
| PS.1.1 시크릿 보호 | ✅ | ✅ | Gitleaks 빌더 핀화 + .gitleaks.toml 미생성 잔존 |
| PS.2.1 의존성 핀 | ⚠️ | ⚠️ | F-011 해결, F-014 잔존(SLSA 예외 코멘트). 빌더 이미지로 도구 핀 강화. 단 F-036(binary digest 무력화)로 부분 약화 |
| **PS.2.2 빌드 무결성** | ✅ | ✅(강화) | cosign keyless + SLSA L3 + 빌더 이미지 자체 서명 — **강화**. 단 F-038(regex 앵커) 잔존 |
| PS.3.1/3.2 SBOM/Attest | ✅ | ✅ | + 빌더 이미지 SBOM. 단 F-042(syft 버전 분리) |
| PW.1.1 시크릿 차단 | ✅ | ✅ | |
| PW.4.1/4.4 SCA | ⚠️ | ⚠️ | F-021 잔존 |
| PW.5.1 IaC 보안 | ❌ | ❌ | 빌더에 checkov 핀 추가됐으나 워크플로에서 호출 없음 — 미작동 |
| PW.7.1/7.2 SAST | ⚠️ | ✅ | F-010 부분 해결 (returntocorp/semgrep 외부 의존 제거) |
| PW.9.1 안전한 기본값 | ✅ | ✅(강화) | + 빌더 이미지 non-root + read-only rootfs |
| PO.5.1 컴플라이언스 | ⚠️ | ⚠️ | F-001 해결, F-003 잔존 |
| RV.1.1 nightly 재스캔 | ❌ | ❌ | Trivy nightly 미작성 |

| 800-204D Family | 1차 | 라운드 2 | 비고 |
|---|---|---|---|
| SR-3 의존성 위험 | ⚠️ | ⚠️ | Trivy fs 잡 미작성 |
| SR-4 빌드 무결성·SBOM | ✅ | ✅(강화) | |
| **MA-3 빌드 인증** | ✅ | ✅(강화) | OIDC + Fulcio + Rekor + 빌더 이미지 서명 체인 — **강화**. 단 F-038 정정 필요 |
| PO-1 거버넌스 | ⚠️ | ⚠️ | CODEOWNERS 미생성 |

| AI RMF 통제 | 1차 | 라운드 2 | 비고 |
|---|---|---|---|
| GOVERN 1.4, 1.6 | ⚠️ | ⚠️ | |
| GOVERN 6.1 (공급망) | ✅ | ✅(강화) | |
| MAP 4.1/4.2 | ⚠️ | ⚠️ | IaC 게이트 미구현 |
| MEASURE 2.3, 2.7 | ⚠️ | ⚠️ | F-023 잔존 |
| MEASURE 2.6, 2.9 | ✅ | ✅ | + 빌더 안에서 실행 → 재현성 강화 |
| MANAGE 1.3, 3.1 | ⚠️ | ⚠️ | F-003 잔존 |
| MANAGE 2.4 | ⚠️ | ⚠️ | F-006 잔존 |
| MANAGE 4.1 | ⚠️ | ⚠️ | F-007/F-008 해결, F-023 잔존 |

**방산 컴플라이언스 종합**: 🟡(1차) → 🟡(라운드 2)

라운드 B는 PS.2.2/MA-3/PW.9.1을 강화했지만 PS.2.1은 F-036(sha256 무력화)로 부분 약화 — 순차감. 신규 갭: **빌더 이미지 자체의 신뢰 부트스트랩**(SSDF PO.5.1 추가 항목).

---

## §5. 잔여 🔴/🟡/🔵 종합

### 🔴 필수 수정 — 9건

**1차 잔존 (4건)**:
- F-003 build_oscal --append-poam 미구현 (워크플로 우회 작동, 04 §3.7 단일 출처 부재)
- F-006 ArgoCD Deployment/Rollout 동기화 충돌 (사용자 결정 보류)
- F-009 Dockerfile base digest placeholder (런타임 이미지)
- F-010 Semgrep 컨테이너 → 빌더 이미지의 semgrep==1.85.0 핀 검증 필요 (부분 해결)

**라운드 B 신규 (5건)**:
- F-036 Dockerfile.builder binary SHA256 placeholder + `|| true` 무력화
- F-037 부트스트랩 chicken-and-egg (BUILDER_IMAGE_DIGEST 미설정 차단)
- F-038 cosign verify `certificate-identity-regexp` anchor 부재
- F-039 ai-redteam.yml 화이트리스트 3개 잡 Python 환경 불일치
- F-040 ci-enhanced lint ↔ ci-quality-patch lint 중복(F-016 강화 재발)

### 🟡 권장 수정 — 14건

**1차 잔존 (10건)**: F-014, F-015, F-016(→F-040으로 흡수), F-018, F-019, F-021, F-022, F-023, F-025

**라운드 A 자체 (1건)**:
- F-035 dora-push needs 그래프에 smoke skip 시 잡 흐름 혼동 가능성

**라운드 B 신규 (4건)**: F-041 (캐시 디렉터리 충돌), F-042 (syft 호스트/빌더 분리), F-043 (sigstore SPOF), F-035

### 🔵 모니터링 — 14건

1차 9건(F-026~F-034) + 라운드 B 신규 5건(F-044~F-048).

### 머지 가능 여부 판정

| Phase | 1차 결정 | 라운드 2 결정 | 비고 |
|-------|---------|--------------|------|
| Phase A (스크립트 → 정식 경로) | 차단(F-001/F-002/F-003) | **🟢 진행 가능** | F-001/F-002 해결, F-003은 워크플로 우회 — 별도 PR로 분리 |
| Phase B (워크플로) | 차단(다수 🔴) | **🟡 부트스트랩 후 진행** | 빌더 이미지 부트스트랩(별도 단계 0) → ci-quality-patch → ci-enhanced → cd-staging → cd-prod → ai-redteam 순서 |
| Phase C (인프라) | 차단(F-006) | 차단 | F-006 사용자 결정 보류 |
| Phase D (모니터링) | 차단(F-007/F-008) | **🟡 진행 가능** | F-007/F-008 해결. 단 Argo Rollouts/Pushgateway 설치 PR 선행 |
| Phase E (pyproject/pre-commit) | 차단(F-013) | **🟢 진행 가능** | F-013 해결 |

**종합**: 🟡 **조건부 머지 가능** — Phase A/D/E는 즉시 가능. Phase B는 빌더 부트스트랩 + F-036/F-038 정정 후 가능. Phase C는 사용자 결정(F-006) 후 가능.

---

## §6. 머지 가능 여부 + 사용자 다음 액션 우선순위

### 6.1 머지 가능 여부 종합

- **운영 준비**: 🟡 (조건부 가능)
- **방산 컴플라이언스**: 🟡 (PS.2.2/MA-3 강화, 단 F-036/F-038 정정 필요)
- **잔여 🔴**: 9건 (1차 4건 + 라운드 B 5건)
- **잔여 🟡**: 14건
- **머지 가능 Phase**: A(즉시), D(인프라 설치 PR 후), E(즉시), B(부트스트랩 + 3건 정정 후), C(F-006 결정 후)

### 6.2 사용자 다음 액션 — 핵심 3가지 (Top Priority)

1. **🔴 [블로커] 빌더 이미지 부트스트랩 5단계 + binary digest 실측**
   - **사전**: `docker pull python:3.11-slim-bookworm` 후 sha256 실측 → `Dockerfile.builder:43, 155` placeholder 치환
   - 5개 binary(gitleaks/syft/trivy/cosign/gh) release 페이지에서 `*_checksums.txt` 다운로드 → `Dockerfile.builder:104, 114, 124, 135, 144` ARG 치환 + `|| true` **모두 제거** (F-036)
   - PR-0: `deploy/Dockerfile.builder` + `build-builder.yml` 만 머지 (다른 워크플로 patch는 보류)
   - `gh workflow run build-builder.yml --ref main` → 자동 PR 머지 → `gh variable set BUILDER_IMAGE_DIGEST sha256:<digest>`
   - 그 다음 단계로 ci-quality-patch.yml → ci-enhanced.yml → cd-staging.yml → cd-prod.yml → ai-redteam.yml patch를 1개씩 머지하며 각 단계 검증
   - **이 단계 미수행 시 모든 CI/CD 즉시 차단**

2. **🔴 [블로커] cosign verify regex 정정(F-038) + 트랙 A 단일 선택(F-006)**
   - F-038: 6개 워크플로 verify-builder의 regex를 `^https://github\.com/s1ns3nz0/pollack-ai/\.github/workflows/build-builder\.yml@refs/heads/main$`로 강화 (또는 운영 정책 결정 후 ref 패턴 명시)
   - F-006: `deploy/k8s/30-deployment-a-hotpath.yaml` 또는 `argo-rollout-hotpath.yaml` 중 하나 git rm 강제. 임시: ArgoCD Application의 `directory.exclude`에 미선택 파일 추가
   - 미수행 시 첫 prod 배포가 ArgoCD sync 충돌로 비결정 상태

3. **🟡 [강력 권고] ci-enhanced ↔ ci-quality-patch lint 중복 제거(F-040) + ai-redteam 화이트리스트 잡 Python 환경 통일(F-039)**
   - F-040: `ci-enhanced.yml:104-120`의 lint 잡 제거 → ci-quality-patch.yml이 단독 담당. PR당 verify-builder 호출이 6→3회로 축소(러너 비용·F-038 노출면 감소)
   - F-039: ai-redteam.yml의 pyrit-campaign/garak-campaign/report-and-poam을 빌더 이미지 안에서 실행하도록 변경(빌더에 azure-cli + gh 핀 추가 PR 동반) — 라운드 B 재현성 의도 달성
   - 미수행 시 환경 불일치로 인한 간헐적 회귀 발생 위험

### 6.3 권장 다음 머지 순서

```
PR-0 (Bootstrap)
  ├─ Dockerfile.builder digest 실측 + || true 제거
  ├─ build-builder.yml 머지
  ├─ workflow_dispatch 첫 빌드
  └─ gh variable set BUILDER_IMAGE_DIGEST

PR-1 (Phase A - 스크립트)
  ├─ check_poam_thresholds.py → compliance/oscal/
  ├─ check_gates.py → benchmarks/
  └─ ai_redteam_to_poam.py → scripts/

PR-2 (Phase E - pyproject)
  └─ pyproject.toml.patch 적용 (F-013 해결됨)

PR-3 (F-038 정정)
  └─ 6개 워크플로 verify-builder regex 강화

PR-4 (Phase B - 워크플로, 단계별)
  ├─ ci-quality-patch.yml (lint 단독 담당, F-040 정정)
  ├─ ci-enhanced.yml (lint 제거)
  ├─ cd-staging.yml (F-005/F-007 해결됨)
  ├─ cd-prod.yml (F-001/F-008 해결됨)
  └─ ai-redteam.yml (F-004/F-017 해결됨, F-039 정정 권고)

PR-5 (Phase C - 인프라, 사용자 결정 후)
  ├─ 트랙 A 단일 선택(F-006)
  └─ Dockerfile + deploy/k8s 적용

PR-6 (Phase D - 모니터링, 인프라 설치 후)
  ├─ Argo Rollouts 컨트롤러 Helm Application
  ├─ Pushgateway Helm Application
  └─ servicemonitor.yaml + prometheusrule.yaml + dashboards

PR-7 (별도 — F-003 우회 해소)
  └─ build_oscal.py --append-poam 정식 구현 + poam_schema.py 단일 출처
```

---

## §7. 마지막 보고 (핵심 3가지)

1. **🔴 잔여 카운트 — 총 9건**: 1차 잔존 4건(F-003, F-006, F-009, F-010) + 라운드 B 신규 5건(F-036~F-040). 머지 가능 등급은 🟡(조건부) — 부트스트랩 절차 + 사용자 결정 5건 + placeholder 6종 실측 후 머지 권장.

2. **머지 가능 여부**: **조건부 가능**(🟡). Phase A/D/E는 즉시 가능. Phase B는 부트스트랩 + F-036/F-038/F-040 정정 후. Phase C는 F-006 사용자 결정 후. 1차 핵심 차단성 결함(F-001/F-002/F-007/F-008/F-011/F-012/F-013/F-017/F-020)이 모두 해결되어 라운드 B의 빌더 부트스트랩만 안전히 수행하면 운영 진입 가능.

3. **사용자 다음 액션 핵심 3가지**:
   - **부트스트랩 + binary digest 실측**: Dockerfile.builder 6종 placeholder(base + 5 binary) 실측 + `|| true` 제거(F-036). 그 다음 build-builder.yml 단독 머지 → workflow_dispatch → `gh variable set BUILDER_IMAGE_DIGEST`. 이 한 단계 미완료 시 모든 후속 머지가 CI 차단.
   - **cosign regex 강화(F-038) + 트랙 A 단일 선택(F-006)**: 6개 워크플로 verify-builder의 `certificate-identity-regexp`에 `^...@refs/heads/main$` 앵커 추가. `deploy/k8s/30-deployment-a-hotpath.yaml` ↔ `argo-rollout-hotpath.yaml` 중 1개 git rm. 미수행 시 prod 배포가 ArgoCD 충돌 + 공급망 검증 우회 가능.
   - **lint 중복 제거(F-040) + ai-redteam 환경 통일(F-039)**: ci-enhanced의 lint 잡 제거. ai-redteam.yml의 3개 화이트리스트 잡을 빌더 이미지 위로 이전 또는 환경 동기화. 미수행 시 라운드 B 재현성 보장이 깨지고 PR당 verify-builder 6회 호출로 비용·보안 면적 증가.

운영 준비: 🟡 **조건부 머지 가능**. 방산 컴플라이언스: 🟡 **PS.2.2/MA-3 강화, 단 F-036/F-038 정정 필요**.

---

**라운드 2 리뷰 종료**.
