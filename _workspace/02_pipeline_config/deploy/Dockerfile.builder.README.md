# uav-soc-builder — CI/CD 공통 빌더 이미지 운영 가이드

> 본 문서는 `_workspace/02_pipeline_config/deploy/Dockerfile.builder` 가
> 산출하는 `ghcr.io/s1ns3nz0/uav-soc-builder` 이미지의 운영·갱신·재현·부트스트랩 절차를 정의한다.

---

## 1. 목적

| 목표 | 구현 |
|------|------|
| 재현성(reproducibility) | 모든 CI 도구를 SemVer 핀 + base 이미지 digest 핀 |
| 공급망 무결성(supply chain) | cosign keyless 서명 + Syft SBOM attest, GHCR push 는 OIDC 기반 GITHUB_TOKEN |
| 에어갭 호환(air-gapped) | 단일 이미지로 모든 도구 제공 — 잡 실행 중 `pip install` 행위 제거 |
| 권한 최소화(least privilege) | non-root uid 10001, read-only rootfs, cap-drop=ALL |

---

## 2. 도구 풀스택 핀 목록

| 분류 | 도구 | 버전 | 비고 |
|------|------|------|------|
| Python 품질 | black | 24.10.0 | `ci-quality-patch.yml#lint` |
| Python 품질 | ruff | 0.5.7 | `ci-quality-patch.yml#lint` |
| Python 품질 | mypy | 1.11.2 | `ci-quality-patch.yml#typecheck` |
| Python 품질 | pytest | 8.3.3 | `ci-enhanced.yml#test` |
| Python 품질 | pytest-cov | 5.0.0 | coverage 임계 검증 |
| Python 품질 | pytest-asyncio | 0.24.0 | async agent 테스트 |
| Python 품질 | interrogate | 1.7.0 | 독스트링 ≥80% |
| Python 품질 | xenon | 0.9.3 | 복잡도 게이트 |
| 보안(SCA/SAST) | pip-audit | 2.7.3 | SCA 보완 |
| 보안(SAST) | semgrep | 1.85.0 | p/python + p/security-audit |
| 보안(IaC) | checkov | 3.2.255 | K8s/Dockerfile 정적 분석 |
| 보안(시크릿) | gitleaks | 8.18.4 | binary, 이력+staged 스캔 |
| 보안(SBOM) | syft | 1.14.1 | binary, SPDX-JSON 산출 |
| 보안(컨테이너) | trivy | 0.55.2 | binary, CVSS Critical 차단 |
| 보안(서명) | cosign | 2.4.1 | binary, Sigstore keyless |
| OSCAL | compliance-trestle | 3.5.1 | trestle validate 5종 |
| OSCAL | jsonschema | 4.23.0 | 보조 검증 |
| GitHub | gh CLI | 2.55.0 | binary, `cd-prod.yml#ai-redteam-check` 등 사용 |
| 유틸 | jq, curl, git, tini, bash | distro 기본 | apt |

> 갱신 정책: 도구별 Major/Minor 변경 시 PR, Patch 변경은 월 1회 schedule run.

---

## 3. 빌드 주기

| 트리거 | 동작 | 결과 |
|--------|------|------|
| `push to main` (Dockerfile.builder/pyproject.toml/build-builder.yml 변경) | 즉시 빌드 | 신규 digest PR |
| `schedule: 0 4 1 * *` (월 1회) | 정기 갱신 빌드 | 베이스 CVE 패치 반영 PR |
| `workflow_dispatch` | 수동 부트스트랩/핫픽스 | 강제 태그 지원 |

---

## 4. 도구 버전 갱신 절차

1. **갱신 PR**
   ```bash
   git checkout -b chore/builder-tools-bump
   # deploy/Dockerfile.builder 의 ARG/RUN pip install 핀 버전 수정
   git commit -am "chore(builder): bump black 24.10.0 -> 24.11.0"
   git push -u origin chore/builder-tools-bump
   gh pr create --base main
   ```
2. **PR 머지** → `build-builder.yml` 자동 실행 → 신규 이미지 + cosign 서명 + smoke-test 통과
3. **digest 갱신 PR 자동 생성** (`ci-bot/builder-digest-<run_id>`) → 머지
4. **repo variable 갱신** (수동, 머지 후 1줄 명령):
   ```bash
   gh variable set BUILDER_IMAGE_DIGEST \
     --body "sha256:<신규 digest>" \
     --repo s1ns3nz0/pollack-ai
   ```
5. 다음 워크플로 실행부터 모든 잡이 신규 빌더 이미지에서 실행됨.

> **자동 PR 갱신을 자동 머지하지 않는 이유**: 도구 버전이 사후 호환성을 깨면 모든 CI 잡이 한 번에 실패한다. 사람이 PR diff 를 보고 머지 시점을 통제.

---

## 5. digest 핀 갱신 메커니즘

```
build-builder.yml
  └─ build-builder        ──→ outputs.image_digest
  └─ sign-attest          ──→ release-signing.yml (cosign keyless)
  └─ smoke-test           ──→ docker run 도구 자기진단
  └─ update-digest        ──→ peter-evans/create-pull-request
                             └─ deploy/.builder-image-digest 파일 갱신 PR

(사람) PR 머지 + gh variable set BUILDER_IMAGE_DIGEST <new>

다음 CI 잡:
  jobs.lint.container.image = ghcr.io/.../uav-soc-builder@${{ vars.BUILDER_IMAGE_DIGEST }}
  + first step: cosign verify (서명 무결성 강제)
```

`deploy/.builder-image-digest` 는 사람이 읽는 진실 원본(audit trail). `vars.BUILDER_IMAGE_DIGEST` 는 워크플로가 실제 참조하는 값.

---

## 6. 로컬 재현(개발자)

CI 와 동일한 환경에서 로컬 검증:

```bash
# 1) 이미지 pull (digest 핀)
docker pull ghcr.io/s1ns3nz0/uav-soc-builder@${BUILDER_IMAGE_DIGEST}

# 2) 코드 디렉터리를 mount 해서 도구 실행
docker run --rm \
  -v "$(pwd)":/workspace \
  --user 10001 \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m \
  --cap-drop=ALL \
  ghcr.io/s1ns3nz0/uav-soc-builder@${BUILDER_IMAGE_DIGEST} \
  black --check .

# 3) pre-commit 대용 — black + ruff + mypy + pytest 한 번에
docker run --rm \
  -v "$(pwd)":/workspace \
  --user 10001 \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --cap-drop=ALL \
  ghcr.io/s1ns3nz0/uav-soc-builder:latest \
  bash -lc 'black --check . && ruff check . && mypy . && pytest -q'
```

> 로컬에선 `:latest` 도 OK. CI 는 항상 digest 핀.

---

## 7. cosign 서명 검증

다운스트림 잡(또는 사람)이 빌더 이미지를 신뢰하려면:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github\.com/s1ns3nz0/pollack-ai/\.github/workflows/build-builder\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/s1ns3nz0/uav-soc-builder@${BUILDER_IMAGE_DIGEST}
```

CI 워크플로는 모든 잡 **첫 step** 에서 이 검증을 수행한다(공급망 무결성 강제).

---

## 8. BUILDER_IMAGE_DIGEST 등록 절차 (repo variable)

### 8.1 GitHub UI

`Settings > Secrets and variables > Actions > Variables` 탭 →
`New repository variable`
- Name: `BUILDER_IMAGE_DIGEST`
- Value: `sha256:abc123…` (build-builder.yml 산출 digest)

### 8.2 gh CLI

```bash
gh variable set BUILDER_IMAGE_DIGEST \
  --body "sha256:<digest>" \
  --repo s1ns3nz0/pollack-ai

# 확인
gh variable list --repo s1ns3nz0/pollack-ai | grep BUILDER_IMAGE_DIGEST
```

> Variable(시크릿 아님) — 워크플로의 `${{ vars.BUILDER_IMAGE_DIGEST }}` 로 평문 참조됨. digest 는 비밀이 아니므로 정상.

---

## 9. 첫 배포 부트스트랩 (vars.BUILDER_IMAGE_DIGEST 미설정 시)

`vars.BUILDER_IMAGE_DIGEST` 가 비어 있으면 다운스트림 워크플로의 `container:` 핀이 만들어지지 않아 모든 잡이 즉시 실패한다. 다음 절차로 초기화:

```bash
# (1) build-builder.yml 만 머지 — 다른 워크플로는 아직 container: 핀 미적용 상태여야 함.
git checkout -b feat/builder-image
git add deploy/Dockerfile.builder _workspace/02_pipeline_config/.github/workflows/build-builder.yml
git commit -m "feat(ci): add uav-soc-builder image + build-builder.yml"
gh pr create --base main
# (사람) PR 머지

# (2) workflow_dispatch 로 첫 빌드 트리거
gh workflow run build-builder.yml --ref main

# (3) 빌드 성공 확인 + digest 획득
RUN_ID=$(gh run list --workflow=build-builder.yml --limit=1 --json databaseId -q '.[0].databaseId')
gh run watch "$RUN_ID"

# (4) 산출 digest 확보 (sign-attest 잡 로그에서도 확인 가능)
DIGEST=$(gh run view "$RUN_ID" --log | grep -oP 'sha256:[0-9a-f]{64}' | head -1)
echo "$DIGEST"

# (5) repo variable 등록
gh variable set BUILDER_IMAGE_DIGEST --body "$DIGEST" --repo s1ns3nz0/pollack-ai

# (6) 다운스트림 워크플로(ci-enhanced/cd-staging/cd-prod/ci-quality-patch/ai-redteam) PR 머지
git checkout -b feat/ci-container-pin
# 본 라운드의 5개 워크플로 patch 머지
gh pr create --base main

# (7) CI 잡이 cosign verify 통과하는지 확인
gh run watch
```

> **단계 (1) 시점에 다른 워크플로에 `container:` 핀이 이미 들어 있으면 안 된다.** 부트스트랩 순서를 깨면 chicken-and-egg.

---

## 10. 장애 대응(Runbook)

| 증상 | 원인 후보 | 조치 |
|------|---------|------|
| 모든 CI 잡이 `image pull` 단계에서 401 | `BUILDER_IMAGE_DIGEST` 미설정 또는 잘못된 값 | §8 절차로 재등록 |
| `cosign verify` step 실패 | 이미지 재태깅·수동 push 로 서명 분실 | build-builder.yml 재실행 → digest 갱신 PR 머지 |
| `BUILDER_IMAGE_DIGEST` 갱신 후 도구 동작 깨짐 | 도구 버전 비호환 | `gh variable set` 으로 이전 digest 복구 → 별도 PR 로 도구 핀 조정 |
| smoke-test 잡에서 도구 일부 누락 | Dockerfile.builder 의 `RUN ... self-check` 실패 누락 | self-check 단계에 누락 도구 추가, 다시 빌드 |
| schedule run 이 베이스 이미지 변화 없이 동일 digest | buildx provenance 동일성 — 정상. PR 본문에서 변경점 0 확인 후 close | — |

---

## 11. 변경 이력

| 일자 | 변경 | 비고 |
|------|------|------|
| 2026-06-29 | 초안(라운드 B) | 옵션 1(빌더 이미지 핀) 도입 |
