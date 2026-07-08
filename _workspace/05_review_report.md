# CI/CD 파이프라인 리뷰 보고서 (UAV AI SOC)

**리뷰어**: pipeline-reviewer
**대상 산출물**: `_workspace/{00..04d}_*.md` + `_workspace/02_pipeline_config/**`
**작성일**: 2026-06-29
**참조 기준**: NIST SSDF (SP 800-218), NIST SP 800-204D, NIST AI RMF 1.0 (OSCAL 1.1.2), `CLAUDE.md`, `.claude/rules/python-conventions.md`

---

## 1. Executive Summary

8개 산출 워크플로(`ci-enhanced/cd-staging/cd-prod/release-signing/ai-redteam/ci-quality-patch`)와 모니터링·OSCAL 자동화 매니페스트가 **설계 의도와 80% 정합**한 상태로 작성되었으나, **🔴 13건의 배포-차단성 오류**가 존재한다. 가장 치명적 결함은 (a) `check_poam_thresholds.py` 호출이 **미구현 CLI 옵션**(`--mode`, `--partial-warn`)을 사용해 prod 게이트가 **즉시 실패**하고, (b) `compliance/oscal/build_oscal.py --append-poam` 옵션이 미구현 상태에서 `ai-redteam.yml`이 의존하며, (c) 워크플로가 `_workspace/02_pipeline_config/scripts/...` 경로를 직접 호출해 실제 `.github/workflows/`로 승격 시 모두 미해결 경로가 된다. 또한 (d) DORA 메트릭·G2 Pushgateway 메트릭이 PrometheusRule에서 알림 대상이지만 **소스가 어디에도 없음**(앱·CI 어디서도 push 안 함). 운영 준비도는 🔴 **재작업** 등급.

---

## 2. 발견 항목 카탈로그

### 🔴 필수 수정 (배포 전 반드시 해결) — 13건

#### F-001 🔴 `check_poam_thresholds.py` CLI 옵션 불일치 — 즉시 실패
- **위치**: `_workspace/02_pipeline_config/.github/workflows/cd-staging.yml:212-213`, `cd-prod.yml:130-131`
- **현상**:
  ```yaml
  python compliance/oscal/check_poam_thresholds.py \
    --critical-max 0 --high-max 3 --partial-warn 25 \
    --mode block
  ```
  `check_poam_thresholds.py`(474줄)에는 `--partial-warn`·`--mode` 옵션이 **존재하지 않음**. 실제 구현은 `--warn-only` 플래그 하나뿐.
- **영향**: argparse `error: unrecognized arguments` → prod 게이트 즉시 차단(false positive). 첫 main push에서 cd-prod 실패.
- **수정**:
  ```yaml
  # cd-prod.yml
  python compliance/oscal/check_poam_thresholds.py \
    compliance/oscal/poam/uav-soc-poam.json \
    --critical-max 0 --high-max 3
  # cd-staging.yml (warn 모드)
  python compliance/oscal/check_poam_thresholds.py \
    compliance/oscal/poam/uav-soc-poam.json \
    --critical-max 0 --high-max 5 --warn-only
  ```
  또는 스크립트에 `--mode {warn|block}` 와 `--partial-warn N` 옵션을 추가 구현.
- **담당**: security-scanner (스크립트 보강) **또는** infra-engineer (워크플로 정정)

#### F-002 🔴 `check_gates.py --profile=staging|prod` 옵션 미구현
- **위치**: `cd-staging.yml:61`, `cd-prod.yml:68`
- **현상**: 워크플로가 `python benchmarks/check_gates.py --profile=prod` 호출.
  `check_gates.py` argparse에 `--profile` 인자가 **없음** (842줄, `_build_parser` 참조). 개별 임계 플래그(`--fp-threshold`, `--atlas-threshold` 등)만 존재.
- **영향**: argparse 오류 → G2 게이트 첫 호출에서 cd-staging·cd-prod 모두 실패.
- **수정**: 두 가지 중 택1.
  - (A) `check_gates.py`에 `--profile {staging|prod}` 추가, 내부에서 임계 사전(`PROFILES = {"staging": {...}, "prod": {...}}`)을 적용.
  - (B) 워크플로에서 명시 플래그로 전환:
    ```yaml
    # cd-prod.yml
    run: |
      python benchmarks/check_gates.py \
        --fp-threshold 0.05 --atlas-threshold 0.80 \
        --kpi-precision 0.85 --kpi-recall 0.85
    ```
- **담당**: test-engineer (선호: A 옵션이 향후 확장성·일관성 우수)

#### F-003 🔴 `build_oscal.py --append-poam` 미구현
- **위치**: `_workspace/04_security_scan.md §3.7`·`§9` 표, `04c_test_strategy.md §7.2` (예시 `cd-prod g2-gate`), `04d_ai_redteam.md §5`·§11.1 인터페이스 합의
- **현상**: 4개 설계 문서가 모두 `python compliance/oscal/build_oscal.py compliance/oscal --append-poam X.json` 패턴을 가정하지만, 실제 `build_oscal.py:589 main()`은 `sys.argv[1]` 하나만 받음(argparse 없음). 옵션 자체가 구현되지 않음.
- **영향**: AI 레드팀 nightly가 POAM에 자동 누적시키지 못함 → 회귀 차단 사이클 단절. test-engineer 설계 §7.2의 `if: failure()` 분기 미작동.
- **수정**: 별도 PR로 `build_oscal.py`에 argparse + `--append-poam <fragment.json>` 구현. `ai_redteam_to_poam.py`의 `merge_into_existing_poam()` 로직을 단일 출처(`compliance/oscal/poam_schema.py` 신규)로 추출 후 양측 import.
- **담당**: governance + ai-redteam-engineer (04d §13 #1·#3, 04 §10 #3 보류 항목)
- **임시 대응**: ai-redteam.yml은 `ai_redteam_to_poam.py --append-to-poam`(이미 구현됨)으로 우회. `build_oscal.py --append-poam` 의존 흐름은 별도 PR 머지 전까지 워크플로에서 제거.

#### F-004 🔴 워크플로가 `_workspace/02_pipeline_config/scripts/...` 경로 직접 참조
- **위치**: `ai-redteam.yml:216, 501, 512, 520`
- **현상**:
  ```yaml
  python _workspace/02_pipeline_config/scripts/ai_redteam_to_poam.py ...
  python _workspace/02_pipeline_config/scripts/check_poam_thresholds.py ...
  ```
  설계상 `_workspace/`는 초안 디렉토리. 실제 `.github/workflows/ai-redteam.yml`로 승격되면 해당 경로의 스크립트는 **저장소 root에 없음** → `FileNotFoundError`.
- **영향**: ai-redteam.yml 첫 실행 즉시 4개 step 실패.
- **수정**: 워크플로 머지 직전 다음 정식 경로로 교체.
  ```
  scripts/ai_redteam_to_poam.py
  compliance/oscal/check_poam_thresholds.py   (또는 scripts/check_poam_thresholds.py — F-005 참조)
  ```
- **담당**: ai-redteam-engineer + infra-engineer (`11. 마이그레이션 절차` 단계에 명시 필요)

#### F-005 🔴 `check_poam_thresholds.py` 정식 경로 불일치
- **위치**:
  - `cd-staging.yml:211`, `cd-prod.yml:129`: `compliance/oscal/check_poam_thresholds.py`
  - `ai-redteam.yml:520`: `_workspace/02_pipeline_config/scripts/check_poam_thresholds.py`
- **현상**: 같은 스크립트의 정식 배치 경로가 워크플로마다 다름. 04 §3.5.1 보류 항목이 결정 안 됨.
- **영향**: 한쪽이 정식 경로로 이동되면 다른쪽이 깨짐.
- **수정**: 사용자 결정 필요. 권고: **`compliance/oscal/check_poam_thresholds.py`** (build_oscal.py와 짝, OSCAL과 응집도). 결정 후 `ai-redteam.yml`도 동일 경로로 통일.
- **담당**: 사용자/security-scanner

#### F-006 🔴 ArgoCD 동기화 충돌 — Deployment ↔ Rollout 같은 이름·디렉토리
- **위치**:
  - `_workspace/02_pipeline_config/deploy/k8s/30-deployment-a-hotpath.yaml` (kind: Deployment, name: soc-hotpath)
  - `_workspace/02_pipeline_config/deploy/k8s/argo-rollout-hotpath.yaml` (kind: Rollout, name: soc-hotpath)
  - ArgoCD App `deploy/argocd/apps/soc.yaml:14`: `path: deploy/k8s`
- **현상**: ArgoCD가 `deploy/k8s` 전체를 sync — 동일 namespace에 동일 name으로 두 워크로드 컨트롤러를 동시에 적용. Rollout의 selector가 Deployment Pod를 가로채거나 selector 충돌로 sync 실패.
- **영향**: 첫 배포 직후 클러스터 상태 비결정. selfHeal이 두 컨트롤러 사이에서 oscillate 가능.
- **수정**: 사용자 결정(`01_pipeline_design.md §10 #1` 보류). 옵션 A 채택 시 `30-deployment-a-hotpath.yaml`을 git rm, 옵션 B 채택 시 `argo-rollout-hotpath.yaml`을 git rm. **머지 전 강제 단일 선택**. 임시 대응으로 ArgoCD Application의 `directory.exclude`에 미선택 파일 추가.
- **담당**: 사용자 + infra-engineer

#### F-007 🔴 DORA 메트릭 소스 부재 — PrometheusRule이 빈 메트릭 평가
- **위치**:
  - `prometheusrule.yaml:93, 106` (`deployment_frequency_total`, `mean_time_to_restore_seconds`)
  - `grafana-dashboard-dora.yaml:42, 67, 90, 112`
  - CI/CD 워크플로 어디에도 push 코드 없음
- **현상**: PrometheusRule이 `deployment_frequency_total`, `change_failure_total`, `lead_time_for_changes_seconds_bucket`, `mean_time_to_restore_seconds` 4종 메트릭을 알림 조건으로 사용. 그러나 어떤 워크플로 step도 Pushgateway에 push 안 함. exporter 매니페스트도 없음.
- **영향**: `DeploymentFrequencyDrop` 알림이 24h 0건 = no-data 상태로 영구 발화. `MTTRBudgetExceeded`는 메트릭 부재로 false. 대시보드 패널 빈 그래프.
- **수정**: 두 트랙 중 택1.
  - (A) cd-prod.yml/cd-staging.yml 종료 step에 Pushgateway push 추가:
    ```yaml
    - name: DORA — 배포 빈도 push
      if: success()
      run: |
        cat <<EOF | curl --data-binary @- ${PUSHGATEWAY_URL}/metrics/job/cd-prod/instance/${{ github.run_id }}
        deployment_frequency_total{environment="production"} 1
        EOF
    ```
  - (B) GitHub Actions workflow_run exporter Helm Application(예: `kubectl apply -f https://...`) 별도 PR.
  - 03_monitoring §12 #4 보류 — **사용자 결정 필요**.
- **담당**: monitoring-specialist + infra-engineer

#### F-008 🔴 G2/AI 레드팀 Pushgateway 메트릭 소스 부재
- **위치**:
  - `prometheusrule.yaml:124-167` (g2-regression, ai-redteam 그룹)
  - 워크플로 어디에도 `g2_summary.json → Pushgateway` push 없음
- **현상**: `g2_gate_pass_total`, `g2_gate_fail_total`, `g2_gate_value`, `ai_redteam_ttp_fail_total`, `ai_redteam_determinism_check`, `garak_probe_fail_rate` 메트릭이 알림·대시보드 의존이나 push 코드 없음.
  - `04c_test_strategy.md §9 (monitoring-specialist 송신)` 합의는 있으나 워크플로 미반영.
  - `04d_ai_redteam.md §7.3` 합의도 미반영.
- **영향**: G2/AI 레드팀 알림 영구 no-data. 가시성 0.
- **수정**: cd-prod g2-gate 잡 끝에 push step 추가:
  ```yaml
  - name: G2 summary → Pushgateway
    if: always() && vars.PUSHGATEWAY_URL != ''
    run: |
      python - <<PY
      import json, urllib.request
      s = json.load(open('g2_summary.json'))
      lines = []
      for g in s.get('gates', []):
        name = g['name']; sev = g['severity']
        if g['passed']: lines.append(f'g2_gate_pass_total{{name="{name}"}} 1')
        else: lines.append(f'g2_gate_fail_total{{name="{name}",severity="{sev}"}} 1')
        if g.get('value') is not None:
          lines.append(f'g2_gate_value{{name="{name}"}} {g["value"]}')
      body = '\n'.join(lines) + '\n'
      req = urllib.request.Request('${PUSHGATEWAY_URL}/metrics/job/g2-gate/instance/${{ github.run_id }}', data=body.encode(), method='POST')
      urllib.request.urlopen(req)
      PY
  ```
  ai-redteam.yml `report-and-poam`에도 동등 push step. `check_gates.py`는 이미 `--summary-json` 출력 지원(F-002 무관 별개로 사용 가능).
- **담당**: monitoring-specialist + test-engineer + ai-redteam-engineer

#### F-009 🔴 Dockerfile 베이스 이미지 digest가 placeholder(가짜 해시)
- **위치**: `_workspace/02_pipeline_config/deploy/Dockerfile:24, 66`
- **현상**: `FROM python:3.11-slim-bookworm@sha256:7f9e6f4f9a8a6d7e2c2b3c0a9b6e7d8f4c2a1d9e6f7a8b3c4d5e6f7a8b9c0d1e` — sha256 패턴이지만 실제 존재하는 digest가 아닐 가능성 매우 높음(반복 패턴). `02_infra_config.md §10.3` 인계에서 인지된 placeholder.
- **영향**: docker buildx 첫 빌드에서 `manifest unknown` 오류로 CI 차단. 공급망 무결성 위장.
- **수정**:
  ```bash
  docker pull python:3.11-slim-bookworm
  docker inspect --format='{{index .RepoDigests 0}}' python:3.11-slim-bookworm
  # 결과로 placeholder 교체 + 두 FROM 라인 통일
  ```
  Dependabot `docker` ecosystem 활성화 PR 동반.
- **담당**: infra-engineer (사용자 환경에서 1회 실측 후 fix-up PR)

#### F-010 🔴 Semgrep 컨테이너 digest가 placeholder
- **위치**: `ci-enhanced.yml:214`
- **현상**: `image: returntocorp/semgrep@sha256:8c1f5e64d0c6ad34a0b9cf04ee0e8e6e8e62b96f9c87a7ee84f5a5c52b3e6cf3` — F-009와 유사하게 가짜 digest 가능성. infra-engineer §10.3 (Semgrep container digest) 인계 인지.
- **영향**: Semgrep 잡 첫 실행에서 image pull 실패.
- **수정**: `docker pull returntocorp/semgrep:latest && docker inspect --format='{{index .RepoDigests 0}}' returntocorp/semgrep:latest`로 확정 후 갱신. SHA 핀이 안되면 `:latest` 태그 사용은 공급망 정책상 차단(설계 §6.2 #1).
- **담당**: security-scanner + infra-engineer

#### F-011 🔴 `ci-quality-patch.yml` 액션 미핀(SHA 안 박힘)
- **위치**: `ci-quality-patch.yml:43, 46, 73, 76, 95, 98, 124, 127, 146`
- **현상**: 모두 `actions/checkout@v4`·`actions/setup-python@v5` 태그만 사용. `04_security_scan.md §6.2 #1` "모든 `uses:`가 40자 SHA로 핀"과 정면 위반.
- **영향**: 공급망 무결성 위반. devsecops-redteam 자기점검 차단. ci-enhanced와 정책 불일치.
- **수정**: 모든 액션을 `ci-enhanced.yml`과 동일 SHA(파일 내 주석으로 명시되어 있음)로 교체.
- **담당**: quality-gate (본인 산출물 정합) **또는** infra-engineer (SHA 표 적용)

#### F-012 🔴 ai-redteam.yml `azure/login` SHA 불일치
- **위치**:
  - `cd-prod.yml:364`: `azure/login@a65d910e8af852a8061c627c456678983e180302 # v2.2.0`
  - `ai-redteam.yml:298`: `azure/login@a457da9ea143d694b1b9c7c869ebb04ebe844ef5 # v2.3.0`
- **현상**: 같은 액션이 SHA가 다름. 02 §8 인계 표에는 `v2.2.0`(SHA `a65d910e...`)만 명시. v2.3.0 SHA는 ai-redteam-engineer가 별도 채택했으나 SHA 검증 미수행 가능성.
- **영향**: SHA 검증 미수행 시 공급망 위험. infra-engineer 표와 정합 안 됨.
- **수정**: `gh api repos/Azure/login/git/refs/tags/v2.3.0` 또는 `v2.2.0`으로 통일. 02 §8 표 정합 권고.
- **담당**: infra-engineer (실측 후 두 워크플로 정합)

#### F-013 🔴 `pyproject.toml.patch`의 mypy `python_version` 결정 보류 + 적용 충돌
- **위치**: `pyproject.toml.patch:99` (3.12→3.11 변경 제안)
- **현상**:
  - 04b §1.4 "python_version 통일 결정 필요", §9.1 🔴 필수 명시.
  - 그러나 현재 `pyproject.toml`은 numpy 등 전이 스텁이 3.12 type 문법 요구하는 주석을 달고 3.12 사용 중. 패치를 그대로 적용하면 mypy 실행 시 numpy 스텁 파싱 충돌 가능.
- **영향**: 패치 적용 후 mypy 잡 첫 실행에서 transitive type stub 충돌. typecheck 잡 차단.
- **수정**: 결정 트리 명시.
  - (A) mypy 3.11로 통일하되 `[[tool.mypy.overrides]] module = ["numpy.*"]` `ignore_missing_imports = true` 강제 → numpy 스텁 회피.
  - (B) black/ruff target을 `py312`로 통일하되 `requires-python>=3.12` 변경(런타임 영향 검토 필요).
  - **권고: (A)** — runtime 호환 영향 최소.
- **담당**: 사용자 결정 + quality-gate 패치 보강

---

### 🟡 권장 수정 (1-2주 내) — 12건

#### F-014 🟡 SLSA generator reusable workflow tag 핀(예외 허용 명시 부족)
- **위치**: `cd-prod.yml:246` — `uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0`
- **현상**: `04_security_scan.md §6.2 항목 3`이 SLSA generator를 예외로 허용(SLSA generator 자체가 hardened). 정책상 OK이나 워크플로 코멘트에 예외 사유 명시 부재.
- **수정**: 해당 라인 상단에 주석 추가:
  ```yaml
  # SLSA reusable workflow — tag 핀 예외 허용 (PS.2.1 정책 §6.2 #3).
  ```
- **담당**: infra-engineer

#### F-015 🟡 Trivy 이중 호출(스캔 + 차단 게이트) 비효율
- **위치**: `ci-enhanced.yml:349-370`, `cd-staging.yml:148-168`, `cd-prod.yml:202-221`
- **현상**: 각 워크플로가 Trivy를 2회 실행: 1차 SARIF용(`exit-code: 0`), 2차 차단용(`severity: CRITICAL exit-code: 1`). 빌드시간 약 1-2분 중복.
- **수정**: 1회 호출 + jq로 SARIF 파싱 후 차단. 또는 1차 호출의 `exit-code: 1` + `vuln-type` 분리:
  ```yaml
  - uses: aquasecurity/trivy-action@<SHA>
    with:
      image-ref: ${{ ... }}
      format: sarif
      output: trivy.sarif
      severity: CRITICAL,HIGH
      exit-code: 0
  - run: jq '.runs[].results | length > 0' trivy.sarif | grep -q true && exit 1 || exit 0  # critical만 차단
  ```
- **담당**: security-scanner

#### F-016 🟡 ci-quality-patch.yml과 ci-enhanced.yml의 `lint` 잡 중복 실행
- **위치**: `ci-quality-patch.yml:38-63` vs `ci-enhanced.yml:66-84`
- **현상**: 두 워크플로 모두 push to main/develop + PR 트리거. `lint`/`typecheck` 잡이 양쪽에서 실행 → 같은 PR에 2회 black/ruff/mypy 실행.
- **수정**: 둘 중 하나로 통합. 권고: ci-enhanced의 lint 잡을 제거하고 ci-quality-patch가 5개 잡(lint/typecheck/complexity/docstring/convention)을 모두 담당. ci-enhanced는 test/secret/codeql/build/scan만.
- **담당**: pipeline-designer + quality-gate 협업

#### F-017 🟡 `ai-redteam.yml`이 `actions/download-artifact`로 이전 PR 산출물 못 받음
- **위치**: `ai-redteam.yml:160`, `474-479`
- **현상**: `actions/download-artifact@v4`는 **같은 워크플로 run 내**의 artifact만 다운로드 가능. 이전 run(특히 다른 워크플로 run)의 artifact는 `dawidd6/action-download-artifact` 같은 액션이나 `gh api` 호출이 필요.
  - 첫 실행 시 `ai-redteam-passing-ttps` artifact가 없음 → `continue-on-error: true`로 회피하나 매번 회귀 게이트가 무의미해짐.
- **영향**: 회귀 차단 메커니즘이 무력화. 04d §6 회귀 감지 게이트 약화.
- **수정**: `dawidd6/action-download-artifact@<SHA>` 채택, `workflow: ai-redteam.yml`, `branch: main`, `name: ai-redteam-passing-ttps` 명시. 또는 GitHub Releases artifact로 보존.
- **담당**: ai-redteam-engineer

#### F-018 🟡 `cd-prod.yml` rollouts-monitor 잡의 OIDC 의존 + skip 조건 위험
- **위치**: `cd-prod.yml:343-395`
- **현상**: `if: vars.ARGOCD_SERVER != ''`로 ArgoCD 변수 미설정 시 잡 자체가 skip → 카나리 모니터링·자동 롤백 step 모두 미실행. AKS 자격이 없으면 더 안쪽 step도 skip.
- **영향**: 환경 미준비 상태에서도 cd-prod가 "성공"으로 끝남 → 잘못된 안전감.
- **수정**: 잡을 skip이 아닌 **명시적 실패**로 전환하거나, `gitops-bump`까지만 수행하고 `rollouts-monitor`는 별도 PR로 분리(환경 준비 후 활성).
  ```yaml
  if: vars.ARGOCD_SERVER == ''
    run: |
      echo "::error::ArgoCD 환경 미준비 — prod 배포 차단"
      exit 1
  ```
- **담당**: infra-engineer

#### F-019 🟡 OSCAL CronJob의 `oscal-build` emptyDir 마운트가 read-only 컨테이너와 충돌
- **위치**: `oscal-export-cronjob.yaml:88, 95`
- **현상**: `readOnlyRootFilesystem: true` + `cd /app && python compliance/oscal/build_oscal.py compliance/oscal` — `build_oscal.py`는 `/app/compliance/oscal/` 하위에 JSON 쓰기. `oscal-build` emptyDir이 `_build` 하위에만 마운트되어 있음.
- **영향**: `build_oscal.py write_json()` 호출 시 OSError(read-only filesystem).
- **수정**:
  ```yaml
  volumeMounts:
    - { name: tmp, mountPath: /tmp }
    - { name: oscal-out, mountPath: /app/compliance/oscal }   # 전체 디렉터리 마운트
  volumes:
    - { name: tmp, emptyDir: {} }
    - { name: oscal-out, emptyDir: {} }
  ```
  단, 마운트 시 이미지 내 기존 `compliance/oscal/` 컨텐츠가 hidden됨 → `initContainer`로 사전 복사 패턴 필요.
- **담당**: monitoring-specialist + infra-engineer

#### F-020 🟡 ServiceMonitor metricRelabelings keep 화이트리스트에서 `mttt_seconds_bucket` 누락
- **위치**: `servicemonitor.yaml:55` (soc-hotpath)
- **현상**: `mttt_seconds` 만 매치(`mttt_seconds`). Histogram 메트릭은 실제 `mttt_seconds_bucket`, `mttt_seconds_count`, `mttt_seconds_sum`로 시리즈 분리. regex가 `mttt_seconds`만 keep → `_bucket/_count/_sum` drop.
- **영향**: `prometheusrule.yaml:301` `histogram_quantile(... mttt_seconds_bucket ...)` 알림 영구 no-data. AnalysisTemplate `agent_latency_seconds_bucket`은 OK(이미 `_bucket` 명시).
- **수정**:
  ```regex
  ...mttt_seconds(_bucket|_count|_sum)?...
  ```
- **담당**: monitoring-specialist

#### F-021 🟡 ci-enhanced `pip-audit`의 진짜 차단 임계 불명확
- **위치**: `ci-enhanced.yml:264-270` — `pip-audit --strict --progress-spinner=off`
- **현상**: 코멘트("High↑ 차단은 후속 PR로 강화")가 명시. `--strict`만으로는 severity 필터링 부재 — 모든 vuln 발견 시 차단. `04_security_scan §1.1 #8`은 "High 이상 차단" 임계. 현재 구현은 임계 부재로 너무 광범위 차단 또는 너무 느슨.
- **수정**: 실제 정책 결정 후 `pip-audit --fix --requirement requirements.txt` 또는 `pip-audit ... -V High` 같은 명시적 필터. 현재 `pip-audit` CLI는 severity 필터 미지원 → JSON 출력 + jq 후처리.
- **담당**: security-scanner

#### F-022 🟡 ci-enhanced 의 `oscal-schema` 잡 `continue-on-error`로 사실상 무력화
- **위치**: `ci-enhanced.yml:118` (`continue-on-error: true`)
- **현상**: 01 §5.1 표는 "PR=경고/main=차단"이지만 02 §9는 "CI에서는 모두 경고"로 변경됨. cd-prod의 `oscal-gate`가 차단을 담당하므로 의도된 분리이나, CI 단계에서 스키마 위반이 main까지 통과해 cd-prod에서 차단되면 피드백 사이클이 길어짐.
- **수정**: PR/develop=경고(continue-on-error: true), main 트리거 시 `continue-on-error: ${{ github.event_name != 'push' || github.ref != 'refs/heads/main' }}` 동적 분기. 또는 cd-prod의 oscal-gate를 신뢰하고 현 상태 유지(설계 조정 가능).
- **담당**: pipeline-designer + security-scanner

#### F-023 🟡 카나리 자동 롤백 SPOF — RAGAS 메트릭 미노출 시 무중단 진입
- **위치**: `analysistemplates/hotpath-success-rate-latency.yaml:94-103`
- **현상**: 03 §6 검증 표가 `ragas_faithfulness_score`을 "**앱 노출 필수**"로 명시. 미노출 시 `avg_over_time(...) returns no data` → `successCondition: result[0] >= 0.75`가 평가 안 되어 카나리는 통과로 진행.
- **영향**: 핵심 품질 게이트가 메트릭 미노출만으로 무력화 → 잘못된 안전감.
- **수정**:
  - 단기: `successCondition: result[0] >= 0.75 || result.length == 0` 같은 조건은 부적합 — Prometheus query result가 empty면 Argo Rollouts 평가가 Error/Inconclusive.
  - 권고: `AnalysisTemplate.metrics[].failureCondition` 또는 `inconclusiveLimit: 0`을 명시해 no-data를 실패로 처리. 또는 `vector(0)` fallback 쿼리.
    ```yaml
    successCondition: result[0] >= 0.75
    failureCondition: result[0] < 0.75
    inconclusiveLimit: 0
    failureLimit: 2
    ```
  - 03 §11 #2 application-engineer 별도 PR로 메트릭 노출 작업 동반 권장.
- **담당**: monitoring-specialist + application-engineer

#### F-024 🟡 cd-staging.yml의 `gitops-bump`가 `develop`에 직접 push — 워크플로 무한 트리거 가능
- **위치**: `cd-staging.yml:227-247` (`git push origin develop`)
- **현상**: `on: push: branches: [develop]` → bump 커밋이 다시 cd-staging을 트리거. `concurrency.cancel-in-progress: false`로 큐가 쌓일 수 있음. 커밋 메시지에 `[skip ci]` 등 가드 없음.
- **수정**:
  - 커밋 메시지에 `[skip ci]` 추가: `git commit -am "ci(staging): bump image to sha-${SHORT_SHA} [skip ci]"`
  - 또는 워크플로 트리거에 `if: !contains(github.event.head_commit.message, 'ci(staging): bump')` paths-ignore: `deploy/k8s/**` 부분만 ignore.
- **담당**: infra-engineer

#### F-025 🟡 `interrogate` 80% 임계가 현 코드베이스 실측 미수행
- **위치**: `pyproject.toml.patch:147` `fail-under = 80`
- **현상**: 04b §8.4 #3에서도 명시. 현 코드베이스 실제 독스트링 커버리지 미측정. 80%가 첫날 통과 가능한지 불확실. 미통과 시 모든 PR이 차단.
- **수정**: 머지 전 다음 측정:
  ```bash
  pip install interrogate && interrogate -c pyproject.toml .
  ```
  결과에 따라 60→70→80 단계 적용(04b §6.1 점진 로드맵 참조).
- **담당**: quality-gate (실측) + 사용자(임계 확정)

---

### 🔵 모니터링 (관찰만) — 9건

#### F-026 🔵 `concurrency.cancel-in-progress: true` 차이 — cd-staging/cd-prod는 false
- 의도된 차이(배포 안정성). 단, ai-redteam.yml은 true → 캠페인 중간 취소 시 결정론 회귀 검증 시퀀스가 깨질 수 있음. 운영 1-2주 관찰 후 재평가.

#### F-027 🔵 OSCAL CronJob의 `ghcr.io/.../uav-ai-soc:prod` 이동 태그 의존
- prod 태그가 cd-prod에서 갱신될 때 CronJob도 새 이미지로 자동 풀. 의도된 동작이나 prod 이미지가 회귀 시 CronJob도 영향. ImagePullPolicy `IfNotPresent`로 첫 풀 후 캐시. 운영 관찰.

#### F-028 🔵 `--warn-only`/`--fail-on-new` 동시 지정 시 우선순위
- `ai_redteam_to_poam.py:765-770`: `warn_only` 검사가 `fail_on_new`보다 먼저 — `--fail-on-new --warn-only` 동시 지정 시 warn이 우선. 워크플로에서는 분기 사용되지만 운영자 수동 호출 시 혼동 가능. 코드에 `--warn-only`와 `--fail-on-new` 상호배타 강제 권고.

#### F-029 🔵 트랙 A `replicas: 2` 변경의 상태 보유 영향
- 01 §10 #1, 02 §9 보류. 사용자 결정 필요. 옵션 A(StatefulSet 분리)·B(Blue-Green) 의사결정 트리는 명확하나 미해결 — 운영 정합 검증 권장.

#### F-030 🔵 Kyverno verifyImages 정책 미배포 — 클러스터 차단 미작동
- 04 §4.3 권장. ClusterPolicy 매니페스트 미작성. `supply_chain_unsigned_image_total` 메트릭 소스 부재(F-008과 동질) → `UnsignedImageDeployAttempt` 알림 영구 no-data. 정책 배포 시 활성화 권고.

#### F-031 🔵 Argo Rollouts 컨트롤러 설치 부재
- 02 §11 #4. `kubectl argo rollouts status` 명령이 cd-prod rollouts-monitor에서 사용되나 컨트롤러 미설치 시 무용. `deploy/argocd/apps/argo-rollouts.yaml` 별도 PR 필요(02 §6.2 언급만).

#### F-032 🔵 Pushgateway 설치 부재
- 03 §11 #3, §12 #2. ServiceMonitor `soc-pushgateway`가 존재하나 Helm chart/Application 미작성. 별도 PR 필요.

#### F-033 🔵 GitHub Actions SHA 검증 미수행
- 02 §8 표 SHA가 "본 문서 작성 시점 추정(검증 필요)" 명시. 다음 명령으로 일괄 검증 권고:
  ```bash
  gh api repos/actions/checkout/git/refs/tags/v4.2.2 --jq .object.sha
  ```
  실제 값과 일치하지 않을 경우 patch PR.

#### F-034 🔵 OSCAL high≤3 임계 1-2주 운영 후 재평가
- 04 §10 #2. 현재 실측 high=1(GOVERN 1.6 planned). 신규 컴포넌트 추가 시 partial→planned 후퇴 가능성.

---

## 3. 인터페이스 정합성 매트릭스

| # | 인터페이스 | 생산자 | 소비자 | 정합 | 비고 |
|---|---|---|---|---|---|
| 1 | `g2_summary.json` 스키마 | `check_gates.py --summary-json` | (없음 — Pushgateway push 미구현) | ❌ | F-008 |
| 2 | `failed_gates_poam.json` POAM 스키마 | `check_gates.py --emit-poam` | `check_poam_thresholds.py` | ✅ | severity/UUID 일치 검증 완료 |
| 3 | `ai_redteam_poam.json` POAM 스키마 | `ai_redteam_to_poam.py --out` | `check_poam_thresholds.py` + `build_oscal.py --append-poam` | ⚠️ | build_oscal append 미구현(F-003) |
| 4 | `previous_pass.json` 스키마 | `ai-redteam.yml`(atlas-deterministic) | `ai_redteam_to_poam.py --previous-pass` | ⚠️ | artifact 다운로드 메커니즘 부적합(F-017) |
| 5 | POAM Item severity 정규화 | 3가지 생산자(check_gates·ai_redteam_to_poam·기존 build_oscal) | `check_poam_thresholds.py SEVERITY_ALIASES` + `oscal_to_metrics.py SEVERITY_ALIASES` | ✅ | 한/영 매핑 dict 일치 |
| 6 | POAM closed 키워드 | 모든 생산자 | `check_poam_thresholds._is_closed` + `oscal_to_metrics._is_closed` | ✅ | `("closed","completed","종결","완료","해결")` 일치 |
| 7 | `failed_ttps.json` 스키마 (04 §3.7) | `ai-redteam.yml` | `build_oscal.py --append-poam` | ❌ | 04 §3.7 설계 ↔ 04d §11.2 합의 스키마 상이(필드명 다름). 단일 출처 미정(04d §13 #1) |
| 8 | OSCAL 메트릭 이름 | `oscal_to_metrics.py render_textfile/push_to_gateway` | `prometheusrule.yaml`(oscal-compliance 그룹) + `grafana-dashboard-oscal.yaml` | ✅ | `oscal_controls_total`/`oscal_poam_open_total`/`oscal_compliance_ratio`/`oscal_last_build_timestamp` 4종 일치 |
| 9 | AnalysisTemplate ↔ ServiceMonitor 메트릭 이름 | `hotpath-success-rate-latency.yaml`(쿼리) | `servicemonitor.yaml soc-hotpath`(scrape) | ⚠️ | `mttt_seconds_bucket` 누락(F-020), `ragas_faithfulness_score` 앱 노출 의존(F-023) |
| 10 | `image_ref`/`image_tag` 인터페이스 | `cd-staging build-push.outputs` + `cd-prod build-push.outputs` | `release-signing.yml inputs` | ✅ | digest 기반 ref 사용, 표준화됨 |
| 11 | AKS 자격 환경변수 인터페이스 | infra-engineer §3.2 (`AZURE_*` variables) | `cd-prod rollouts-monitor` + `ai-redteam pyrit-campaign` | ⚠️ | ai-redteam은 `secrets.AZURE_REDTEAM_CLIENT_ID`로 분리(redteam-staging env) — 의도된 분리이나 02 §4.1 표에 미수록 |
| 12 | DORA 메트릭 인터페이스 | (없음 — exporter 미구현) | `grafana-dashboard-dora.yaml` + `prometheusrule.yaml` ci-cd-pipeline 그룹 | ❌ | F-007 |
| 13 | G2/AI Red Team Pushgateway | (없음 — push 미구현) | `prometheusrule.yaml` g2-regression/ai-redteam 그룹 | ❌ | F-008 |
| 14 | SHA 핀 표 (02 §8) ↔ 실제 워크플로 | infra-engineer §8 | 모든 워크플로 `uses:` | ⚠️ | ci-quality-patch 미핀(F-011), azure/login SHA 상이(F-012) |
| 15 | quality-gate 강화 룰 ↔ check_gates.py 코드 통과 | 04b ruff D/T20/ANN/PT 등 | `_workspace/.../check_gates.py` (842줄) | ✅ | Google docstring·타입힌트·구체 예외·TypeGuard·`Any` 0건 — 100% 준수 검증 |
| 16 | OSCAL Profile mapped controls ↔ POAM `ai-rmf-controls` props | `build_oscal.py:362 build_profile()` | `ai_redteam_to_poam.ATLAS_TO_AI_RMF` | ✅ | MEASURE 2.7/2.6, GOVERN 4.3 등 매핑 일치 |

**요약**: ✅ 9 / ⚠️ 4 / ❌ 4

---

## 4. 운영 준비성 체크리스트

| 항목 | 상태 | 비고 |
|---|---|---|
| 모든 워크플로 timeout 명시 | ✅ | 잡 단위 `timeout-minutes:` 모두 설정 |
| 모든 워크플로 `permissions:` 최소 | ✅ | top-level read, job-level write — 정합 |
| 자동 롤백 메커니즘 | ⚠️ | `cd-prod rollouts-monitor` 의 git revert 로직 OK이나 환경 미준비 시 skip(F-018) |
| 시크릿 OIDC keyless | ✅ | cosign keyless + GHCR GITHUB_TOKEN, PAT 제거 |
| SBOM·서명·SLSA | ✅ | release-signing.yml 재사용 + SLSA L3 generator 호출 |
| 알림·승인 게이트 위치 | ✅ | `prod-approval` environment=production, 24h 대기 허용 |
| 의존 리소스 사전 준비 명시 | ⚠️ | Pushgateway·Argo Rollouts·Kyverno 설치 PR 미존재(F-031, F-032) |
| 시크릿 사전 등록 | ⚠️ | AAD App + Federated Credential 사용자 작업 필요(02 §3.2) — 가이드는 명시되어 있으나 완료 시점 모니터링 필요 |
| 메트릭 instrumentation | ❌ | application engineer 별도 PR 필요(03 §9, F-023) — 본 작업 범위 외 |
| 첫 배포 dry-run 절차 | ⚠️ | 02 §11 마이그레이션 절차 10단계 명시이나 dry-run 단계 부재 |
| 감사 추적성 | ✅ | gitops-bump 커밋, cosign Rekor, SBOM 90일+, signature 365일 보존 |
| 비용 상한 (CI runner 시간) | ✅ | concurrency cancel + timeout-minutes 캡 |
| 도메인 G2 게이트 ↔ 실 benchmarks/results | ⚠️ | `--profile` 미구현(F-002) — 호환 확인 후 가능 |

---

## 5. 방산 컴플라이언스 매트릭스

### NIST SSDF (SP 800-218)

| Practice | 게이트 | 상태 | 갭/비고 |
|---|---|---|---|
| PS.1.1 시크릿 보호 | Gitleaks + GITHUB_TOKEN + OIDC | ✅ | PAT 제거 완료, .gitleaks.toml 초기 생성 필요 |
| PS.2.1 의존성 핀 | 모든 액션 SHA 핀 | ⚠️ | F-011(ci-quality-patch), F-012(azure/login SHA 상이), F-014(SLSA generator 예외 코멘트 필요) |
| PS.2.2 빌드 무결성 | cosign + SLSA L3 | ✅ | release-signing.yml + slsa-github-generator |
| PS.3.1/3.2 SBOM/Attest | Syft + cosign attest | ✅ | SPDX-JSON, 90일+Rekor |
| PW.1.1 시크릿 차단 | secret-scan 잡 | ✅ | ci-enhanced |
| PW.4.1/4.4 SCA | dependency-review + pip-audit | ⚠️ | F-021 (pip-audit 임계 불명확) |
| PW.5.1 IaC 보안 | Trivy config (설계) | ❌ | 워크플로에 IaC 잡 미구현 (`ci-enhanced.yml`은 컨테이너 스캔만) |
| PW.7.1/7.2 SAST | CodeQL + Semgrep | ⚠️ | F-010 (semgrep digest placeholder) |
| PW.9.1 안전한 기본값 | Dockerfile non-root, seccomp | ✅ | runtime stage non-root, capabilities drop |
| PO.5.1 컴플라이언스 | OSCAL 스키마 + POAM 임계 | ⚠️ | F-001 (옵션 불일치), F-003 (append-poam 미구현) |
| RV.1.1 nightly 재스캔 | (미구현) | ❌ | Trivy nightly 재스캔 워크플로 부재(01 §1.2 명시 vs 워크플로 미작성) |

### NIST SP 800-204D (C-SCRM)

| Family | 게이트 | 상태 | 비고 |
|---|---|---|---|
| SR-3 의존성 위험 | dependency-review + pip-audit + Trivy fs | ⚠️ | Trivy fs 잡 미작성 (`ci-enhanced.yml`은 image만) |
| SR-4 빌드 무결성·SBOM | Syft + cosign + SLSA | ✅ | |
| MA-3 빌드 인증 | OIDC + Fulcio + Rekor | ✅ | |
| PO-1 거버넌스 | CODEOWNERS, environment=production | ⚠️ | CODEOWNERS 매니페스트 미생성(04 §6.2 #30 항목) |

### NIST AI RMF (OSCAL 1.1.2)

| 통제 | 매핑 게이트 | 상태 | 비고 |
|---|---|---|---|
| GOVERN 1.4, 1.6 | OSCAL POAM 임계 + GOVERN 1.6 partial 승격 | ⚠️ | GOVERN 1.6 planned 1건(04 §3.4 실측) — 90일 내 해소 권고 |
| GOVERN 6.1 | 공급망 무결성 풀스택 | ✅ | |
| MAP 4.1/4.2 | Trivy + IaC + AI 레드팀 | ⚠️ | IaC 게이트 미구현(F-PW.5.1) |
| MEASURE 2.3, 2.7 | KPI + ATLAS + RAGAS | ⚠️ | RAGAS 메트릭 앱 노출 필요(F-023) |
| MEASURE 2.6, 2.9 | AI 레드팀 캠페인 | ✅ | atlas-deterministic + 결정론 검증 |
| MANAGE 1.3, 3.1 | POAM·SBOM·SCA | ⚠️ | append-poam 미구현(F-003) |
| MANAGE 2.4 | Deployment & GitOps | ⚠️ | F-006 (ArgoCD 동기화 충돌) |
| MANAGE 4.1 | Observability | ⚠️ | F-007/F-008/F-023 |

---

## 6. 누락·보류 사항 종합 표

| 항목 | 분류 | 결정 주체 | 영향도 | 권고 |
|---|---|---|---|---|
| `build_oscal.py --append-poam` 옵션 구현 | 의존 PR | governance + ai-redteam-engineer | 🔴 | 별도 PR 필수 (F-003) |
| `check_poam_thresholds.py` 정식 배치 경로 | 결정 보류 | 사용자/security-scanner | 🔴 | `compliance/oscal/` 권고 (F-005) |
| 트랙 A 상태 분리 (옵션 A vs B) | 결정 보류 | infra-engineer + 사용자 | 🔴 | 머지 전 단일 선택 강제 (F-006) |
| Dockerfile + Semgrep 베이스 digest 실측 | 의존 작업 | infra-engineer + security-scanner | 🔴 | 실측 후 fix-up (F-009, F-010) |
| GitHub Actions SHA 표 검증 | 의존 작업 | infra-engineer | 🟡 | `gh api` 일괄 (F-033) |
| Application metrics instrumentation | 별도 PR | application-engineer | 🟡 | 03 §9 — `core/observability/metrics.py` |
| Argo Rollouts 컨트롤러 설치 | 별도 PR | infra-engineer | 🟡 | F-031 |
| Pushgateway 설치 | 별도 PR | infra-engineer | 🟡 | F-032 |
| Kyverno verifyImages 정책 | 별도 PR | infra-engineer | 🟡 | 04 §4.3 |
| AKS 클러스터 + AAD App + Federated Credentials | 사용자 작업 | 사용자 | 🔴 | 02 §3.2 명시 — 사전 완료 |
| `dah-soc-staging` namespace + ArgoCD App | 사용자 승인 | 사용자 | 🟡 | 01 §10 #2 |
| OSCAL high≤3 임계 운영 가능성 | 운영 관찰 | governance | 🔵 | 1-2주 후 재평가 (F-034) |
| `python_version` 3.11 vs 3.12 통일 | 결정 보류 | 사용자/quality-gate | 🔴 | 옵션 A 권고 (F-013) |
| `interrogate` 80% 기준선 | 의존 작업 | quality-gate | 🟡 | 머지 전 실측 (F-025) |
| `--profile` 인자 구현 또는 워크플로 정정 | 코드 보강 | test-engineer | 🔴 | 옵션 A 권고 (F-002) |
| DORA 메트릭 exporter | 의존 PR | monitoring-specialist + infra-engineer | 🔴 | F-007 |
| G2/AI Red Team Pushgateway push | 워크플로 보강 | test-engineer + ai-redteam-engineer | 🔴 | F-008 |
| RAGAS 인플라이트 평가 모듈 | 별도 PR | application-engineer | 🟡 | 03 §9 #5 |
| CODEOWNERS / branch protection | repo 설정 | infra-engineer + 사용자 | 🟡 | 04 §6.2 #30, #31 |
| Trivy nightly 재스캔 워크플로 | 누락 작업 | security-scanner | 🟡 | 01 §1.2 명시 vs 미구현 |
| IaC 스캔 잡 (Trivy config / Checkov) | 누락 작업 | security-scanner | 🟡 | 04 §1.1 #12·#13 설계 vs ci-enhanced 미구현 |
| ci-enhanced ↔ ci-quality-patch 통합 | 토폴로지 결정 | pipeline-designer | 🟡 | F-016 |

---

## 7. 다음 단계 권고 (사용자 승인 필요 항목)

### 7.1 머지 전 반드시 결정해야 할 사용자 의사결정 (5건)

1. **트랙 A 옵션 선택 (A=Rollout / B=Blue-Green)** — F-006 차단성. 결정 즉시 미선택 매니페스트 git rm.
2. **`check_poam_thresholds.py` 정식 경로 (compliance/oscal/ vs scripts/)** — F-005. 모든 워크플로에 정합 적용.
3. **`python_version` 통일 (mypy 3.11 + numpy override vs 전체 3.12)** — F-013. 패치 적용 가부 결정.
4. **OSCAL POAM `high≤3` 임계 채택** — F-034. 현 실측 high=1, 보수성 vs 운영 가능성.
5. **DORA 메트릭 exporter 채택 (Pushgateway push vs cdevents 외부 도구)** — F-007.

### 7.2 머지 전 반드시 완료해야 할 코드/스크립트 보강 (8건)

1. F-001: `cd-staging/cd-prod`의 `check_poam_thresholds.py` 호출 인자 정정.
2. F-002: `check_gates.py`에 `--profile {staging|prod}` 추가 **또는** 워크플로에서 명시 플래그 사용.
3. F-004: `ai-redteam.yml`의 4개 `_workspace/02_pipeline_config/scripts/...` 참조를 정식 경로로 변경.
4. F-009: Dockerfile baseimage digest 실측 + 적용.
5. F-010: Semgrep 컨테이너 digest 실측 + 적용.
6. F-011: `ci-quality-patch.yml` 9개 액션 SHA 핀.
7. F-012: `azure/login` SHA 통일.
8. F-020: ServiceMonitor `mttt_seconds_bucket` keep regex 보강.

### 7.3 머지 후 1-2주 내 별도 PR 권장 (8건)

1. F-003: `build_oscal.py --append-poam` 옵션 구현 + `compliance/oscal/poam_schema.py` 단일 출처 모듈.
2. F-007: DORA 메트릭 Pushgateway exporter step.
3. F-008: G2/AI Red Team Pushgateway push step.
4. F-019: OSCAL CronJob initContainer 패턴.
5. F-023: RAGAS 인플라이트 평가 모듈 + AnalysisTemplate `failureCondition` 보강.
6. Argo Rollouts + Pushgateway + Kyverno 설치 PR (F-031, F-032, F-030).
7. IaC 스캔 잡 + Trivy nightly 재스캔 워크플로.
8. CODEOWNERS + branch protection 적용.

---

## 8. 산출물 통합 적용 권장 순서

다음 순서로 사용자가 `_workspace/02_pipeline_config/` → 실제 경로로 반영하기를 권고한다.

### Phase A: 정합성·차단성 수정 (머지 PR-A)
1. `_workspace/02_pipeline_config/scripts/check_poam_thresholds.py` → `compliance/oscal/check_poam_thresholds.py`
2. `_workspace/02_pipeline_config/scripts/oscal_to_metrics.py` → `scripts/oscal_to_metrics.py` (또는 `compliance/oscal/oscal_to_metrics.py`)
3. `_workspace/02_pipeline_config/scripts/ai_redteam_to_poam.py` → `scripts/ai_redteam_to_poam.py`
4. `_workspace/02_pipeline_config/benchmarks/check_gates.py` → `benchmarks/check_gates.py`
5. 위 4개 스크립트의 단위 테스트 추가 (`tests/__tests__/test_check_*.py` 등)

### Phase B: 워크플로 적용 (PR-B, PR-A 후 의존)
1. `_workspace/02_pipeline_config/.github/workflows/release-signing.yml` → `.github/workflows/release-signing.yml` (재사용 워크플로 우선)
2. F-001~F-005, F-009~F-012, F-020 정정 후 다음 4개 동시 머지:
   - `ci-enhanced.yml` (`ci.yml` 대체)
   - `ci-quality-patch.yml` (또는 ci-enhanced로 통합 — F-016)
   - `cd-staging.yml`
   - `cd-prod.yml`
3. `ai-redteam.yml` 적용 (F-004, F-017 수정 후)

### Phase C: 인프라 매니페스트 (PR-C, 사용자 결정 F-006 후)
1. `deploy/Dockerfile` 강화 (F-009 적용 후)
2. **트랙 A 옵션 결정에 따라**:
   - 옵션 A: `deploy/k8s/argo-rollout-hotpath.yaml` 적용, `30-deployment-a-hotpath.yaml` git rm
   - 옵션 B: 반대
3. `deploy/k8s/analysistemplates/hotpath-success-rate-latency.yaml` (옵션 A 시)
4. `deploy/argocd/apps/soc-staging.yaml` 신규 (사용자 승인 후)

### Phase D: 모니터링 (PR-D, 의존 리소스 설치 후)
1. Argo Rollouts 컨트롤러 + Pushgateway Helm Application (별도 인프라 PR 선행)
2. `deploy/monitoring/servicemonitor.yaml` 적용 (F-020 수정 후)
3. `deploy/monitoring/prometheusrule.yaml` 적용 (F-007/F-008 보강 후, 또는 알림 규칙 부분 활성)
4. `deploy/monitoring/grafana-dashboard-*.yaml` 4종
5. `deploy/monitoring/oscal-export-cronjob.yaml` (F-019 수정 후)

### Phase E: pyproject/pre-commit 패치 (PR-E)
1. 사용자 결정 F-013(python_version) 후 `pyproject.toml.patch` 적용
2. `interrogate` 80% 실측(F-025) 후 임계 확정 → 적용
3. `.pre-commit-config.yaml.patch` 적용
4. `pre-commit install --install-hooks` 사용자 실행

---

## 9. 마지막 요약 보고

- **🔴 필수 수정**: 13건
- **🟡 권장 수정**: 12건
- **🔵 모니터링**: 9건

### 인터페이스 정합성 매트릭스 요약
- ✅ **정합**: 9건 (POAM 스키마, severity 정규화, closed 키워드, 이미지 ref, OSCAL 메트릭, quality-gate 컨벤션 등)
- ⚠️ **부분 정합**: 4건 (`failed_ttps.json` 스키마 두 출처, SHA 핀 표, AKS 자격 분리, AnalysisTemplate 메트릭 노출)
- ❌ **불일치**: 4건 (g2 Pushgateway 소스 부재, DORA exporter 부재, build_oscal append-poam 미구현, ai_redteam_poam append 흐름 단절)

### 다음 단계 권고 (핵심 3가지)
1. **🔴 F-001/F-002/F-003 (게이트 차단성) 즉시 수정** — 현재 워크플로는 첫 실행에서 모두 실패한다. `check_poam_thresholds.py`/`check_gates.py` CLI 옵션을 일치시키거나 워크플로를 정정. `build_oscal.py --append-poam` 별도 PR 머지 또는 ai-redteam 흐름에서 임시 제거.
2. **🔴 F-006 (ArgoCD 동기화 충돌) — 트랙 A 옵션 사용자 결정 강제** — 머지 전 옵션 A/B 중 단일 선택. 미해결 시 첫 sync에서 클러스터 상태 비결정.
3. **🔴 F-007/F-008 (메트릭 소스 부재)** — DORA·G2·AI Red Team Pushgateway push step을 워크플로 종료부에 추가하지 않으면 PrometheusRule 알림이 영구 no-data로 무력화된다. application-engineer 별도 PR도 동반 필요.

운영 준비: 🔴 **재작업** — 위 핵심 3가지 차단성 결함 해결 + Phase A/B 머지까지 진행 후 재리뷰 권장. 방산 컴플라이언스 등급: 🟡 **수정 후 가능** (SSDF/800-204D 풀스택 설계는 정합하나 구현 갭으로 첫 통과 불가).

---

**리뷰 종료**.
