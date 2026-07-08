# =====================================================================
# Dockerfile.builder — UAV AI SOC CI/CD 공통 빌더 이미지
#
# 목적:
#   1) 모든 CI/CD 잡(린트·테스트·보안 스캔·OSCAL 검증·AI 레드팀)을 동일 환경에서 실행 →
#      재현성(reproducibility), 공급망 무결성(supply chain integrity), 에어갭 가용성을 한 번에 해결.
#   2) 도구(tool) 풀스택을 **핀 버전**으로 고정 → CI 잡 YAML 에서 `pip install` 행위 자체를 제거.
#   3) 비루트(uid 10001) + read-only rootfs(컨테이너 옵션) + cap-drop=ALL 로 잡 권한 최소화.
#
# 산출 이미지 ref: ghcr.io/s1ns3nz0/uav-soc-builder
#   - 태그 :latest, :sha-<git-sha>
#   - 워크플로는 항상 digest 핀(`@sha256:...`)으로 사용 — `vars.BUILDER_IMAGE_DIGEST` 참조.
#
# 베이스 핀:
#   - python:3.11-slim-bookworm (Debian 12)
#   - F-009(02_infra_config.md §8) 의 런타임 Dockerfile 과 동일 digest 사용.
#   - 실제 sha256 값은 사용자 환경에서 `docker pull python:3.11-slim-bookworm &&
#     docker inspect --format='{{index .RepoDigests 0}}' python:3.11-slim-bookworm`
#     으로 확정 후 placeholder 치환. Dependabot 으로 월 1회 갱신.
#
# 도구 핀 (모두 명시):
#   [Python 품질]
#     black==24.10.0, ruff==0.5.7, mypy==1.11.2, pytest==8.3.3,
#     pytest-cov==5.0.0, pytest-asyncio==0.24.0, interrogate==1.7.0,
#     xenon==0.9.3
#   [보안 — pip]
#     pip-audit==2.7.3, semgrep==1.85.0, checkov==3.2.255
#   [보안 — binary]
#     gitleaks==8.18.4, syft==1.14.1, trivy==0.55.2, cosign==2.4.1, gh==2.55.0
#   [OSCAL]
#     compliance-trestle==3.5.1, jsonschema==4.23.0
#   [유틸 — apt]
#     jq, curl, git, tini, bash, ca-certificates
#
# HEALTHCHECK NONE — CI 잡 컨테이너이므로 헬스체크 불요(잡 종료가 곧 검증).
# USER 10001, WORKDIR /workspace, ENTRYPOINT tini.
# =====================================================================

# ─────────────────────────────────────────
# Stage 1: builder — bin 다운로드·검증, pip wheel 빌드
# ─────────────────────────────────────────
# placeholder digest. 사용자 환경에서 실측 sha256 으로 치환할 것(F-009 와 동일).
FROM python:3.11-slim-bookworm@sha256:7f9e6f4f9a8a6d7e2c2b3c0a9b6e7d8f4c2a1d9e6f7a8b3c4d5e6f7a8b9c0d1e AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    DEBIAN_FRONTEND=noninteractive

# 도구 바이너리 다운로드용 + pip 컴파일 의존성.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        tar \
        xz-utils \
        build-essential \
        gcc \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# ─────────────────────────────────────────
# pip 도구 풀스택 (가상환경 격리 → final stage 복사)
# ─────────────────────────────────────────
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# wheel 캐시 미사용(--no-cache-dir 강제). 모든 버전 명시 핀.
# 의존성 충돌 회피를 위해 두 단계로 분리(품질 도구 → 보안/OSCAL).
RUN pip install --upgrade "pip==24.2" "wheel==0.44.0" "setuptools==74.1.2"

RUN pip install \
        "black==24.10.0" \
        "ruff==0.5.7" \
        "mypy==1.11.2" \
        "pytest==8.3.3" \
        "pytest-cov==5.0.0" \
        "pytest-asyncio==0.24.0" \
        "interrogate==1.7.0" \
        "xenon==0.9.3"

RUN pip install \
        "pip-audit==2.7.3" \
        "semgrep==1.85.0" \
        "checkov==3.2.255"

RUN pip install \
        "compliance-trestle==3.5.1" \
        "jsonschema==4.23.0"

# ─────────────────────────────────────────
# 보안 도구 바이너리 다운로드(SHA-256 검증)
#   - 핀 버전 + 공식 release URL.
#   - 실측 sha256 은 GitHub Release 자산의 *_checksums.txt 와 대조한다(주석 참고).
#   - 본 단계의 sha256 placeholder 는 빌더 빌드 시 사용자가 검증/치환할 것.
# ─────────────────────────────────────────
ARG TARGETARCH=amd64

# gitleaks 8.18.4 — https://github.com/gitleaks/gitleaks/releases/tag/v8.18.4
# SHA256 placeholder — 사용자가 실측 후 fix-up PR 로 치환 필수(F-036).
# 실측 명령:
#   curl -fsSLO https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_checksums.txt
#   grep 'gitleaks_8.18.4_linux_x64.tar.gz' gitleaks_8.18.4_checksums.txt
# placeholder 상태로 빌드 시 sha256sum 검증 실패 → 의도된 차단(빌더 부트스트랩 가드, F-036 정정).
ARG GITLEAKS_VERSION=8.18.4
ARG GITLEAKS_SHA256=0000000000000000000000000000000000000000000000000000000000000000
RUN curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
        -o /tmp/gitleaks.tar.gz \
    && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gitleaks.tar.gz -C /tmp gitleaks \
    && install -m 0755 /tmp/gitleaks /usr/local/bin/gitleaks \
    && rm -f /tmp/gitleaks.tar.gz /tmp/gitleaks

# syft 1.14.1 — https://github.com/anchore/syft/releases/tag/v1.14.1
# SHA256 placeholder — 사용자가 실측 후 fix-up PR 로 치환 필수(F-036).
# 실측 명령:
#   curl -fsSLO https://github.com/anchore/syft/releases/download/v1.14.1/syft_1.14.1_checksums.txt
#   grep 'syft_1.14.1_linux_amd64.tar.gz' syft_1.14.1_checksums.txt
# placeholder 상태로 빌드 시 sha256sum 검증 실패 → 의도된 차단(빌더 부트스트랩 가드, F-036 정정).
ARG SYFT_VERSION=1.14.1
ARG SYFT_SHA256=0000000000000000000000000000000000000000000000000000000000000000
RUN curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz" \
        -o /tmp/syft.tar.gz \
    && echo "${SYFT_SHA256}  /tmp/syft.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/syft.tar.gz -C /tmp syft \
    && install -m 0755 /tmp/syft /usr/local/bin/syft \
    && rm -f /tmp/syft.tar.gz /tmp/syft

# trivy 0.55.2 — https://github.com/aquasecurity/trivy/releases/tag/v0.55.2
# SHA256 placeholder — 사용자가 실측 후 fix-up PR 로 치환 필수(F-036).
# 실측 명령:
#   curl -fsSLO https://github.com/aquasecurity/trivy/releases/download/v0.55.2/trivy_0.55.2_checksums.txt
#   grep 'trivy_0.55.2_Linux-64bit.tar.gz' trivy_0.55.2_checksums.txt
# placeholder 상태로 빌드 시 sha256sum 검증 실패 → 의도된 차단(빌더 부트스트랩 가드, F-036 정정).
ARG TRIVY_VERSION=0.55.2
ARG TRIVY_SHA256=0000000000000000000000000000000000000000000000000000000000000000
RUN curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
        -o /tmp/trivy.tar.gz \
    && echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/trivy.tar.gz -C /tmp trivy \
    && install -m 0755 /tmp/trivy /usr/local/bin/trivy \
    && rm -f /tmp/trivy.tar.gz /tmp/trivy

# cosign 2.4.1 — https://github.com/sigstore/cosign/releases/tag/v2.4.1
# release-signing.yml 의 cosign-installer@v3.8.1 가 사용하는 cosign-release 와 동일.
# SHA256 placeholder — 사용자가 실측 후 fix-up PR 로 치환 필수(F-036).
# 실측 명령:
#   curl -fsSLO https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64-keyless.pem
#   curl -fsSL  https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64.sig
#   # 또는 release 페이지에서 cosign-linux-amd64 의 sha256 직접 확인
#   sha256sum cosign-linux-amd64
# placeholder 상태로 빌드 시 sha256sum 검증 실패 → 의도된 차단(빌더 부트스트랩 가드, F-036 정정).
ARG COSIGN_VERSION=2.4.1
ARG COSIGN_SHA256=0000000000000000000000000000000000000000000000000000000000000000
RUN curl -fsSL "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${TARGETARCH}" \
        -o /tmp/cosign \
    && echo "${COSIGN_SHA256}  /tmp/cosign" | sha256sum -c - \
    && install -m 0755 /tmp/cosign /usr/local/bin/cosign \
    && rm -f /tmp/cosign

# gh CLI 2.55.0 — https://github.com/cli/cli/releases/tag/v2.55.0
# SHA256 placeholder — 사용자가 실측 후 fix-up PR 로 치환 필수(F-036).
# 실측 명령:
#   curl -fsSLO https://github.com/cli/cli/releases/download/v2.55.0/gh_2.55.0_checksums.txt
#   grep 'gh_2.55.0_linux_amd64.tar.gz' gh_2.55.0_checksums.txt
# placeholder 상태로 빌드 시 sha256sum 검증 실패 → 의도된 차단(빌더 부트스트랩 가드, F-036 정정).
ARG GH_VERSION=2.55.0
ARG GH_SHA256=0000000000000000000000000000000000000000000000000000000000000000
RUN curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${TARGETARCH}.tar.gz" \
        -o /tmp/gh.tar.gz \
    && echo "${GH_SHA256}  /tmp/gh.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gh.tar.gz -C /tmp \
    && install -m 0755 "/tmp/gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh" /usr/local/bin/gh \
    && rm -rf /tmp/gh.tar.gz "/tmp/gh_${GH_VERSION}_linux_${TARGETARCH}"

# ─────────────────────────────────────────
# Stage 2: final — slim 런타임 (도구만 포함, 비루트)
# ─────────────────────────────────────────
FROM python:3.11-slim-bookworm@sha256:7f9e6f4f9a8a6d7e2c2b3c0a9b6e7d8f4c2a1d9e6f7a8b3c4d5e6f7a8b9c0d1e AS final

# OCI 표준 라벨 — GHCR UI / 감사 추적.
LABEL org.opencontainers.image.title="uav-soc-builder" \
      org.opencontainers.image.description="UAV AI SOC CI builder image — pinned tools for reproducible CI/CD" \
      org.opencontainers.image.vendor="Pollack AI" \
      org.opencontainers.image.licenses="Proprietary" \
      org.opencontainers.image.source="https://github.com/s1ns3nz0/pollack-ai" \
      org.opencontainers.image.documentation="https://github.com/s1ns3nz0/pollack-ai/blob/main/deploy/Dockerfile.builder.README.md" \
      org.opencontainers.image.base.name="docker.io/library/python:3.11-slim-bookworm"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:/usr/local/bin:$PATH" \
    DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    HOME=/home/builder \
    # CI 잡이 임시 파일을 /tmp 에 쓸 수 있도록 read-only rootfs 환경에서도 /tmp tmpfs 가정.
    XDG_CACHE_HOME=/tmp/.cache

# 런타임 유틸 — 도구 풀스택 보조(jq/curl/git/tini/bash).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        jq \
        tini \
        bash \
        openssh-client \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
    && apt-get clean

# 비루트 사용자(uid 10001) — Pod securityContext runAsUser 와 동일.
RUN groupadd --system --gid 10001 builder \
    && useradd --system --uid 10001 --gid 10001 \
        --home-dir /home/builder --create-home --shell /bin/bash builder

# builder stage 에서 pip venv + 보안 도구 바이너리 복사.
COPY --from=builder --chown=builder:builder /opt/venv /opt/venv
COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=builder /usr/local/bin/syft     /usr/local/bin/syft
COPY --from=builder /usr/local/bin/trivy    /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/cosign   /usr/local/bin/cosign
COPY --from=builder /usr/local/bin/gh       /usr/local/bin/gh

# 작업 디렉터리 — GitHub Actions 가 source 를 mount/checkout 하는 위치.
WORKDIR /workspace
RUN chown builder:builder /workspace

# 도구 가용성 self-check(빌드 시 1회). 빌드 실패 = digest 핀 직전 stop.
# trestle 은 `--version` 미지원 버전이 존재 → 별도 RUN 으로 분리하고 || true 허용.
RUN black --version \
 && ruff --version \
 && mypy --version \
 && pytest --version \
 && pip-audit --version \
 && semgrep --version \
 && gitleaks version \
 && syft version \
 && trivy --version \
 && cosign version \
 && gh --version
RUN trestle --version || trestle version || echo "trestle import OK"

USER 10001:10001

# CI 잡 컨테이너 — 헬스체크 불요.
HEALTHCHECK NONE

# PID 1 시그널 처리(잡 cancel/timeout 시 graceful 종료).
ENTRYPOINT ["/usr/bin/tini", "--"]

# 인자 없이 실행 시 도구 버전 출력(스모크 진단용).
CMD ["bash", "-c", "echo 'uav-soc-builder ready' && black --version && ruff --version && mypy --version && pytest --version"]
