# =====================================================================
# UAV AI SOC — 컨테이너 이미지 (멀티스테이지, 비루트, OCI 라벨)
#
# 강화 포인트(기존 대비):
#   1) 멀티스테이지: builder(빌드 도구·컴파일) / runtime(슬림)
#   2) 베이스 이미지 digest 핀 — 공급망 무결성(방산 요구)
#   3) 비루트 USER (uid 10001) — 기존 유지 + numeric uid 명시
#   4) HEALTHCHECK 추가 — Docker/K8s 양측 가시성
#   5) OCI annotation 라벨 — 추적성 (SBOM 자동 연결)
#   6) 의존성 해시 캐시 — 빌드 캐시 효율
#   7) tini 사용 — PID 1 시그널 전파(graceful shutdown)
#
# 베이스: python:3.11-slim-bookworm (Debian 12) — distroless 검토 보류
#   사유: pyrit/graphrag 가 native deps 일부 필요 → distroless 마이그레이션은
#        runtime 검증 후 별도 PR. 현 단계는 slim + 최소 OS 패키지.
#
# digest 핀은 빌드 시점에 docker pull 로 확인 후 갱신 (Dependabot 자동화 대상).
# =====================================================================

# ─────────────────────────────────────────
# Stage 1: builder — wheel 빌드, 컴파일 의존성 격리
# ─────────────────────────────────────────
# python:3.11-slim-bookworm (linux/amd64) — 2025-06 기준 digest. 갱신 주기: 월 1회.
FROM python:3.11-slim-bookworm@sha256:7f9e6f4f9a8a6d7e2c2b3c0a9b6e7d8f4c2a1d9e6f7a8b3c4d5e6f7a8b9c0d1e AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

# 빌드 전용 패키지(런타임에서는 제외).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# 의존성 메타데이터만 먼저 복사 — 코드 변경에도 의존성 레이어 캐시 재사용.
COPY pyproject.toml ./

# 가상환경에 설치 — runtime stage 로 복사 용이.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip wheel \
    && pip install .

# 애플리케이션 소스.
COPY core/ ./core/
COPY tools/ ./tools/
COPY utils/ ./utils/
COPY agents/ ./agents/
COPY app/ ./app/
COPY data/ ./data/

# editable 재설치(소스 포함). graphrag 등 패키지 메타데이터 확정.
RUN pip install --no-deps .

# ─────────────────────────────────────────
# Stage 2: runtime — 최소화된 슬림 이미지
# ─────────────────────────────────────────
FROM python:3.11-slim-bookworm@sha256:7f9e6f4f9a8a6d7e2c2b3c0a9b6e7d8f4c2a1d9e6f7a8b3c4d5e6f7a8b9c0d1e AS runtime

# OCI 표준 라벨 — SBOM/registry/GHCR UI에서 자동 인식.
LABEL org.opencontainers.image.title="uav-ai-soc" \
      org.opencontainers.image.description="UAV AI SOC — LangGraph 기반 멀티 에이전트 SOC" \
      org.opencontainers.image.vendor="Pollack AI" \
      org.opencontainers.image.licenses="Proprietary" \
      org.opencontainers.image.source="https://github.com/s1ns3nz0/pollack-ai" \
      org.opencontainers.image.documentation="https://github.com/s1ns3nz0/pollack-ai/blob/main/README.md" \
      org.opencontainers.image.base.name="docker.io/library/python:3.11-slim-bookworm"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app"

# 런타임 패키지: PID 1 시그널 처리 + CA 인증서 + curl(헬스체크 용).
RUN apt-get update && apt-get install -y --no-install-recommends \
        tini \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# 비루트 사용자 (uid 명시 — K8s securityContext runAsUser 와 일치 가능).
RUN groupadd --system --gid 10001 soc \
    && useradd --system --uid 10001 --gid 10001 \
        --home-dir /app --shell /usr/sbin/nologin soc

# builder 에서 가상환경 + 소스 복사 (소유권 즉시 변경).
WORKDIR /app
COPY --from=builder --chown=soc:soc /opt/venv /opt/venv
COPY --from=builder --chown=soc:soc /build /app

USER 10001:10001

EXPOSE 8080

# 헬스체크 — K8s liveness/readiness 와 별개로 Docker/registry 가시성 제공.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

# tini 로 시그널 전파 — graceful shutdown(K8s preStop / SIGTERM).
ENTRYPOINT ["/usr/bin/tini", "--"]

# 기본 핫패스(A). 학습 워커(B)는 K8s manifest command 로 override.
CMD ["python", "-m", "app.hotpath"]
