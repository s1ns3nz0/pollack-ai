# UAV AI SOC — 컨테이너 이미지(Deployment A/B 공용).
# A(핫패스)/B(학습)는 동일 이미지에서 command 로 분기한다.
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# 의존성 레이어 캐싱: 메타데이터 먼저 복사 후 설치.
COPY pyproject.toml ./
COPY core/ ./core/
COPY tools/ ./tools/
COPY utils/ ./utils/
COPY agents/ ./agents/
COPY app/ ./app/
COPY data/ ./data/

RUN pip install --upgrade pip && pip install .

# 비루트 실행.
RUN useradd --create-home --uid 10001 soc && chown -R soc:soc /app
USER soc

EXPOSE 8080

# 기본은 핫패스(A). 학습 워커(B)는 K8s manifest 의 command 로 오버라이드.
CMD ["python", "-m", "app.hotpath"]
