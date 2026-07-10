# kagent 운영 마이그레이션 + 대시보드 외부 노출 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** pollack-ai UAV AI SOC를 kagent(AKS) 오케스트레이션 계층으로 운영하고, 대시보드를 `soc.pollak.store/dashboard`(도메인 미지정 시 Azure 기본 호스트명)로 외부 노출한다.

**Architecture:** 기존 in-process LangGraph 엔진(hotpath/learning)은 불변. kagent를 그 위에 얹어 신규 soc-toolserver의 coarse MCP 툴(`analyze_alert`)로 hotpath HTTP 표면을 호출한다. 대시보드를 컨테이너화하고 app-routing managed nginx Ingress로 `/dashboard` prefix 노출. 도메인은 배포 시 `DOMAIN` 인자로 주입, 미지정 시 평문 HTTP + Azure `*.cloudapp.azure.com` 폴백.

**Tech Stack:** Python 3.11, FastAPI/uvicorn(대시보드), mcp.server.fastmcp(SSE toolserver), httpx, kagent v1alpha2(Helm 0.9.9), ArgoCD, AKS app-routing addon, Azure OpenAI(kagent ModelConfig 전용).

**Spec:** `docs/superpowers/specs/2026-07-10-kagent-migration-design.md`

---

## 사전 확인된 사실 (조사 완료)

- 의존성 전부 설치됨: `mcp`(FastMCP 사용 가능), `httpx` 0.28.1, `fastapi`/`uvicorn`. **신규 의존성 불필요**.
- 대시보드 `create_app(snapshot_dir)` 는 루트(`/`)에서 서빙, 기존 테스트가 이를 전제(`tests/__tests__/test_dashboard_app.py` 가 `get("/")`, `/api/snapshots` 등 호출). → prefix는 **opt-in 파라미터**로만 추가, 기본 동작 보존.
- 대시보드 클라이언트 절대경로: `app/dashboard_static/index.html` 의 `/static/...`(L7-10,48), `app/dashboard_static/dashboard.js` 의 `fetch('/api/topology')`(L1402), `fetch('/api/snapshots')`(L1407), `new EventSource('/events')`(L1429).
- 대시보드 런타임 파일 의존: `core/policy/asset-topology.yaml`, `data/attack_coverage.yaml`(둘 다 Dockerfile 이 이미 COPY), `demo_snapshots/`(**Dockerfile 미포함 → 추가 필요**).
- FastMCP API: `FastMCP(name, host, port)`, `@mcp.tool()` 데코레이터(원함수 반환 → 테스트에서 직접 await 가능), `mcp.sse_app()` → Starlette 앱(`/sse` 라우트 포함), `settings.host/port`.
- 기존 kagent stub `deploy/k8s/50-kagent-toolserver.yaml`(v1alpha1, 죽은 `soc-learning/mcp` 가리킴) → 제거 후 v1alpha2 정식 CRD로 교체.
- ArgoCD `deploy/argocd/apps/soc.yaml` 은 `deploy/k8s` 경로를 dah-soc ns로 자동 동기화(concrete 매니페스트만 둘 것).

## File Structure

**신규 파일:**
- `app/toolserver.py` — MCP SSE 서버. coarse 툴 `analyze_alert` → hotpath HTTP POST.
- `tests/__tests__/test_toolserver.py` — toolserver 단위 테스트(hotpath mock).
- `tests/__tests__/test_dashboard_prefix.py` — `/dashboard` prefix 서빙 + health 라우트 테스트.
- `deploy/k8s/60-deployment-dashboard.yaml` — 대시보드 Deployment + Service(ClusterIP).
- `deploy/k8s/61-deployment-toolserver.yaml` — toolserver Deployment + Service(ClusterIP).
- `deploy/kagent/values.yaml` — kagent Helm 값(내장 에이전트 비활성, AzureOpenAI provider).
- `deploy/kagent/modelconfig.yaml` — ModelConfig(AzureOpenAI), envsubst 템플릿.
- `deploy/kagent/agent.yaml` — Agent(Declarative) soc-orchestrator.
- `deploy/kagent/remotemcpserver.yaml` — RemoteMCPServer(SSE) → soc-toolserver.
- `deploy/ingress/dashboard-ingress.yaml.template` — Ingress(DOMAIN/TLS envsubst 템플릿).
- `deploy/scripts/deploy-soc.sh` — 배포 오케스트레이션(자격증명→addon→helm→secret→CRD→ingress).
- `deploy/JUDGE-DEPLOY.md` — 심사위원 배포 가이드.
- `deploy/judge.env.example` — 심사위원 env 예제.

**수정 파일:**
- `core/settings.py` — `dashboard_root_path` + `AZURE_OPENAI_*` 필드 추가.
- `app/dashboard.py` — `create_app(root_path=...)` prefix 마운트 + health 라우트 + `main()` 배선.
- `app/dashboard_static/index.html` — 자산 절대경로 → 상대경로.
- `app/dashboard_static/dashboard.js` — fetch/EventSource 절대경로 → 상대경로.
- `core/exceptions.py` — `ToolServerError(SOCPlatformError)` 추가.
- `deploy/Dockerfile` — `COPY demo_snapshots/` 추가.
- `deploy/k8s/10-configmap.yaml` — `DASHBOARD_HOST`, `DASHBOARD_ROOT_PATH` 추가.
- `.env.example` — `AZURE_OPENAI_*`, `DASHBOARD_ROOT_PATH`, `DOMAIN` 항목 추가.

**삭제 파일:**
- `deploy/k8s/50-kagent-toolserver.yaml` — v1alpha1 stub 제거(→ `deploy/kagent/` 로 정식 이전).

---

## Task 1: Settings 확장 (dashboard_root_path + Azure OpenAI)

**Files:**
- Modify: `core/settings.py` (대시보드 섹션 L449 부근, LLM 섹션)
- Test: `tests/__tests__/test_settings.py` (없으면 생성)

- [ ] **Step 1: 실패 테스트 작성**

`tests/__tests__/test_settings.py` 에 추가(파일 없으면 아래로 생성):

```python
"""Settings 확장 필드 검증."""

from core.settings import Settings


def _settings(**overrides: object) -> Settings:
    base = {
        "ragflow_api_token": "t",
        "ragflow_dataset_id": "d",
        "ragflow_exp_dataset_id": "e",
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def test_dashboard_root_path_defaults_to_dashboard() -> None:
    """대시보드 root_path 기본값은 /dashboard 다."""
    assert _settings().dashboard_root_path == "/dashboard"


def test_azure_openai_fields_default_empty() -> None:
    """kagent 전용 Azure OpenAI 필드는 기본 빈 문자열이다."""
    settings = _settings()
    assert settings.azure_openai_endpoint == ""
    assert settings.azure_openai_deployment == "gpt-4o-soc"
```

> 참고: `Settings` 필수 필드가 위 3개와 다르면 `_settings` base 를 실제 필수 필드에 맞춰 조정한다(`core/settings.py` 에서 default 없는 필드 확인).

- [ ] **Step 2: 테스트 실패 확인**

Run: `pytest tests/__tests__/test_settings.py -v`
Expected: FAIL — `AttributeError: 'Settings' object has no attribute 'dashboard_root_path'`

- [ ] **Step 3: 필드 추가**

`core/settings.py` 대시보드 섹션(`dashboard_public_url` Field 정의 바로 뒤)에 추가:

```python
    dashboard_root_path: str = Field(
        default="/dashboard",
        description=(
            "대시보드 URL prefix. Ingress 가 이 경로로 외부 노출한다. "
            "빈 문자열이면 루트(/)에서 서빙."
        ),
    )
```

LLM 섹션 부근(Azure OpenAI 관련 위치)에 kagent 전용 필드 추가:

```python
    # ── kagent 오케스트레이터 전용 Azure OpenAI (SOC 엔진 LLM 과 별개) ──
    azure_openai_endpoint: str = Field(
        default="",
        description="kagent ModelConfig 용 Azure OpenAI 엔드포인트.",
    )
    azure_openai_deployment: str = Field(
        default="gpt-4o-soc",
        description="kagent ModelConfig 용 Azure OpenAI 배포명.",
    )
    azure_openai_api_version: str = Field(
        default="2024-10-21",
        description="Azure OpenAI API 버전.",
    )
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `pytest tests/__tests__/test_settings.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: 커밋**

```bash
git add core/settings.py tests/__tests__/test_settings.py
git commit -m "feat(settings): add dashboard_root_path + kagent Azure OpenAI fields"
```

---

## Task 2: 대시보드 클라이언트 자산 상대경로화

**이유:** `/dashboard` prefix 하에서 절대경로 `/static`·`/api`·`/events` 는 Ingress 라우팅 밖으로 나가 깨진다. 상대경로로 바꾸면 마운트 지점(`/` 또는 `/dashboard/`) 무관하게 문서 URL 기준으로 해석된다. 서버 라우트는 그대로라 기존 테스트 불변.

**Files:**
- Modify: `app/dashboard_static/index.html` (L7-10, L48)
- Modify: `app/dashboard_static/dashboard.js` (L1402, L1407, L1429)
- Test: `tests/__tests__/test_dashboard_static.py` (기존 — 회귀 확인만)

- [ ] **Step 1: index.html 자산 상대경로화**

`app/dashboard_static/index.html` 편집 — 절대경로 `/static/` → 상대 `static/`:

```html
    <link rel="stylesheet" href="static/vendor/astryx/reset.css" />
    <link rel="stylesheet" href="static/vendor/astryx/astryx.css" />
    <link rel="stylesheet" href="static/vendor/astryx/theme-neutral.css" />
    <link rel="stylesheet" href="static/dashboard.css" />
```

L48 script:

```html
    <script src="static/dashboard.js" defer></script>
```

`<head>` 안(첫 `<meta>` 뒤)에 base 태그 추가 — 트레일링 슬래시 보장으로 상대경로 해석 고정:

```html
    <base href="./" />
```

- [ ] **Step 2: dashboard.js fetch 상대경로화**

`app/dashboard_static/dashboard.js` 편집:
- L1402 `fetch('/api/topology')` → `fetch('api/topology')`
- L1407 `fetch('/api/snapshots')` → `fetch('api/snapshots')`
- L1429 `new EventSource('/events')` → `new EventSource('events')`

- [ ] **Step 3: 기존 정적 테스트 회귀 확인**

Run: `pytest tests/__tests__/test_dashboard_static.py -v`
Expected: PASS — 테스트는 HTML 내 `"dashboard.css"`·`"dashboard.js"` 부분문자열만 확인하므로 상대경로 전환 후에도 통과.

- [ ] **Step 4: 커밋**

```bash
git add app/dashboard_static/index.html app/dashboard_static/dashboard.js
git commit -m "refactor(dashboard): relative asset/fetch paths for prefix serving"
```

---

## Task 3: 대시보드 prefix 마운트 + health 라우트

**Files:**
- Modify: `app/dashboard.py` (`create_app` L60-120, `main` L126-148, 모듈 L123)
- Test: `tests/__tests__/test_dashboard_prefix.py` (신규)

- [ ] **Step 1: 실패 테스트 작성**

`tests/__tests__/test_dashboard_prefix.py`:

```python
"""대시보드 prefix 마운트 + health 라우트 검증."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.dashboard import create_app


def test_prefix_serves_index_under_dashboard(tmp_path: Path) -> None:
    """root_path 지정 시 /dashboard/ 에서 인덱스를 서빙한다."""
    client = TestClient(create_app(tmp_path, root_path="/dashboard"))

    response = client.get("/dashboard/")

    assert response.status_code == 200
    assert "UAV AI SOC" in response.text


def test_prefix_serves_api_under_dashboard(tmp_path: Path) -> None:
    """prefix 하에서 API 도 /dashboard/api 로 접근된다."""
    client = TestClient(create_app(tmp_path, root_path="/dashboard"))

    response = client.get("/dashboard/api/snapshots")

    assert response.status_code == 200
    assert response.json() == {"snapshots": []}


def test_healthz_is_unprefixed(tmp_path: Path) -> None:
    """K8s 프로브용 /healthz 는 prefix 없이 응답한다."""
    client = TestClient(create_app(tmp_path, root_path="/dashboard"))

    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200


def test_root_mount_still_works(tmp_path: Path) -> None:
    """root_path 미지정 시 기존처럼 / 에서 서빙(회귀)."""
    client = TestClient(create_app(tmp_path))

    assert client.get("/").status_code == 200
    assert client.get("/healthz").status_code == 200
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `pytest tests/__tests__/test_dashboard_prefix.py -v`
Expected: FAIL — `create_app()` 이 `root_path` 인자를 받지 않음(TypeError) / `/healthz` 404.

- [ ] **Step 3: create_app 확장 + health 라우트 + main 배선**

`app/dashboard.py` 편집.

`create_app` 시그니처와 반환부 수정(health 라우트는 항상 unprefixed 하도록 outer 앱에 등록):

```python
def create_app(
    snapshot_dir: str | Path | None = None,
    root_path: str = "",
) -> FastAPI:
    """Create the dashboard FastAPI app.

    Args:
        snapshot_dir: Optional replay snapshot directory.
        root_path: URL prefix (예: "/dashboard"). 빈 문자열이면 루트에서 서빙.

    Returns:
        Configured FastAPI application. root_path 지정 시 prefix 마운트된
        부모 앱을 반환하며, /healthz·/readyz 는 prefix 없이 노출된다.
    """
    replay_dir = (
        Path(snapshot_dir) if snapshot_dir is not None else Path("demo_snapshots")
    )
    app = FastAPI(title="UAV AI SOC Defense Dashboard")
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="dashboard_static")

    # ... 기존 @app.get("/"), /api/snapshots, /api/topology, /events 정의 그대로 유지 ...

    def _register_health(target: FastAPI) -> None:
        @target.get("/healthz", response_class=PlainTextResponse)
        async def healthz() -> str:
            """Liveness probe."""
            return "ok"

        @target.get("/readyz", response_class=PlainTextResponse)
        async def readyz() -> str:
            """Readiness probe."""
            return "ok"

    if root_path:
        parent = FastAPI(title="UAV AI SOC Defense Dashboard (mounted)")
        parent.mount(root_path, app)
        _register_health(parent)
        return parent

    _register_health(app)
    return app
```

import 에 `PlainTextResponse` 추가(L10 부근):

```python
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
```

모듈 레벨(L123)과 `main()` 을 settings prefix 로 배선:

```python
app = create_app()


def main() -> None:
    """Run the dashboard server using Settings-driven host/port/prefix."""
    settings = get_settings()
    host = settings.dashboard_host
    public_url = settings.dashboard_public_url.strip().rstrip("/")
    if public_url and host == "127.0.0.1":
        host = "0.0.0.0"  # noqa: S104 — 공개 도메인 opt-in 시에만 외부 바인드

    server_app = create_app(root_path=settings.dashboard_root_path)
    _logger.info(
        "dashboard listening host=%s port=%d root_path=%s",
        host,
        settings.dashboard_port,
        settings.dashboard_root_path,
    )
    uvicorn.run(server_app, host=host, port=settings.dashboard_port)
```

> 주의: `create_app` 내부의 기존 `/`·`/api/*`·`/events` 라우트 정의는 삭제하지 말고 그대로 둘 것. 위 스니펫의 `# ...` 는 그 블록을 가리킨다.

- [ ] **Step 4: 테스트 통과 확인**

Run: `pytest tests/__tests__/test_dashboard_prefix.py tests/__tests__/test_dashboard_app.py -v`
Expected: PASS — 신규 4개 + 기존 대시보드 앱 테스트 전부 통과(회귀 없음).

- [ ] **Step 5: 커밋**

```bash
git add app/dashboard.py tests/__tests__/test_dashboard_prefix.py
git commit -m "feat(dashboard): opt-in prefix mount + unprefixed health routes"
```

---

## Task 4: core/exceptions — ToolServerError

**Files:**
- Modify: `core/exceptions.py`
- Test: `tests/__tests__/test_exceptions.py` (없으면 생성)

- [ ] **Step 1: 실패 테스트 작성**

`tests/__tests__/test_exceptions.py` 에 추가:

```python
from core.exceptions import SOCPlatformError, ToolServerError


def test_toolserver_error_is_platform_error() -> None:
    """ToolServerError 는 SOCPlatformError 하위다."""
    assert issubclass(ToolServerError, SOCPlatformError)
```

- [ ] **Step 2: 실패 확인**

Run: `pytest tests/__tests__/test_exceptions.py::test_toolserver_error_is_platform_error -v`
Expected: FAIL — `ImportError: cannot import name 'ToolServerError'`

- [ ] **Step 3: 예외 추가**

`core/exceptions.py` 에 추가(기존 예외 계층 끝):

```python
class ToolServerError(SOCPlatformError):
    """MCP toolserver 의 hotpath 호출 오류."""
```

- [ ] **Step 4: 통과 확인**

Run: `pytest tests/__tests__/test_exceptions.py::test_toolserver_error_is_platform_error -v`
Expected: PASS

- [ ] **Step 5: 커밋**

```bash
git add core/exceptions.py tests/__tests__/test_exceptions.py
git commit -m "feat(exceptions): add ToolServerError"
```

---

## Task 5: soc-toolserver (MCP SSE 서버)

**Files:**
- Create: `app/toolserver.py`
- Test: `tests/__tests__/test_toolserver.py`

- [ ] **Step 1: 실패 테스트 작성**

`tests/__tests__/test_toolserver.py`:

```python
"""soc-toolserver analyze_alert 툴 검증(hotpath mock)."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.toolserver import analyze_alert
from core.exceptions import ToolServerError


@pytest.mark.asyncio
async def test_analyze_alert_returns_hotpath_verdict() -> None:
    """hotpath 응답 JSON 을 가공 없이 반환한다."""
    verdict = {"verdict": "malicious", "severity": "high"}
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json = MagicMock(return_value=verdict)

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client

    with patch("app.toolserver.httpx.AsyncClient", return_value=mock_client):
        result = await analyze_alert({"alert_id": "A-1"})

    assert result == verdict
    mock_client.post.assert_awaited_once()


@pytest.mark.asyncio
async def test_analyze_alert_wraps_http_error() -> None:
    """hotpath HTTP 오류는 ToolServerError 로 감싼다."""
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.side_effect = httpx.ConnectError("refused")

    with patch("app.toolserver.httpx.AsyncClient", return_value=mock_client):
        with pytest.raises(ToolServerError):
            await analyze_alert({"alert_id": "A-1"})
```

- [ ] **Step 2: 실패 확인**

Run: `pytest tests/__tests__/test_toolserver.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.toolserver'`

- [ ] **Step 3: toolserver 구현**

`app/toolserver.py`:

```python
"""UAV SOC ops MCP toolserver — hotpath LangGraph 표면을 coarse 툴로 노출.

kagent 오케스트레이터가 SSE 로 이 서버를 호출한다. 단일 coarse 툴
``analyze_alert`` 는 alert 를 hotpath Deployment 에 HTTP POST 하고 verdict 를
그대로 반환한다(신규 판정 미생성 — 전달만).
"""

from __future__ import annotations

import os

import httpx
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from core.exceptions import ToolServerError
from utils.logging import get_logger

_logger = get_logger("toolserver")

_HOTPATH_URL = os.environ.get(
    "HOTPATH_URL",
    "http://soc-hotpath.dah-soc.svc.cluster.local:80/alert",
)
_HOST = os.environ.get("MCP_HOST", "0.0.0.0")  # noqa: S104 — 컨테이너 내부
_PORT = int(os.environ.get("MCP_PORT", "8080"))

mcp = FastMCP("uav-soc-ops", host=_HOST, port=_PORT)


@mcp.tool()
async def analyze_alert(alert: dict[str, object]) -> dict[str, object]:
    """UAV SOC alert 를 hotpath 그래프에 제출하고 판정을 반환한다.

    Args:
        alert: SOC alert JSON(alert_id, 원 이벤트 필드 포함).

    Returns:
        hotpath 가 반환한 verdict/severity JSON(가공 없음).

    Raises:
        ToolServerError: hotpath 연결/HTTP 오류 시.
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(_HOTPATH_URL, json=alert)
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPStatusError as exc:
        raise ToolServerError(
            f"hotpath HTTP 오류 {exc.response.status_code}"
        ) from exc
    except httpx.HTTPError as exc:
        raise ToolServerError(f"hotpath 연결 실패: {exc}") from exc


async def _healthz(_request: Request) -> PlainTextResponse:
    """Liveness/readiness probe."""
    return PlainTextResponse("ok")


def build_app() -> Starlette:
    """SSE MCP 앱에 /healthz 를 추가한 Starlette 앱을 반환한다.

    Returns:
        `/sse`(MCP) + `/healthz`(프로브) 라우트를 가진 Starlette 앱.
    """
    app = mcp.sse_app()
    app.router.routes.append(Route("/healthz", _healthz))
    return app


def main() -> None:
    """toolserver 를 uvicorn 으로 실행(SSE + healthz)."""
    import uvicorn

    _logger.info("toolserver listening host=%s port=%d", _HOST, _PORT)
    uvicorn.run(build_app(), host=_HOST, port=_PORT)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: 통과 확인**

Run: `pytest tests/__tests__/test_toolserver.py -v`
Expected: PASS (2 passed)

> `@mcp.tool()` 이 원함수를 반환하지 않아 `analyze_alert` 가 await 불가하면: 데코레이터를 떼고 함수 정의 후 별도로 `mcp.add_tool(analyze_alert)` 를 호출하도록 바꾼다(테스트는 그대로 통과).

- [ ] **Step 5: 커밋**

```bash
git add app/toolserver.py tests/__tests__/test_toolserver.py
git commit -m "feat(toolserver): MCP SSE server wrapping hotpath analyze_alert"
```

---

## Task 6: Dockerfile — demo_snapshots 포함

**Files:**
- Modify: `deploy/Dockerfile` (L18 뒤)

- [ ] **Step 1: COPY 추가**

`deploy/Dockerfile` 의 `COPY data/ ./data/`(L18) 바로 뒤에 추가:

```dockerfile
COPY demo_snapshots/ ./demo_snapshots/
```

- [ ] **Step 2: 빌드 검증(로컬 Docker 있으면)**

Run: `docker build -f deploy/Dockerfile -t uav-ai-soc:migtest . && docker run --rm uav-ai-soc:migtest python -c "from pathlib import Path; assert Path('demo_snapshots').is_dir(); print('demo_snapshots ok')"`
Expected: `demo_snapshots ok`

> Docker 미가용 환경이면 이 스텝은 스킵하고 매니페스트 배포 시 확인. 스킵 사실을 커밋 메시지에 남긴다.

- [ ] **Step 3: 커밋**

```bash
git add deploy/Dockerfile
git commit -m "build: bundle demo_snapshots for dashboard replay"
```

---

## Task 7: ConfigMap — 대시보드 host/root_path

**Files:**
- Modify: `deploy/k8s/10-configmap.yaml`

- [ ] **Step 1: 항목 추가**

`deploy/k8s/10-configmap.yaml` 의 `data:` 끝(`LOG_LEVEL` 뒤)에 추가:

```yaml
  # 대시보드(컨테이너 내부 바인드 + 외부 노출 prefix)
  DASHBOARD_HOST: "0.0.0.0"
  DASHBOARD_ROOT_PATH: "/dashboard"
```

- [ ] **Step 2: YAML 유효성 확인**

Run: `python -c "import yaml; yaml.safe_load(open('deploy/k8s/10-configmap.yaml'))" && echo ok`
Expected: `ok`

- [ ] **Step 3: 커밋**

```bash
git add deploy/k8s/10-configmap.yaml
git commit -m "chore(k8s): configmap dashboard host + root_path"
```

---

## Task 8: 대시보드 Deployment + Service

**Files:**
- Create: `deploy/k8s/60-deployment-dashboard.yaml`

- [ ] **Step 1: 매니페스트 작성**

`deploy/k8s/60-deployment-dashboard.yaml`:

```yaml
# 대시보드(read-only replay). 외부 노출 대상 — Ingress 가 /dashboard 로 라우팅.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: soc-dashboard
  namespace: dah-soc
  labels:
    app: soc-dashboard
    soc.role: dashboard
spec:
  replicas: 1
  selector:
    matchLabels:
      app: soc-dashboard
  template:
    metadata:
      labels:
        app: soc-dashboard
    spec:
      containers:
        - name: dashboard
          image: ghcr.io/s1ns3nz0/uav-ai-soc:latest
          command: ["python", "-m", "app.dashboard"]
          ports:
            - name: http
              containerPort: 8791
          envFrom:
            - configMapRef:
                name: soc-config
            - secretRef:
                name: soc-secrets
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8791
            initialDelaySeconds: 10
            periodSeconds: 15
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8791
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: "100m"
              memory: "256Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"
---
apiVersion: v1
kind: Service
metadata:
  name: soc-dashboard
  namespace: dah-soc
  labels:
    app: soc-dashboard
spec:
  selector:
    app: soc-dashboard
  ports:
    - name: http
      port: 80
      targetPort: 8791
```

- [ ] **Step 2: YAML 유효성 확인**

Run: `python -c "import yaml,sys; list(yaml.safe_load_all(open('deploy/k8s/60-deployment-dashboard.yaml'))); print('ok')"`
Expected: `ok`

- [ ] **Step 3: 커밋**

```bash
git add deploy/k8s/60-deployment-dashboard.yaml
git commit -m "feat(k8s): dashboard deployment + clusterip service"
```

---

## Task 9: toolserver Deployment + Service

**Files:**
- Create: `deploy/k8s/61-deployment-toolserver.yaml`

- [ ] **Step 1: 매니페스트 작성**

`deploy/k8s/61-deployment-toolserver.yaml`:

```yaml
# soc-toolserver — MCP SSE 서버. kagent 오케스트레이터가 in-cluster SSE 로 호출.
# 외부 미노출(ClusterIP). analyze_alert → soc-hotpath HTTP POST.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: soc-toolserver
  namespace: dah-soc
  labels:
    app: soc-toolserver
    soc.role: toolserver
spec:
  replicas: 1
  selector:
    matchLabels:
      app: soc-toolserver
  template:
    metadata:
      labels:
        app: soc-toolserver
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: toolserver
          image: ghcr.io/s1ns3nz0/uav-ai-soc:latest
          command: ["python", "-m", "app.toolserver"]
          env:
            - name: MCP_HOST
              value: "0.0.0.0"
            - name: MCP_PORT
              value: "8080"
            - name: HOTPATH_URL
              value: "http://soc-hotpath.dah-soc.svc.cluster.local:80/alert"
          ports:
            - name: http
              containerPort: 8080
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 15
            periodSeconds: 20
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: "100m"
              memory: "256Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
---
apiVersion: v1
kind: Service
metadata:
  name: soc-toolserver
  namespace: dah-soc
  labels:
    app: soc-toolserver
spec:
  type: ClusterIP
  selector:
    app: soc-toolserver
  ports:
    - name: http
      port: 8080
      targetPort: 8080
```

- [ ] **Step 2: YAML 유효성 확인**

Run: `python -c "import yaml; list(yaml.safe_load_all(open('deploy/k8s/61-deployment-toolserver.yaml'))); print('ok')"`
Expected: `ok`

- [ ] **Step 3: 커밋**

```bash
git add deploy/k8s/61-deployment-toolserver.yaml
git commit -m "feat(k8s): soc-toolserver deployment + clusterip service"
```

---

## Task 10: 기존 v1alpha1 kagent stub 제거

**Files:**
- Delete: `deploy/k8s/50-kagent-toolserver.yaml`

- [ ] **Step 1: 삭제**

Run: `git rm deploy/k8s/50-kagent-toolserver.yaml`
이유: v1alpha1 + 죽은 `soc-learning/mcp` 대상. 정식 CRD 는 `deploy/kagent/`(Task 11)로 이전하며, operator 미설치 상태에서 ArgoCD 자동 동기화 경로(`deploy/k8s`)에 CRD 가 있으면 sync 실패한다.

- [ ] **Step 2: README 참조 정리**

`deploy/k8s/README.md` 에서 `50-kagent-toolserver.yaml` 언급 줄(L10, L38-39 부근)을 제거하거나 "kagent CRD 는 `deploy/kagent/` 로 이전(operator 설치 후 deploy-soc.sh 가 적용)"으로 교체.

- [ ] **Step 3: 커밋**

```bash
git add deploy/k8s/README.md
git commit -m "chore(k8s): drop v1alpha1 kagent stub (moved to deploy/kagent)"
```

---

## Task 11: kagent CRD 매니페스트 (ModelConfig / Agent / RemoteMCPServer)

**Files:**
- Create: `deploy/kagent/modelconfig.yaml`
- Create: `deploy/kagent/agent.yaml`
- Create: `deploy/kagent/remotemcpserver.yaml`

> ⚠️ 아래는 fried-pollack-ai 검증본과 동일한 `kagent.dev/v1alpha2` 스키마다. **Task 13(배포 스크립트) 실행 시 `kubectl get crd | grep kagent` 로 설치된 실제 버전을 확인**하고 apiVersion/필드가 다르면 정합 조정한다(spec 미검증 가정 #3).

- [ ] **Step 1: ModelConfig 작성(envsubst 템플릿)**

`deploy/kagent/modelconfig.yaml`:

```yaml
apiVersion: kagent.dev/v1alpha2
kind: ModelConfig
metadata:
  name: soc-azure-openai
  namespace: dah-soc
spec:
  provider: AzureOpenAI
  model: gpt-4o-mini
  apiKeySecret: kagent-azure-openai
  apiKeySecretKey: AZUREOPENAI_API_KEY
  azureOpenAI:
    azureEndpoint: "${AZURE_OPENAI_ENDPOINT}"
    azureDeployment: "${AZURE_OPENAI_DEPLOYMENT}"
    apiVersion: "${AZURE_OPENAI_API_VERSION}"
```

- [ ] **Step 2: RemoteMCPServer 작성**

`deploy/kagent/remotemcpserver.yaml`:

```yaml
apiVersion: kagent.dev/v1alpha2
kind: RemoteMCPServer
metadata:
  name: soc-toolserver
  namespace: dah-soc
spec:
  description: UAV SOC coarse ops MCP toolserver (analyze_alert → hotpath)
  protocol: SSE
  url: http://soc-toolserver.dah-soc.svc.cluster.local:8080/sse
  timeout: 30s
  sseReadTimeout: 5m
  terminateOnClose: true
```

- [ ] **Step 3: Agent 작성**

`deploy/kagent/agent.yaml`:

```yaml
apiVersion: kagent.dev/v1alpha2
kind: Agent
metadata:
  name: soc-orchestrator
  namespace: dah-soc
spec:
  description: Submits UAV SOC alerts to the analyze_alert MCP tool and summarizes the returned verdict.
  type: Declarative
  declarative:
    modelConfig: soc-azure-openai
    systemMessage: |-
      You are the UAV AI SOC triage orchestrator.

      Constraints:
      - You may call only the coarse analyze_alert MCP tool.
      - Pass the alert JSON through unchanged; do not fabricate verdict, severity, or mission impact.
      - The tool returns the authoritative hotpath verdict. Summarize it faithfully in Markdown.
      - Do not invent detections or downgrade severity. Surface degraded/unknown states honestly.
    tools:
      - type: McpServer
        mcpServer:
          apiGroup: kagent.dev
          kind: RemoteMCPServer
          name: soc-toolserver
          toolNames:
            - analyze_alert
```

- [ ] **Step 4: YAML 유효성 확인**

Run: `for f in deploy/kagent/*.yaml; do python -c "import yaml,sys; list(yaml.safe_load_all(open('$f')))" && echo "$f ok"; done`
Expected: 3개 파일 모두 `ok`

- [ ] **Step 5: 커밋**

```bash
git add deploy/kagent/modelconfig.yaml deploy/kagent/agent.yaml deploy/kagent/remotemcpserver.yaml
git commit -m "feat(kagent): v1alpha2 ModelConfig + Agent + RemoteMCPServer for SOC orchestrator"
```

---

## Task 12: kagent Helm values

**Files:**
- Create: `deploy/kagent/values.yaml`

- [ ] **Step 1: values 작성**

`deploy/kagent/values.yaml` (fried-pollack 미러, 내장 에이전트 전부 비활성, AOAI provider):

```yaml
# kagent 플랫폼 Helm 값. 내장 에이전트/툴은 전부 비활성 — SOC 오케스트레이터만 사용.
providers:
  default: azureOpenAI
  azureOpenAI:
    provider: AzureOpenAI
    model: gpt-4o-mini
    apiKeySecretRef: kagent-azure-openai
    apiKeySecretKey: AZUREOPENAI_API_KEY
    config:
      apiVersion: "2024-10-21"
      azureEndpoint: "${AZURE_OPENAI_ENDPOINT}"
      azureDeployment: "${AZURE_OPENAI_DEPLOYMENT}"

kagent-tools:
  enabled: false
grafana-mcp:
  enabled: false
querydoc:
  enabled: false
k8s-agent:
  enabled: false
kgateway-agent:
  enabled: false
istio-agent:
  enabled: false
promql-agent:
  enabled: false
observability-agent:
  enabled: false
argo-rollouts-agent:
  enabled: false
cilium-agent:
  enabled: false
```

- [ ] **Step 2: YAML 유효성 확인**

Run: `python -c "import yaml; yaml.safe_load(open('deploy/kagent/values.yaml')); print('ok')"`
Expected: `ok`

- [ ] **Step 3: 커밋**

```bash
git add deploy/kagent/values.yaml
git commit -m "feat(kagent): helm values (builtin agents disabled, azure openai)"
```

---

## Task 13: Ingress 템플릿 (DOMAIN/TLS envsubst)

**Files:**
- Create: `deploy/ingress/dashboard-ingress.yaml.template`

- [ ] **Step 1: 템플릿 작성**

`deploy/ingress/dashboard-ingress.yaml.template` — `deploy-soc.sh` 가 envsubst 로 렌더. `${TLS_BLOCK}`/`${TLS_ANNOTATION}` 는 DOMAIN 유무에 따라 스크립트가 채우거나 빈 문자열로 치환:

```yaml
# 대시보드 외부 노출 Ingress. app-routing managed nginx 사용.
# ${DOMAIN}: 실도메인(soc.pollak.store) 또는 Azure 기본 호스트명.
# TLS: 실도메인일 때만 cert-manager 발급, 폴백(Azure 호스트명)은 평문 HTTP.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: soc-dashboard
  namespace: dah-soc
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /$2
${TLS_ANNOTATION}
spec:
  ingressClassName: webapprouting.kubernetes.azure.com
  rules:
    - host: "${DOMAIN}"
      http:
        paths:
          - path: /dashboard(/|$)(.*)
            pathType: ImplementationSpecific
            backend:
              service:
                name: soc-dashboard
                port:
                  number: 80
${TLS_BLOCK}
```

> **Prefix 처리 주석:** 대시보드 앱은 `DASHBOARD_ROOT_PATH=/dashboard` 로 `/dashboard/` 에서 서빙하고, 클라이언트 자산은 상대경로(Task 2)다. rewrite-target 은 `/dashboard` 방문 시 앱 마운트 지점과 정합하도록 `$2` 로 캡처 경로를 넘긴다. 배포 검증(Task 16)에서 CSS/JS 로딩과 SSE 를 실제 확인한다.

- [ ] **Step 2: 렌더 스모크(DOMAIN 지정/미지정)**

Run:
```bash
DOMAIN=soc.pollak.store TLS_ANNOTATION='    cert-manager.io/cluster-issuer: letsencrypt-prod' \
TLS_BLOCK='  tls:
    - hosts:
        - soc.pollak.store
      secretName: soc-dashboard-tls' \
envsubst < deploy/ingress/dashboard-ingress.yaml.template | python -c "import yaml,sys; list(yaml.safe_load_all(sys.stdin)); print('domain-render ok')"
```
Expected: `domain-render ok`

Run(폴백):
```bash
DOMAIN=uav-soc.koreacentral.cloudapp.azure.com TLS_ANNOTATION='' TLS_BLOCK='' \
envsubst < deploy/ingress/dashboard-ingress.yaml.template | python -c "import yaml,sys; list(yaml.safe_load_all(sys.stdin)); print('fallback-render ok')"
```
Expected: `fallback-render ok`

- [ ] **Step 3: 커밋**

```bash
git add deploy/ingress/dashboard-ingress.yaml.template
git commit -m "feat(ingress): templated dashboard ingress (domain + conditional TLS)"
```

---

## Task 14: 배포 스크립트 deploy-soc.sh

**Files:**
- Create: `deploy/scripts/deploy-soc.sh`

- [ ] **Step 1: 스크립트 작성**

`deploy/scripts/deploy-soc.sh`:

```bash
#!/usr/bin/env bash
# UAV AI SOC — kagent(AKS) 배포 오케스트레이션.
# 기존 dah-soc AKS 재사용. DOMAIN 미지정 시 Azure 기본 호스트명 + 평문 HTTP 폴백.
#
# 필수 env: AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_KEY
# 선택 env: DOMAIN(미지정→Azure 호스트명), RESOURCE_GROUP, AKS_NAME,
#           AZURE_OPENAI_DEPLOYMENT(기본 gpt-4o-soc), AZURE_OPENAI_API_VERSION(기본 2024-10-21),
#           KAGENT_VERSION(기본 0.9.9), DNS_LABEL(기본 uav-soc)
set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-dah-soc-rg}"
AKS_NAME="${AKS_NAME:-dah-soc-aks}"
KAGENT_VERSION="${KAGENT_VERSION:-0.9.9}"
DNS_LABEL="${DNS_LABEL:-uav-soc}"
AZURE_OPENAI_DEPLOYMENT="${AZURE_OPENAI_DEPLOYMENT:-gpt-4o-soc}"
AZURE_OPENAI_API_VERSION="${AZURE_OPENAI_API_VERSION:-2024-10-21}"
NS_SOC="dah-soc"
NS_KAGENT="kagent"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

: "${AZURE_OPENAI_ENDPOINT:?AZURE_OPENAI_ENDPOINT 필요}"
: "${AZURE_OPENAI_KEY:?AZURE_OPENAI_KEY 필요}"
export AZURE_OPENAI_ENDPOINT AZURE_OPENAI_DEPLOYMENT AZURE_OPENAI_API_VERSION

echo "==> [1/8] AKS 자격증명 (${RESOURCE_GROUP}/${AKS_NAME})"
az aks get-credentials -g "$RESOURCE_GROUP" -n "$AKS_NAME" --overwrite-existing

echo "==> [2/8] app-routing addon 활성화 (managed nginx)"
az aks approuting enable -g "$RESOURCE_GROUP" -n "$AKS_NAME" 2>/dev/null || \
  echo "    (이미 활성 또는 enable 실패 — kubectl 로 webapprouting 확인 필요)"

echo "==> [3/8] 네임스페이스"
kubectl create namespace "$NS_SOC" --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace "$NS_KAGENT" --dry-run=client -o yaml | kubectl apply -f -

echo "==> [4/8] Azure OpenAI 시크릿 (kagent + dah-soc 양 ns)"
for ns in "$NS_KAGENT" "$NS_SOC"; do
  kubectl create secret generic kagent-azure-openai \
    --namespace "$ns" \
    --from-literal=AZUREOPENAI_API_KEY="$AZURE_OPENAI_KEY" \
    --dry-run=client -o yaml | kubectl apply -f -
done

echo "==> [5/8] kagent 플랫폼 Helm 설치 (${KAGENT_VERSION})"
helm upgrade -i kagent-crds oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds \
  --version "$KAGENT_VERSION" --namespace "$NS_KAGENT"
envsubst < "$REPO_ROOT/deploy/kagent/values.yaml" > /tmp/kagent-values.rendered.yaml
helm upgrade -i kagent oci://ghcr.io/kagent-dev/kagent/helm/kagent \
  --version "$KAGENT_VERSION" --namespace "$NS_KAGENT" \
  -f /tmp/kagent-values.rendered.yaml

echo "==> [6/8] kagent CRD 스키마 확인"
kubectl get crd 2>/dev/null | grep kagent || echo "    (kagent CRD 미표시 — operator 기동 대기 후 재확인)"

echo "==> [7/8] SOC CRD 적용 (ModelConfig/RemoteMCPServer/Agent)"
for f in modelconfig remotemcpserver agent; do
  envsubst < "$REPO_ROOT/deploy/kagent/${f}.yaml" | kubectl apply -f -
done

echo "==> [8/8] 대시보드 Ingress (DOMAIN 해석)"
if [[ -n "${DOMAIN:-}" ]]; then
  echo "    실도메인: ${DOMAIN} (cert-manager TLS)"
  export DOMAIN
  export TLS_ANNOTATION="    cert-manager.io/cluster-issuer: letsencrypt-prod"
  export TLS_BLOCK="  tls:
    - hosts:
        - ${DOMAIN}
      secretName: soc-dashboard-tls"
else
  # 폴백: app-routing LB 공인 IP → Azure 기본 호스트명(평문 HTTP)
  echo "    DOMAIN 미지정 — Azure 기본 호스트명 폴백"
  LB_IP="$(kubectl get svc -n app-routing-system nginx -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
  if [[ -z "$LB_IP" ]]; then
    echo "    LB IP 아직 미할당 — 잠시 후 재실행하거나 DOMAIN 을 직접 지정하세요." >&2
    exit 1
  fi
  PIP_ID="$(az network public-ip list --query "[?ipAddress=='${LB_IP}'].id" -o tsv | head -1)"
  if [[ -n "$PIP_ID" ]]; then
    az network public-ip update --ids "$PIP_ID" --dns-name "$DNS_LABEL" >/dev/null
    REGION="$(az aks show -g "$RESOURCE_GROUP" -n "$AKS_NAME" --query location -o tsv)"
    export DOMAIN="${DNS_LABEL}.${REGION}.cloudapp.azure.com"
  else
    export DOMAIN="$LB_IP"  # DNS 라벨 부여 불가 시 IP 직접
  fi
  export TLS_ANNOTATION=""
  export TLS_BLOCK=""
  echo "    폴백 접속 호스트: ${DOMAIN}"
fi
envsubst < "$REPO_ROOT/deploy/ingress/dashboard-ingress.yaml.template" | kubectl apply -f -

SCHEME="http"; [[ -n "${TLS_BLOCK:-}" ]] && SCHEME="https"
echo "==> 완료. 대시보드: ${SCHEME}://${DOMAIN}/dashboard"
```

- [ ] **Step 2: 실행권한 + 문법 검사**

Run: `chmod +x deploy/scripts/deploy-soc.sh && bash -n deploy/scripts/deploy-soc.sh && echo "syntax ok"`
Expected: `syntax ok`

- [ ] **Step 3: 커밋**

```bash
git add deploy/scripts/deploy-soc.sh
git commit -m "feat(deploy): deploy-soc.sh kagent+ingress orchestration with domain fallback"
```

---

## Task 15: 심사위원 배포 문서

**Files:**
- Create: `deploy/judge.env.example`
- Create: `deploy/JUDGE-DEPLOY.md`

- [ ] **Step 1: env 예제 작성**

`deploy/judge.env.example`:

```bash
# 심사위원 배포 env. 채운 뒤: `set -a; source judge.env; set +a; ./deploy/scripts/deploy-soc.sh`
# 자기 Azure 구독/AKS/AOAI 로 배포. DOMAIN 은 비워두면 Azure 기본 호스트명으로 접속 가능.

# 필수 — Azure OpenAI(kagent 오케스트레이터용)
AZURE_OPENAI_ENDPOINT="https://<your-aoai>.openai.azure.com/"
AZURE_OPENAI_KEY="<your-aoai-key>"
AZURE_OPENAI_DEPLOYMENT="gpt-4o-soc"

# 선택 — 기존 클러스터 좌표(기본 dah-soc-rg/dah-soc-aks)
RESOURCE_GROUP="dah-soc-rg"
AKS_NAME="dah-soc-aks"

# 선택 — 도메인. 비우면 <DNS_LABEL>.<region>.cloudapp.azure.com 평문 HTTP.
# DOMAIN="soc.pollak.store"
DNS_LABEL="uav-soc"
```

- [ ] **Step 2: 가이드 작성**

`deploy/JUDGE-DEPLOY.md`:

```markdown
# 심사위원 배포 가이드

도메인 없이도 Azure 기본 호스트명으로 대시보드에 접속할 수 있습니다.

## 사전 요건
- `az` CLI 로그인(`az login`) + 대상 구독 선택(`az account set -s <sub>`)
- 기존 dah-soc AKS 접근 권한(또는 자기 AKS 좌표를 env 로 지정)
- Azure OpenAI 리소스 + 키

## 배포
1. `cp deploy/judge.env.example deploy/judge.env`
2. `deploy/judge.env` 의 `AZURE_OPENAI_*` 를 채움(도메인 없으면 `DOMAIN` 은 비워둠)
3. 실행:
   ```bash
   set -a; source deploy/judge.env; set +a
   ./deploy/scripts/deploy-soc.sh
   ```
4. 스크립트 마지막 줄의 `대시보드: http://<...>.cloudapp.azure.com/dashboard` 로 접속

## 도메인이 있는 경우
`deploy/judge.env` 에 `DOMAIN="soc.pollak.store"` 를 설정하고, 해당 도메인의 DNS A 레코드를
app-routing LB 공인 IP 로 지정하면 cert-manager 가 TLS 인증서를 자동 발급합니다
(`https://soc.pollak.store/dashboard`).

## 노출 범위(정직성)
- 외부 노출은 **대시보드만**(read-only replay). hotpath/learning/toolserver 는 ClusterIP 내부 전용.
- 도메인 없는 폴백은 **평문 HTTP**입니다(가짜 TLS 없음). 실도메인일 때만 HTTPS.
- 대시보드는 무인증(심사 공개용). write 엔드포인트/시크릿 노출 없음.
```

- [ ] **Step 3: 커밋**

```bash
git add deploy/judge.env.example deploy/JUDGE-DEPLOY.md
git commit -m "docs(deploy): judge deployment guide + env example"
```

---

## Task 16: .env.example 갱신 + 최종 게이트

**Files:**
- Modify: `.env.example`

- [ ] **Step 1: .env.example 항목 추가**

`.env.example` 대시보드 섹션(L117-123 부근)과 Azure 섹션에 추가:

```bash
# 대시보드 외부 노출 prefix (Ingress /dashboard 와 정합)
DASHBOARD_ROOT_PATH=/dashboard

# kagent 오케스트레이터 전용 Azure OpenAI (SOC 엔진 LLM 과 별개)
AZURE_OPENAI_ENDPOINT=
AZURE_OPENAI_DEPLOYMENT=gpt-4o-soc
AZURE_OPENAI_API_VERSION=2024-10-21

# 배포 도메인(비우면 Azure 기본 호스트명 폴백)
# DOMAIN=soc.pollak.store
```

- [ ] **Step 2: 전체 품질 게이트**

Run:
```bash
black . && ruff check . && mypy app/toolserver.py app/dashboard.py core/settings.py core/exceptions.py && pytest tests/__tests__/test_toolserver.py tests/__tests__/test_dashboard_prefix.py tests/__tests__/test_dashboard_app.py tests/__tests__/test_dashboard_static.py tests/__tests__/test_settings.py tests/__tests__/test_exceptions.py -q
```
Expected: black/ruff clean, mypy no errors, pytest all pass.

> mypy 가 mcp/starlette stub 관련 경고를 내면 해당 import 에 `# type: ignore[import-untyped]` 를 붙인다(프로젝트 컨벤션 준수).

- [ ] **Step 3: 전체 매니페스트 YAML 검증**

Run:
```bash
for f in deploy/k8s/*.yaml deploy/kagent/*.yaml; do python -c "import yaml,sys; list(yaml.safe_load_all(open('$f')))" && echo "$f ok" || echo "$f FAIL"; done
```
Expected: 전부 `ok`

- [ ] **Step 4: 커밋**

```bash
git add .env.example
git commit -m "docs(env): dashboard root_path + kagent azure openai + domain"
```

---

## 배포 검증 (구현 완료 후, 실 클러스터 접근 시)

계획 구현은 코드/매니페스트까지다. 실 배포 검증은 클러스터 접근 후:

- [ ] `az login` + `./deploy/scripts/deploy-soc.sh` (DOMAIN 미지정) → 폴백 호스트명 출력 확인
- [ ] `kubectl get pods -n dah-soc` → soc-dashboard/soc-toolserver Running
- [ ] `kubectl get crd | grep kagent` → CRD 버전 확인, `deploy/kagent/*.yaml` apiVersion 정합(미검증 가정 #3)
- [ ] 브라우저로 `http://<azure-hostname>/dashboard` → HTML/CSS/JS 로딩 + SSE(`/dashboard/events`) 동작(미검증 가정 #4: 자산 상대경로 정합)
- [ ] `kubectl exec` 로 toolserver → hotpath 왕복(analyze_alert) 스모크
- [ ] DOMAIN=soc.pollak.store 재배포 → cert-manager TLS 발급 확인

---

## Self-Review (작성자 체크 완료)

- **Spec 커버리지:** 오케스트레이터+MCP 래핑(T5,8,9,11,12) · 대시보드 /dashboard 노출(T2,3,7,8,13) · DOMAIN 파라미터+폴백(T13,14) · 기존 AKS 재사용(T14) · 무인증 read-only(T8,15) · 시크릿 imperative(T14) · 신규 Settings(T1) · 테스트/게이트(T16). 전 spec 섹션 대응 태스크 존재.
- **Placeholder:** 코드 스텝 전부 실제 내용. 미검증 가정 4개는 spec 명시분으로, 배포 검증 섹션에서 실증 — 계획 공백 아님.
- **타입 정합:** `create_app(snapshot_dir, root_path)` · `analyze_alert(alert: dict[str,object]) -> dict[str,object]` · `ToolServerError(SOCPlatformError)` · `dashboard_root_path`/`azure_openai_*` 필드명 태스크 간 일관.
