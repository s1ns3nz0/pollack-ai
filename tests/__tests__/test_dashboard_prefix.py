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
