"""ArgoCD GitOps 매니페스트 정합성 — AppProject·Application·자동동기화·repo 일관성."""

from pathlib import Path

import yaml

_ARGOCD = Path(__file__).resolve().parents[2] / "deploy" / "argocd"
_REPO = "https://github.com/s1ns3nz0/pollack-ai.git"


def _docs() -> list[dict]:
    out: list[dict] = []
    for f in sorted(_ARGOCD.rglob("*.yaml")):
        for d in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if isinstance(d, dict):
                out.append(d)
    return out


class TestArgoManifests:
    def test_has_project_and_applications(self) -> None:
        kinds = [d.get("kind") for d in _docs()]
        assert "AppProject" in kinds
        assert kinds.count("Application") >= 2  # root + soc

    def test_git_apps_reference_same_repo(self) -> None:
        for d in _docs():
            if d.get("kind") != "Application":
                continue
            src = d["spec"]["source"]
            if "path" not in src:  # helm 차트 앱은 외부 repo → 제외
                continue
            assert src["repoURL"] == _REPO

    def test_workloads_app_syncs_k8s_path(self) -> None:
        app = next(
            d
            for d in _docs()
            if d.get("kind") == "Application"
            and d["metadata"]["name"] == "dah-soc-workloads"
        )
        assert app["spec"]["source"]["path"] == "deploy/k8s"
        assert app["spec"]["destination"]["namespace"] == "dah-soc"

    def test_automated_sync_enabled(self) -> None:
        for d in _docs():
            if d.get("kind") != "Application":
                continue
            assert "automated" in d["spec"]["syncPolicy"]

    def test_secret_example_excluded(self) -> None:
        app = next(
            d
            for d in _docs()
            if d.get("kind") == "Application"
            and d["metadata"]["name"] == "dah-soc-workloads"
        )
        assert "secret" in app["spec"]["source"]["directory"]["exclude"]

    def test_project_restricts_repo(self) -> None:
        proj = next(d for d in _docs() if d.get("kind") == "AppProject")
        assert _REPO in proj["spec"]["sourceRepos"]
