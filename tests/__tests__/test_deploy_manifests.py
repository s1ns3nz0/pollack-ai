"""배포 매니페스트 정합성 — 유효 YAML·필수 리소스·시크릿 안전·이미지 일관성."""

from pathlib import Path

import yaml

_K8S = Path(__file__).resolve().parents[2] / "deploy" / "k8s"


def _all_docs() -> list[dict]:
    docs: list[dict] = []
    for f in sorted(_K8S.glob("*.yaml")):
        for d in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if isinstance(d, dict):
                docs.append(d)
    return docs


class TestManifests:
    def test_all_yaml_parses(self) -> None:
        docs = _all_docs()
        assert len(docs) >= 8  # ns/cm/secret/sts/svc/deployA/svc/deployB/hpa/...

    def test_required_kinds_present(self) -> None:
        kinds = [d.get("kind") for d in _all_docs()]
        for required in (
            "Namespace",
            "ConfigMap",
            "Secret",
            "StatefulSet",
            "Deployment",
            "Service",
            "HorizontalPodAutoscaler",
        ):
            assert required in kinds, f"{required} 누락"

    def test_two_soc_deployments(self) -> None:
        deploys = [
            d["metadata"]["name"] for d in _all_docs() if d.get("kind") == "Deployment"
        ]
        assert "soc-hotpath" in deploys
        assert "soc-learning" in deploys

    def test_hotpath_single_replica(self) -> None:
        dep = next(
            d
            for d in _all_docs()
            if d.get("kind") == "Deployment" and d["metadata"]["name"] == "soc-hotpath"
        )
        assert dep["spec"]["replicas"] == 1  # 상태 보유 → 단일 레플리카

    def test_all_in_namespace(self) -> None:
        for d in _all_docs():
            if d.get("kind") == "Namespace":
                continue
            assert d["metadata"].get("namespace") == "dah-soc"

    def test_secret_has_no_real_values(self) -> None:
        secret = next(d for d in _all_docs() if d.get("kind") == "Secret")
        for key, val in secret.get("stringData", {}).items():
            assert val == "REPLACE_ME", f"{key} 가 자리표시자가 아님(평문 의심)"

    def test_images_consistent(self) -> None:
        images = set()
        for d in _all_docs():
            if d.get("kind") != "Deployment":
                continue
            for c in d["spec"]["template"]["spec"]["containers"]:
                images.add(c["image"])
        # A/B 는 동일 이미지에서 command 로 분기.
        assert len(images) == 1
