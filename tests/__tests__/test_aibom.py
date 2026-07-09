"""AIBOM — AI 공급망 거버넌스 검증(미등록/소스/pinned/버전/무결성/coverage)."""

from core.aibom import (
    AibomInventory,
    AIBOMVerifier,
    ApprovedAibom,
    _is_unpinned,
    expected_component_types,
)
from core.models import AibomComponent


def _approved() -> ApprovedAibom:
    return ApprovedAibom(
        {
            "m1": {"version": "1.0", "digest": "abc", "source": "reg-ok"},
            "m2": {"version": "2.0", "digest": "", "source": "reg-ok"},
        }
    )


def _c(**kw: object) -> AibomComponent:
    base: dict[str, object] = {"name": "m1", "component_type": "chat_llm"}
    base.update(kw)
    return AibomComponent.model_validate(base)


def _issues(comps: list[AibomComponent], expected: set[str] | None = None) -> set[str]:
    return {
        f.issue for f in AIBOMVerifier(_approved()).verify(comps, expected or set())
    }


class TestVerify:
    def test_clean(self) -> None:
        c = _c(version="1.0", digest="abc", source="reg-ok")
        assert _issues([c]) == set()

    def test_unregistered_stops(self) -> None:
        c = _c(name="shadow", version="latest", source="evil")
        # 미등록이면 stop — 다른 이슈(unpinned/source) 미발생.
        assert _issues([c]) == {"unregistered"}

    def test_untrusted_source(self) -> None:
        assert "untrusted_source" in _issues([_c(version="1.0", source="evil")])

    def test_unpinned(self) -> None:
        assert "unpinned" in _issues([_c(version="latest", source="reg-ok")])

    def test_version_mismatch(self) -> None:
        assert "version_mismatch" in _issues([_c(version="9.9", source="reg-ok")])

    def test_tampered_both_digests(self) -> None:
        c = _c(version="1.0", digest="ZZZ", source="reg-ok")
        assert "tampered" in _issues([c])

    def test_integrity_unverifiable_missing_digest(self) -> None:
        """승인 digest 존재 + 관측 부재 → integrity_unverifiable(tampered 아님)."""
        c = _c(version="1.0", digest="", source="reg-ok")
        iss = _issues([c])
        assert "integrity_unverifiable" in iss and "tampered" not in iss

    def test_no_digest_either_side_no_noise(self) -> None:
        """m2 는 승인 digest 공란 → 무결성 검사 스킵(노이즈 없음)."""
        c = _c(name="m2", version="2.0", source="reg-ok")
        assert _issues([c]) == set()


class TestCoverageGap:
    def test_expected_missing(self) -> None:
        # chat_llm 선언, ragas 기대되나 미선언 → coverage_gap.
        c = _c(name="m1", component_type="chat_llm", version="1.0", source="reg-ok")
        iss = _issues([c], {"chat_llm", "ragas"})
        assert "coverage_gap" in iss

    def test_all_covered(self) -> None:
        c = _c(name="m1", component_type="chat_llm", version="1.0", source="reg-ok")
        assert "coverage_gap" not in _issues([c], {"chat_llm"})


class TestUnpinned:
    def test_mutable_tags(self) -> None:
        for v in ("", "latest", "main", "stable", "x:latest"):
            assert _is_unpinned(v)

    def test_pinned(self) -> None:
        assert not _is_unpinned("1.2.3")
        assert not _is_unpinned("qwen2.5:14b")


class TestLoaders:
    def test_manifest_loads(self) -> None:
        comps = AibomInventory.from_manifest()
        assert comps and all(c.name for c in comps)
        assert {"chat_llm", "embedding", "ragas"} <= {c.component_type for c in comps}

    def test_approved_loads(self) -> None:
        assert ApprovedAibom.from_yaml().approved("qwen2.5:14b") is not None

    def test_default_stack_clean(self) -> None:
        """기본 매니페스트 ↔ 승인목록 정합(위반 0)."""
        approved = ApprovedAibom.from_yaml()
        comps = AibomInventory.from_manifest()
        assert AIBOMVerifier(approved).verify(comps, {"chat_llm"}) == []

    def test_manifest_missing_graceful(self) -> None:
        import pytest

        from core.exceptions import PolicyError

        with pytest.raises(PolicyError):
            AibomInventory.from_manifest("/tmp/__no_aibom__.yaml")


class TestExpectedTypes:
    def test_chat_llm_always(self) -> None:
        from core.settings import Settings

        assert "chat_llm" in expected_component_types(Settings())

    def test_ragflow_default_expects_embedding(self) -> None:
        """기본 ragflow_base_url 설정 → ragflow+embedding 기대(M-a)."""
        from core.settings import Settings

        exp = expected_component_types(Settings())
        assert {"ragflow", "embedding"} <= exp

    def test_graphrag_when_enabled(self) -> None:
        from core.settings import Settings

        assert "graphrag" in expected_component_types(Settings(graph_rag_enabled=True))

    def test_default_settings_stack_clean(self) -> None:
        """실제 기본 설정 → 기본 매니페스트 정합(coverage_gap 없음)."""
        from core.settings import Settings

        approved = ApprovedAibom.from_yaml()
        comps = AibomInventory.from_manifest()
        exp = expected_component_types(Settings())
        assert AIBOMVerifier(approved).verify(comps, exp) == []


class TestDatasetLineage:
    """RAG corpus(dataset) 실행값 관측 — poisoning 공급망 거버넌스."""

    def test_default_no_dataset(self) -> None:
        from core.aibom import settings_datasets
        from core.settings import Settings

        assert settings_datasets(Settings()) == []
        assert "dataset" not in expected_component_types(Settings())

    def test_configured_dataset_observed(self) -> None:
        from core.aibom import settings_datasets
        from core.settings import Settings

        s = Settings(ragflow_dataset_id="kb-prod-01")
        comps = settings_datasets(s)
        assert [c.name for c in comps] == ["kb-prod-01"]
        assert comps[0].component_type == "dataset"
        assert "dataset" in expected_component_types(s)

    def test_shadow_dataset_unregistered(self) -> None:
        from core.aibom import settings_datasets
        from core.settings import Settings

        s = Settings(ragflow_dataset_id="shadow-kb")
        exp = expected_component_types(s)
        comps = AibomInventory.from_manifest() + settings_datasets(s)
        f = AIBOMVerifier(ApprovedAibom.from_yaml()).verify(comps, exp)
        assert any(x.component == "shadow-kb" and x.issue == "unregistered" for x in f)

    def test_dataset_authoritative_no_manifest_duplicate(self) -> None:
        """Codex Low — dataset 은 settings 만 authoritative(매니페스트 dataset 제외)."""
        from agents.report_agent import _load_aibom_findings
        from core.settings import Settings

        # 기본(dataset_id 빈값): dataset 컴포넌트 0 → dataset findings 없음.
        out = _load_aibom_findings(Settings())
        assert not any(f.component_type == "dataset" for f in out)


class TestPolicyDegraded:
    def test_clean_default(self) -> None:
        from agents.report_agent import _load_aibom_findings
        from app.metrics import metrics
        from core.settings import Settings

        before = metrics().aibom_violation_total
        assert _load_aibom_findings(Settings()) == []
        assert metrics().aibom_violation_total == before  # 정상 → 불변

    def test_policy_unavailable_observable(self, monkeypatch: object) -> None:
        """M-b — 정책 로드 실패는 침묵 [] 아니라 관측가능 finding + metric."""
        import agents.report_agent as ra
        from app.metrics import metrics
        from core.exceptions import PolicyError
        from core.settings import Settings

        def _boom(*_a: object, **_k: object) -> ApprovedAibom:
            raise PolicyError("정책 손상")

        monkeypatch.setattr(ra.ApprovedAibom, "from_yaml", _boom)  # type: ignore[attr-defined]
        before = metrics().aibom_violation_total
        out = ra._load_aibom_findings(Settings())
        assert len(out) == 1 and out[0].issue == "policy_unavailable"
        assert metrics().aibom_violation_total == before + 1  # 관측됨
