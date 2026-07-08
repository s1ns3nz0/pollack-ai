"""정책로더 공통 헬퍼 — graceful-degrade 보일러플레이트 단일화 + 버그류 근절."""

from pathlib import Path

from pydantic import BaseModel
import pytest

from core.exceptions import CoverageDataError, PolicyError, SOCPlatformError
from core.policy_loader import (
    load_policy_mapping,
    require_list,
    require_mapping,
    validate_models,
)


class _Item(BaseModel):
    id: str
    n: int = 0


class TestLoadPolicyMapping:
    def test_loads_dict(self, tmp_path: Path) -> None:
        p = tmp_path / "ok.yaml"
        p.write_text("a: 1\nb: 2\n", encoding="utf-8")
        assert load_policy_mapping(p, p, label="x") == {"a": 1, "b": 2}

    def test_missing_file_raises_policy(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyError):
            load_policy_mapping(None, tmp_path / "nope.yaml", label="x")

    def test_non_dict_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "list.yaml"
        p.write_text("- 1\n- 2\n", encoding="utf-8")
        with pytest.raises(PolicyError):
            load_policy_mapping(p, p, label="x")

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.yaml"
        p.write_text("a: [unclosed\n", encoding="utf-8")
        with pytest.raises(PolicyError):
            load_policy_mapping(p, p, label="x")

    def test_custom_error_cls(self, tmp_path: Path) -> None:
        """coverage 등 CoverageDataError 도 SOCPlatformError 하위(graph catch)."""
        with pytest.raises(CoverageDataError):
            load_policy_mapping(
                None, tmp_path / "nope.yaml", label="x", error_cls=CoverageDataError
            )


class TestRequireHelpers:
    def test_require_list_none_empty(self) -> None:
        assert require_list(None, label="x") == []

    def test_require_list_non_list_raises(self) -> None:
        with pytest.raises(PolicyError):
            require_list(5, label="x")

    def test_require_mapping_none_empty(self) -> None:
        assert require_mapping(None, label="x") == {}

    def test_require_mapping_non_dict_raises(self) -> None:
        with pytest.raises(PolicyError):
            require_mapping([1, 2], label="x")


class TestValidateModels:
    """버그류 근절 — 의미검증 실패를 SOCPlatformError 하위로 감쌈."""

    def test_validates_dicts(self) -> None:
        out = validate_models([{"id": "a", "n": 1}], _Item, label="x")
        assert out[0].id == "a" and out[0].n == 1

    def test_semantic_error_wrapped(self) -> None:
        """필드 타입 오류(n=문자열) → ValidationError 아닌 PolicyError."""
        with pytest.raises(PolicyError):
            validate_models([{"id": "a", "n": "notint"}], _Item, label="x")

    def test_wrapped_error_is_soc_platform(self) -> None:
        """graph 의 except SOCPlatformError 가 잡도록 하위 예외임을 보장."""
        try:
            validate_models([{"n": 1}], _Item, label="x")  # id 누락
        except SOCPlatformError:
            pass
        else:
            raise AssertionError("PolicyError(SOCPlatformError) 미발생")

    def test_skip_non_dict(self) -> None:
        out = validate_models([{"id": "a"}, "junk"], _Item, label="x")
        assert len(out) == 1

    def test_non_dict_strict_raises(self) -> None:
        with pytest.raises(PolicyError):
            validate_models(["junk"], _Item, label="x", skip_non_dict=False)

    def test_validator_typeerror_wrapped(self) -> None:
        """validator TypeError 도 PolicyError 로 봉인(pydantic v2 미포장, Codex #1)."""
        from pydantic import field_validator

        class _Strict(BaseModel):
            v: str

            @field_validator("v")
            @classmethod
            def _boom(cls, val: str) -> str:
                raise TypeError("raw type error")

        with pytest.raises(PolicyError):
            validate_models([{"v": "x"}], _Strict, label="x")


class TestMigratedLoadersStillWork:
    """마이그레이션된 로더들이 기본 정책으로 정상 로드(회귀)."""

    def test_all_default_loaders_load(self) -> None:
        from core.bas import BASRunner
        from core.campaign import CampaignChains
        from core.coa import CoaMatrix
        from core.monitoring import SLOMonitor
        from core.terrain import KeyTerrainMap
        from tools.coverage import CoverageMatrix

        assert BASRunner.from_yaml() is not None
        assert CampaignChains.from_yaml().count > 0
        assert CoaMatrix.from_yaml() is not None
        assert SLOMonitor.from_yaml().rule_count > 0
        assert KeyTerrainMap.from_yaml() is not None
        assert CoverageMatrix.from_yaml() is not None

    def test_malformed_item_degrades_not_crashes(self, tmp_path: Path) -> None:
        """마이그레이션 효과 실증 — 잘못된 항목이 든 정책 → PolicyError(크래시 아님)."""
        from core.campaign import CampaignChains

        p = tmp_path / "bad-campaign.yaml"
        # sequence 가 리스트여야 하는데 정수 → ValidationError → PolicyError 로 감싸짐
        p.write_text("chains:\n  - id: C1\n    sequence: 5\n", encoding="utf-8")
        with pytest.raises(PolicyError):
            CampaignChains.from_yaml(p)
