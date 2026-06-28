"""Sentinel 커스텀 테이블 ARM — 구조·컬럼·TimeGenerated·명명 검증."""

import json
from pathlib import Path

import pytest

_DIR = Path(__file__).resolve().parents[2] / "deploy" / "sentinel-tables"
_EXPECTED = {
    "UAVGcsAccess_CL",
    "UAVRouterStats_CL",
    "UAVImagery_CL",
    "UAVFileAudit_CL",
}


def _arms() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in _DIR.glob("*.json"):
        out[f.stem] = json.loads(f.read_text(encoding="utf-8"))
    return out


class TestTableArm:
    def test_all_expected_tables_present(self) -> None:
        assert set(_arms()) == _EXPECTED

    @pytest.mark.parametrize("name", sorted(_EXPECTED))
    def test_arm_structure(self, name: str) -> None:
        arm = _arms()[name]
        res = arm["resources"][0]
        assert res["type"] == "Microsoft.OperationalInsights/workspaces/tables"
        schema = res["properties"]["schema"]
        assert schema["name"] == name  # 테이블명 = _CL 접미

    @pytest.mark.parametrize("name", sorted(_EXPECTED))
    def test_has_timegenerated(self, name: str) -> None:
        cols = _arms()[name]["resources"][0]["properties"]["schema"]["columns"]
        names = {c["name"] for c in cols}
        assert "TimeGenerated" in names  # LA 필수 컬럼
        assert len(cols) >= 5

    @pytest.mark.parametrize("name", sorted(_EXPECTED))
    def test_column_types_valid(self, name: str) -> None:
        valid = {"string", "int", "long", "real", "datetime", "boolean", "dynamic"}
        cols = _arms()[name]["resources"][0]["properties"]["schema"]["columns"]
        for c in cols:
            assert c["type"] in valid, f"{name}.{c['name']} 타입 {c['type']}"

    def test_name_uses_workspace_param(self) -> None:
        for name, arm in _arms().items():
            res_name = arm["resources"][0]["name"]
            assert "parameters('workspaceName')" in res_name
            assert name in res_name
