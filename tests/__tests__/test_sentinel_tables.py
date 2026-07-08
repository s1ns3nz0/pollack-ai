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
    for f in _DIR.glob("UAV*_CL.json"):  # 테이블 ARM 만(dcr.json 제외)
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


class TestDcr:
    """DCR ARM — 스트림 선언이 테이블과 1:1, dataFlows 일치."""

    def _dcr(self) -> dict:
        return json.loads((_DIR / "dcr.json").read_text(encoding="utf-8"))

    def test_streams_match_tables(self) -> None:
        props = self._dcr()["resources"][0]["properties"]
        streams = set(props["streamDeclarations"])
        assert streams == {f"Custom-{t}" for t in _EXPECTED}

    def test_dataflows_route_each_stream(self) -> None:
        props = self._dcr()["resources"][0]["properties"]
        flow_streams = {s for fl in props["dataFlows"] for s in fl["streams"]}
        assert flow_streams == set(props["streamDeclarations"])
        for fl in props["dataFlows"]:
            assert fl["destinations"] == ["dah"]

    def test_stream_columns_match_table_schema(self) -> None:
        # DCR 스트림 컬럼 == 테이블 ARM 컬럼(단일 진실).
        props = self._dcr()["resources"][0]["properties"]
        for name in _EXPECTED:
            tbl_cols = _arms()[name]["resources"][0]["properties"]["schema"]["columns"]
            dcr_cols = props["streamDeclarations"][f"Custom-{name}"]["columns"]
            assert dcr_cols == tbl_cols


class TestDeployScript:
    def test_script_exists_with_shebang(self) -> None:
        sh = (_DIR / "deploy.sh").read_text(encoding="utf-8")
        assert sh.startswith("#!/usr/bin/env bash")
        assert "az deployment group create" in sh
        assert "data-collection endpoint create" in sh
        assert "data-collection rule" in sh
