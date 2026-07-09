"""커버리지 매트릭스 — 적재·KPI 리포트·archetype 분류·인접추론(실 데이터 포함)."""

from pathlib import Path

import pytest

from core.exceptions import CoverageDataError
from tools.coverage import CoverageMatrix

_DATA = Path(__file__).resolve().parents[2] / "data" / "attack_coverage.yaml"

_SAMPLE = """
archetypes:
  A_pre_compromise: {name: "침해 이전", strategy: "scope 밖"}
  B_passive_collection: {name: "수동 수집", strategy: "센서 추가"}
tactics:
  - name: Recon
    order: 1
    covered: [T1595, T1592]
    planned: []
    uncovered:
      - {id: T1590, name: "Net Info", archetype: A_pre_compromise}
  - name: Collection
    order: 2
    covered: [T1185]
    planned: [T9999]
    uncovered:
      - {id: T1125, name: "Video Capture", archetype: B_passive_collection}
      - {id: T1074, name: "Data Staged", archetype: B_passive_collection}
"""


def _matrix(tmp_path: Path) -> CoverageMatrix:
    p = tmp_path / "cov.yaml"
    p.write_text(_SAMPLE, encoding="utf-8")
    return CoverageMatrix.from_yaml(p)


class TestLoadAndReport:
    def test_report_counts(self, tmp_path: Path) -> None:
        rep = _matrix(tmp_path).report()
        assert rep.covered == 3  # T1595,T1592,T1185
        assert rep.planned == 1
        assert rep.uncovered == 3  # T1590,T1125,T1074
        assert rep.total == 7

    def test_addressable_excludes_pre_compromise(self, tmp_path: Path) -> None:
        rep = _matrix(tmp_path).report()
        # 전체 coverage = 3/7; addressable 는 A 갭(T1590) 1개 제외 → 3/6.
        assert rep.coverage_pct == round(3 / 7, 3)
        assert rep.addressable_pct == round(3 / 6, 3)
        assert rep.addressable_pct > rep.coverage_pct

    def test_by_archetype(self, tmp_path: Path) -> None:
        rep = _matrix(tmp_path).report()
        assert rep.by_archetype["A_pre_compromise"] == 1
        assert rep.by_archetype["B_passive_collection"] == 2


class TestGapsAndArchetype:
    def test_gaps_resolve_strategy(self, tmp_path: Path) -> None:
        gaps = {g.id: g for g in _matrix(tmp_path).gaps()}
        assert gaps["T1125"].archetype == "B_passive_collection"
        assert gaps["T1125"].strategy == "센서 추가"  # archetype 에서 해석됨
        assert gaps["T1125"].tactic == "Collection"

    def test_gaps_by_archetype_groups(self, tmp_path: Path) -> None:
        grouped = _matrix(tmp_path).gaps_by_archetype()
        assert [g.id for g in grouped["B_passive_collection"]] == ["T1125", "T1074"]


class TestInferenceAnchors:
    def test_same_and_adjacent_covered(self, tmp_path: Path) -> None:
        anchors = _matrix(tmp_path).inference_anchors("T1125")
        assert anchors.tactic == "Collection"
        assert anchors.same_tactic_covered == ["T1185"]
        assert "T1595" in anchors.adjacent_covered  # 직전 전술(Recon) 형제
        assert "T1592" in anchors.adjacent_covered

    def test_unknown_technique_empty(self, tmp_path: Path) -> None:
        anchors = _matrix(tmp_path).inference_anchors("T0000")
        assert anchors.tactic == ""
        assert anchors.same_tactic_covered == []


class TestErrors:
    def test_bad_yaml_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.yaml"
        p.write_text("just a string", encoding="utf-8")
        with pytest.raises(CoverageDataError):
            CoverageMatrix.from_yaml(p)

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(CoverageDataError):
            CoverageMatrix.from_yaml(tmp_path / "nope.yaml")


class TestDataQuality:
    """data_quality(DeTT&CT) 소비 API — append-only, covered 판정과 분리."""

    def test_no_data_quality_section_loads_as_before(self, tmp_path: Path) -> None:
        # data_quality 키가 아예 없는 YAML(기존 _SAMPLE)도 그대로 로드된다.
        m = _matrix(tmp_path)
        assert m.data_quality == {}
        assert m.data_quality_for("T1595") is None

    def test_out_of_range_visibility_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "cov.yaml"
        p.write_text(
            _SAMPLE + "data_quality:\n  T1595: {visibility: 9}\n", encoding="utf-8"
        )
        with pytest.raises(CoverageDataError):
            CoverageMatrix.from_yaml(p)

    def test_out_of_range_detection_maturity_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "cov.yaml"
        p.write_text(
            _SAMPLE + "data_quality:\n  T1595: {detection_maturity: 99}\n",
            encoding="utf-8",
        )
        with pytest.raises(CoverageDataError):
            CoverageMatrix.from_yaml(p)

    def test_real_data_quality_examples_resolve(self) -> None:
        # PR #74 예시 3건(T0835/T1692.001/T1195) 조회.
        m = CoverageMatrix.from_yaml(_DATA)
        gnss = m.data_quality_for("T0835")
        assert (
            gnss is not None and gnss.visibility == 3 and gnss.detection_maturity == 3
        )
        cmd = m.data_quality_for("T1692.001")
        assert cmd is not None and cmd.log_source
        supply_chain = m.data_quality_for("T1195")
        assert supply_chain is not None and supply_chain.visibility == 1
        assert m.data_quality_for("T9999-not-scored") is None

    def test_report_unaffected_by_data_quality_presence(self, tmp_path: Path) -> None:
        # data_quality 유무가 covered/planned/uncovered 집계(KPI 분모/분자)를 안 바꾼다.
        without_dq = _matrix(tmp_path).report()
        p = tmp_path / "cov_with_dq.yaml"
        p.write_text(
            _SAMPLE
            + "data_quality:\n  T1595: {visibility: 2, detection_maturity: 1}\n",
            encoding="utf-8",
        )
        with_dq = CoverageMatrix.from_yaml(p).report()
        assert with_dq == without_dq


class TestRealData:
    """실제 data/attack_coverage.yaml 무결성 — 발표 수치의 근거."""

    def test_real_matrix_loads(self) -> None:
        m = CoverageMatrix.from_yaml(_DATA)
        assert len(m.tactics) == 15  # 15 전술 전부

    def test_real_gap_count_around_17(self) -> None:
        # 재동기화(10개) + 신규 룰 S127/S128/S129(T1119/T1560/T0882) 저작으로 30 -> 17.
        rep = CoverageMatrix.from_yaml(_DATA).report()
        assert 15 <= rep.uncovered <= 19
        assert rep.addressable_pct >= rep.coverage_pct

    def test_real_archetypes_present(self) -> None:
        grouped = CoverageMatrix.from_yaml(_DATA).gaps_by_archetype()
        # D_uninstrumented_exfil 은 재동기화로 갭 0(완전 해소) — 나머지 4개 archetype 은
        # 여전히 갭 보유.
        assert all(
            grouped.get(a)
            for a in (
                "A_pre_compromise",
                "B_passive_collection",
                "C_encrypted_c2",
                "E_destruction_prevention",
            )
        )
        assert grouped.get("D_uninstrumented_exfil") == []

    def test_staging_gap_has_adjacent_inference_anchor(self) -> None:
        # T1056(Input Capture, ❌) — 인접 단계(C2)의 탐지가능 형제로 추정.
        # T1074/T1119 는 재동기화·신규저작으로 covered 전환됨.
        m = CoverageMatrix.from_yaml(_DATA)
        anchors = m.inference_anchors("T1056")
        assert anchors.tactic == "Collection"
        assert "T1071" in anchors.adjacent_covered  # CommandAndControl(✅) 형제
