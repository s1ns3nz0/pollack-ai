"""bas-scenarios.yaml 자동 추출기 — MaGMA UCF status 병합 로직(deprecated 보존/orphan 캐리포워드)."""

from pathlib import Path

from scripts.gen_bas_scenarios import merge_with_existing, render_yaml


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "existing.yaml"
    p.write_text(text, encoding="utf-8")
    return p


class TestMergeWithExisting:
    def test_no_existing_file_returns_as_is(self, tmp_path: Path) -> None:
        entries = [{"id": "S1-X", "status": "deployed"}]
        merged = merge_with_existing(entries, tmp_path / "nope.yaml")
        assert merged == entries

    def test_deprecated_status_is_preserved_across_rescan(self, tmp_path: Path) -> None:
        existing = _write(
            tmp_path,
            """
scenarios:
  - id: S1-GNSS-SPOOFING
    name: old
    status: deprecated
    signals: [x]
    detection_rule: S1_GNSS_Spoofing.json
    tactic: Collection
    stride: [S]
""",
        )
        new_entries = [
            {
                "id": "S1-GNSS-SPOOFING",
                "name": "new",
                "status": "deployed",
                "signals": ["z"],
                "detection_rule": "S1_GNSS_Spoofing.json",
                "tactic": "Collection",
                "stride": ["S"],
                "campaign": [],
            }
        ]
        merged = merge_with_existing(new_entries, existing)
        assert len(merged) == 1
        assert merged[0]["status"] == "deprecated"

    def test_non_deprecated_status_not_preserved(self, tmp_path: Path) -> None:
        # planned 이었던 항목에 실제 파일이 생기면 재스캔된 deployed 로 자연스럽게 전환.
        existing = _write(
            tmp_path,
            """
scenarios:
  - id: S1-GNSS-SPOOFING
    name: old
    status: planned
    signals: [x]
    detection_rule: ""
    tactic: Collection
    stride: [S]
""",
        )
        new_entries = [
            {
                "id": "S1-GNSS-SPOOFING",
                "name": "new",
                "status": "deployed",
                "signals": ["z"],
                "detection_rule": "S1_GNSS_Spoofing.json",
                "tactic": "Collection",
                "stride": ["S"],
                "campaign": [],
            }
        ]
        merged = merge_with_existing(new_entries, existing)
        assert merged[0]["status"] == "deployed"

    def test_orphaned_entry_carried_forward(self, tmp_path: Path) -> None:
        # 소스 JSON이 사라진 기존 항목은 삭제되지 않고 마지막 상태로 유지된다.
        existing = _write(
            tmp_path,
            """
scenarios:
  - id: S200-ORPHANED-SCENARIO
    name: 삭제된 시나리오
    status: deprecated
    signals: [y]
    detection_rule: S200_Old.json
    tactic: Impact
    stride: [T]
""",
        )
        merged = merge_with_existing([], existing)
        assert len(merged) == 1
        assert merged[0]["id"] == "S200-ORPHANED-SCENARIO"
        assert merged[0]["status"] == "deprecated"


class TestRenderYaml:
    def test_status_field_rendered_and_sorted_by_number(self) -> None:
        entries = [
            {
                "id": "S2-B",
                "name": "b",
                "status": "deployed",
                "signals": ["s"],
                "detection_rule": "S2_B.json",
                "tactic": "Impact",
                "stride": ["T"],
                "campaign": [],
            },
            {
                "id": "S1-A",
                "name": "a",
                "status": "planned",
                "signals": ["s"],
                "detection_rule": "",
                "tactic": "Collection",
                "stride": ["S"],
                "campaign": [],
            },
        ]
        out = render_yaml(entries)
        assert out.index("S1-A") < out.index("S2-B")  # 번호순 정렬
        assert "status: planned" in out
        assert "status: deployed" in out
        assert 'detection_rule: ""' in out  # 빈 문자열은 따옴표로 렌더
