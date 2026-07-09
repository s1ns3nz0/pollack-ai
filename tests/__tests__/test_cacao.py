"""CACAO 2.0 대응 플레이북 카탈로그 — 스키마 정합·no-exec·임무게이트·source_ref 검증.

권고전용(command manual 만)·AST whitelist 조건(eval 금지)·NIST/ATT&CK 매핑을 검증한다.
Spec: docs/superpowers/specs/2026-07-09-cacao-playbooks-design.md
"""

from copy import deepcopy
from typing import Any

from pydantic import ValidationError
import pytest

from core.cacao import (
    CacaoPlaybook,
    CacaoStep,
    _load_matrix_raw,
    load_playbooks,
    resolve_playbook,
    validate_condition,
    validate_playbook,
)
from core.exceptions import PlaybookError

_TACTICS = {
    "InitialAccess",
    "Execution",
    "Persistence",
    "LateralMovement",
    "Collection",
    "CommandAndControl",
    "Exfiltration",
    "ImpairProcessControl",
    "InhibitResponseFunction",
    "Impact",
}


def _matrices() -> tuple[dict[str, Any], dict[str, Any]]:
    return _load_matrix_raw("coa-matrix.yaml"), _load_matrix_raw("recovery-matrix.yaml")


class TestCatalogLoad:
    def test_exemplars_load_and_validate(self) -> None:
        """10 전술 카탈로그 로드, 전술 키 일치."""
        pbs = load_playbooks()
        assert {p.tactic for p in pbs} == _TACTICS

    def test_ten_playbooks_all_validate(self) -> None:
        """10 플레이북 전수 validate_playbook 통과(스키마·no-exec·게이트·source_ref)."""
        coa, rec = _matrices()
        pbs = load_playbooks()
        assert len(pbs) == 10
        for pb in pbs:
            validate_playbook(pb, coa, rec)

    def test_cacao_conformance(self) -> None:
        """CACAO 필수필드·start/end·workflow_start→start."""
        for pb in load_playbooks():
            assert pb.type == "playbook" and pb.spec_version == "cacao-2.0"
            assert pb.created and pb.modified and pb.playbook_activities
            assert pb.workflow[pb.workflow_start].type == "start"
            assert any(s.type == "end" for s in pb.workflow.values())

    def test_workflow_refs_resolve(self) -> None:
        """모든 on_*/분기가 유효 step id."""
        for pb in load_playbooks():
            for step in pb.workflow.values():
                for nxt in (step.on_completion, step.on_true, step.on_false):
                    assert (not nxt) or nxt in pb.workflow

    def test_phase_coverage(self) -> None:
        """contain/eradicate/recover/adapt + recover 검증 step."""
        for pb in load_playbooks():
            phases = {
                s.labels.get("phase")
                for s in pb.workflow.values()
                if s.type == "action"
            }
            assert {"contain", "eradicate", "recover", "adapt"} <= phases
            assert any(
                s.labels.get("phase") == "recover" and s.labels.get("verify")
                for s in pb.workflow.values()
            )

    def test_ir_control_tagged(self) -> None:
        """실행 step 에 nist_ir 라벨."""
        for pb in load_playbooks():
            for s in pb.workflow.values():
                if s.type == "action":
                    assert "nist_ir" in s.labels

    def test_source_ref_resolves(self) -> None:
        """action.source_ref 가 실 coa/recovery 셀에 존재(adapt 제외)."""
        coa, rec = _matrices()
        from core.cacao import _resolve_source_ref

        for pb in load_playbooks():
            for s in pb.workflow.values():
                if s.type == "action" and s.labels.get("phase") != "adapt":
                    assert _resolve_source_ref(str(s.labels["source_ref"]), coa, rec)

    def test_tactic_key_matches_matrix(self) -> None:
        """tactic 키가 coa-matrix 키와 일치."""
        coa, _ = _matrices()
        for pb in load_playbooks():
            assert pb.tactic in coa


class TestMissionGateParser:
    def test_allowed_expression_passes(self) -> None:
        """허용 변수·연산 통과."""
        validate_condition(
            'mission_risk.score >= 6 or mission_risk.factors["civil_geo"] >= 1'
        )
        validate_condition("mission_risk.is_key_terrain and mission_risk.score > 3")

    def test_import_call_rejected(self) -> None:
        """함수호출·import → PlaybookError(eval 금지)."""
        with pytest.raises(PlaybookError):
            validate_condition('__import__("os").system("x")')
        with pytest.raises(PlaybookError):
            validate_condition("open('/etc/passwd')")

    def test_nested_path_rejected(self) -> None:
        """전체 경로 검증 — 중첩 잘못된 경로 거부(Codex diff M3)."""
        for bad in (
            "mission_risk.score.score >= 1",
            "mission_risk.factors.score >= 1",
            "mission_risk.is_key_terrain.score == 1",
        ):
            with pytest.raises(PlaybookError):
                validate_condition(bad)

    def test_constant_only_rejected(self) -> None:
        """상수-only(mission_risk 미참조) 게이트 거부(Codex diff M3)."""
        for bad in ("True", '"x" == "x"', "1 >= 0"):
            with pytest.raises(PlaybookError):
                validate_condition(bad)

    def test_unknown_variable_rejected(self) -> None:
        """미허용 이름/속성 → PlaybookError."""
        with pytest.raises(PlaybookError):
            validate_condition("secret >= 1")
        with pytest.raises(PlaybookError):
            validate_condition("mission_risk.__class__ >= 1")


class TestResolveWalk:
    def _pb(self, workflow: dict[str, CacaoStep], start: str) -> CacaoPlaybook:
        return CacaoPlaybook(
            type="playbook",
            spec_version="cacao-2.0",
            id="playbook--test",
            name="t",
            created="2026-07-09T00:00:00Z",
            modified="2026-07-09T00:00:00Z",
            tactic="Impact",
            workflow_start=start,
            workflow=workflow,
        )

    def test_missing_step_raises(self) -> None:
        """미해결 workflow step → PlaybookError(Codex diff M — 부분 plan 금지)."""
        pb = self._pb(
            {"start--1": CacaoStep(type="start", on_completion="gone--x")}, "start--1"
        )
        with pytest.raises(PlaybookError):
            resolve_playbook(pb, None)

    def test_loop_raises(self) -> None:
        """workflow 루프 → PlaybookError(폴백 유도)."""
        pb = self._pb(
            {
                "start--1": CacaoStep(type="start", on_completion="a--1"),
                "a--1": CacaoStep(type="action", on_completion="a--1"),
            },
            "start--1",
        )
        with pytest.raises(PlaybookError):
            resolve_playbook(pb, None)


class TestInvariants:
    def _base(self) -> dict[str, Any]:
        import yaml

        from core.cacao import _CATALOG

        raw = yaml.safe_load(_CATALOG.read_text(encoding="utf-8"))
        return deepcopy(raw["playbooks"][0])

    def test_no_exec_non_manual_rejected(self) -> None:
        """manual 아닌 command type → 모델 Literal 거부(구조적 no-exec 강제)."""
        item = self._base()
        item["workflow"]["action--contain"]["commands"][0]["type"] = "bash"
        with pytest.raises(Exception):  # noqa: B017 — pydantic ValidationError
            CacaoPlaybook.model_validate(item)

    def test_no_exec_extra_key_rejected(self) -> None:
        """command_b64 등 실행형 extra 키 → extra=forbid 거부."""
        item = self._base()
        item["workflow"]["action--contain"]["commands"][0]["command_b64"] = "ZWNobyB4"
        with pytest.raises(ValidationError):
            CacaoPlaybook.model_validate(item)

    def test_machine_agent_rejected(self) -> None:
        """machine agent type → Literal 거부."""
        item = self._base()
        item["agent_definitions"]["agent--analyst"]["type"] = "http-api"
        with pytest.raises(ValidationError):
            CacaoPlaybook.model_validate(item)

    def test_ir10_external_ref_rejected(self) -> None:
        """폐지된 IR-10 external_reference → PlaybookError."""
        item = self._base()
        item["external_references"].append(
            {"source_name": "nist-800-53", "external_id": "IR-10"}
        )
        coa, rec = _matrices()
        with pytest.raises(PlaybookError):
            validate_playbook(CacaoPlaybook.model_validate(item), coa, rec)

    def test_ir10_label_rejected(self) -> None:
        """폐지된 IR-10 을 nist_ir **라벨**로 우회 → PlaybookError(Codex diff M4)."""
        item = self._base()
        item["workflow"]["action--contain"]["labels"]["nist_ir"] = "IR-10"
        coa, rec = _matrices()
        with pytest.raises(PlaybookError):
            validate_playbook(CacaoPlaybook.model_validate(item), coa, rec)

    def test_non_https_url_rejected(self) -> None:
        """비-https external_reference url → PlaybookError."""
        item = self._base()
        item["external_references"][0]["url"] = "http://attack.mitre.org/x"
        coa, rec = _matrices()
        with pytest.raises(PlaybookError):
            validate_playbook(CacaoPlaybook.model_validate(item), coa, rec)

    def test_bad_source_ref_rejected(self) -> None:
        """존재 않는 source_ref → PlaybookError."""
        item = self._base()
        item["workflow"]["action--contain"]["labels"]["source_ref"] = "coa:Impact:Nope"
        coa, rec = _matrices()
        with pytest.raises(PlaybookError):
            validate_playbook(CacaoPlaybook.model_validate(item), coa, rec)

    def test_missing_mission_gate_rejected(self) -> None:
        """고-임팩트 전술에 mission_gate 없으면 PlaybookError."""
        item = self._base()
        item["workflow"]["if--mission-gate"]["labels"] = {}
        coa, rec = _matrices()
        with pytest.raises(PlaybookError):
            validate_playbook(CacaoPlaybook.model_validate(item), coa, rec)
