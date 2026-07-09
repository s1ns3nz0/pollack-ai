"""Runbook 정책 계약 — detection rule 단위 실행 절차 커버리지."""

import pytest

from core.bas import BASRunner
from core.cacao import load_playbooks, scenario_tactic_map
from core.exceptions import PolicyError
from core.runbook import RunbookCatalog, load_runbooks, validate_runbook_catalog


def test_all_detection_scenarios_have_valid_runbooks() -> None:
    """detection_rule 이 있는 BAS 시나리오는 모두 manual-only runbook 을 가진다."""
    scenarios = BASRunner.from_yaml()._scenarios
    runbooks = load_runbooks()

    validate_runbook_catalog(
        runbooks=runbooks,
        scenarios=scenarios,
        playbooks=load_playbooks(),
        scenario_tactic=scenario_tactic_map(),
    )

    detection_scenario_ids = {s.id for s in scenarios if s.detection_rule}
    assert {rb.scenario_id for rb in runbooks} == detection_scenario_ids


def test_runbook_readiness_separates_generated_scaffolds() -> None:
    """generated runbook 은 존재 커버리지와 curated readiness 에서 분리한다."""
    catalog = load_runbooks()
    summary = catalog.readiness_summary()

    assert summary.total == 131
    assert summary.generated > summary.curated
    assert summary.generated == 121
    assert summary.curated == 10
    assert summary.readiness_ratio == round(summary.curated / summary.total, 3)
    assert summary.generated_backlog[:3]


def test_generated_runbook_backlog_has_stable_scenario_ids() -> None:
    """generated scaffold 는 우선순위 가능한 backlog 로 추적한다."""
    catalog = load_runbooks()
    summary = catalog.readiness_summary()

    assert "S10-BARO-SPOOFING" in summary.generated_backlog
    assert "S1-GNSS-SPOOFING" not in summary.generated_backlog
    assert summary.generated_backlog == sorted(summary.generated_backlog)


def test_runbook_lookup_returns_scenario_specific_contract() -> None:
    """S69 CredentialAccess 는 자격접근 CACAO 플레이북과 수동 절차로 연결된다."""
    catalog = load_runbooks()
    runbook = catalog.by_scenario("S69-VAULT-SECRET-THEFT")

    assert runbook is not None
    assert runbook.id == "RB-S69-VAULT-SECRET-THEFT"
    assert runbook.playbook_id == "playbook--uav-cred-0001"
    assert runbook.operator_steps
    assert {step.kind for step in runbook.operator_steps} == {"manual"}
    assert runbook.verification.method == "outcome_probe"


def test_runbook_playbook_id_must_match_selected_tactic_playbook() -> None:
    """tactic 에 맞지 않는 기존 playbook_id 를 쓰면 정책 검증이 실패한다."""
    scenarios = BASRunner.from_yaml()._scenarios
    catalog = load_runbooks()
    runbooks = list(catalog)
    first = runbooks[0]
    tampered = first.model_copy(update={"playbook_id": "playbook--uav-impact-0001"})
    broken = RunbookCatalog.from_runbooks([tampered, *runbooks[1:]])

    with pytest.raises(PolicyError, match="playbook_id 불일치"):
        validate_runbook_catalog(
            runbooks=broken,
            scenarios=scenarios,
            playbooks=load_playbooks(),
            scenario_tactic=scenario_tactic_map(),
        )
