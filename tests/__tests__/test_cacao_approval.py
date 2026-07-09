"""ApprovalAgent CACAO 보수분기 HITL 강제 — resolve 를 approval 에서 게이트.

interrupt 자체는 그래프 통합(test_soc_agents)이 커버. 여기선 게이트 판정 로직 +
자동승인 경로. Spec: docs/superpowers/specs/2026-07-09-cacao-approval-hitl-design.md
"""

import pytest

from agents.approval_agent import ApprovalAgent
from core.cacao import CacaoPlaybook, CacaoStep, load_playbooks, playbook_requires_hitl
from core.models import Alert, MissionRisk, Severity, SOCState, Verdict
from core.runbook import (
    Runbook,
    RunbookApproval,
    RunbookCatalog,
    RunbookStep,
    VerificationStep,
)
from core.settings import Settings

_CATALOG = load_playbooks()
_MAP = {"S-IMP": "Impact", "S-DISC": "Discovery"}


def _agent(*, wired: bool = True) -> ApprovalAgent:
    return ApprovalAgent(
        Settings(),
        hitl_force_threshold=6,
        playbooks=_CATALOG if wired else None,
        scenario_tactic=_MAP if wired else None,
    )


def _manual_runbook(*, approval_required: bool) -> RunbookCatalog:
    return RunbookCatalog.from_runbooks(
        [
            Runbook(
                id="RB-S-DISC",
                scenario_id="S-DISC",
                detection_rule="S_Disc.json",
                playbook_id="playbook--uav-disc-0001",
                tactic="Discovery",
                operator_steps=[
                    RunbookStep(
                        id="validate_detection",
                        kind="manual",
                        action="탐지 근거 확인",
                    )
                ],
                approval=RunbookApproval(required=approval_required),
                verification=VerificationStep(
                    method="outcome_probe",
                    expected="no_reoccurred",
                ),
            )
        ]
    )


def _state(scenario: str, mr: MissionRisk | None) -> SOCState:
    state: SOCState = {
        "alert": Alert(
            id="A", scenario_id=scenario, title="t", severity_baseline=Severity.LOW
        ),
        "severity": Severity.LOW,
        "verdict": Verdict.TRUE_POSITIVE,
    }
    if mr is not None:
        state["mission_risk"] = mr
    return state


class TestCacaoApprovalGate:
    def test_none_mission_forces_hitl(self) -> None:
        """mission_risk 부재 + Impact 전술 → 보수분기 → HITL 강제(fail-safe)."""
        assert _agent()._cacao_forces_hitl(_state("S-IMP", None)) is True

    def test_low_mission_auto_branch_no_force(self) -> None:
        """低 임무위험(auto 분기) → CACAO 게이트 미발동."""
        agent = _agent()
        assert (
            agent._cacao_forces_hitl(_state("S-IMP", MissionRisk(score=2, factors={})))
            is False
        )

    def test_uncovered_tactic_no_force(self) -> None:
        """Discovery 는 mission-gate 없는 CACAO 경로라 HITL 강제 없음."""
        assert _agent()._cacao_forces_hitl(_state("S-DISC", None)) is False

    def test_runbook_approval_required_forces_hitl(self) -> None:
        """Runbook approval.required=true 이면 저위험 Discovery 도 HITL 강제."""
        agent = ApprovalAgent(
            Settings(),
            hitl_force_threshold=6,
            playbooks=_CATALOG,
            scenario_tactic=_MAP,
            runbooks=_manual_runbook(approval_required=True),
        )

        assert agent._runbook_forces_hitl(_state("S-DISC", MissionRisk(score=1)))

    def test_no_catalog_no_force(self) -> None:
        """카탈로그 미주입 → CACAO 게이트 없음(회귀 안전)."""
        assert _agent(wired=False)._cacao_forces_hitl(_state("S-IMP", None)) is False

    @pytest.mark.asyncio
    async def test_low_all_gates_auto_approves(self) -> None:
        """severity<h + 低임무 + auto분기 → 자동승인(무인터럽트)."""
        out = await _agent().run(_state("S-IMP", MissionRisk(score=2, factors={})))
        assert out["approval"].required is False


class TestPlaybookRequiresHitl:
    def test_malformed_playbook_fails_safe_true(self) -> None:
        """malformed 워크(루프) → True(불명=인간, fail-safe)."""
        pb = CacaoPlaybook(
            type="playbook",
            spec_version="cacao-2.0",
            id="playbook--loop",
            name="t",
            created="2026-07-09T00:00:00Z",
            modified="2026-07-09T00:00:00Z",
            tactic="Impact",
            workflow_start="a--1",
            workflow={"a--1": CacaoStep(type="action", on_completion="a--1")},
        )
        assert playbook_requires_hitl(pb, None) is True
