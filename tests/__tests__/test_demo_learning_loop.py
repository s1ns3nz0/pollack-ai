"""예선 데모 E2E — 관측→PB 효과학습→다음 대응/리포트 반영."""

from __future__ import annotations

import pytest

from agents.outcome_probe_agent import OutcomeProbeAgent
from agents.report_agent import ReportAgent
from agents.response_agent import ResponseAgent
from core.actors import ActorReadGate, ActorWriteGate, InMemoryActorStore
from core.cacao import load_playbooks
from core.models import (
    Alert,
    JudgeFeatures,
    MissionRisk,
    Severity,
    SOCState,
    Verdict,
)
from core.outcome import InMemoryObservationSource, Observation, ProbeEngine
from core.playbook_outcome import ActorPlaybookOutcomeGate
from core.settings import Settings
from core.severity import SeverityEngine


def _judge_features() -> JudgeFeatures:
    return JudgeFeatures(
        has_signal=True,
        has_rule=True,
        corroborated=True,
        confidence=0.9,
    )


def _alert() -> Alert:
    return Alert(
        id="demo-followup",
        scenario_id="S-IMP",
        title="데모 후속 대응",
        severity_baseline=Severity.HIGH,
        defense_playbook={"id": "PB-FALLBACK", "actions": ["기존 조치"]},
        signals=["gps_drift", "mission_effect"],
        expected_detection={"sigma_rule": "uav_gps_spoof_residual.yml"},
        mitre={"tactics": ["Impact"], "techniques": ["T0831"]},
        actor_id="team-red",
    )


@pytest.mark.asyncio
async def test_demo_observation_teaches_next_response_and_report() -> None:
    """OutcomeProbe 학습 결과가 다음 response note 와 report flags 에 노출된다."""
    settings = Settings()
    engine = SeverityEngine()
    actor_store = InMemoryActorStore()
    actor_read = ActorReadGate(actor_store)
    source = InMemoryObservationSource()
    playbook_id = "playbook--uav-impact-0001"
    source.push(
        Observation(
            alert_id="demo-first",
            scenario_id="S-IMP",
            actor_id="team-red",
            playbook_id=playbook_id,
            mission_effect_observed=True,
            ts="2026-07-09T00:00:00Z",
            alert_signals=["gps_drift", "mission_effect"],
            alert_severity=Severity.HIGH,
            alert_verdict=Verdict.TRUE_POSITIVE,
            alert_mitre={"tactics": ["Impact"], "techniques": ["T0831"]},
            asset_id="UAV-01",
            asset_tier="T1",
            judge_features=_judge_features(),
        )
    )
    probe = OutcomeProbeAgent(
        settings,
        source,
        ProbeEngine(),
        actor_gate=ActorWriteGate(actor_store),
        pb_gate=ActorPlaybookOutcomeGate(actor_store),
    )

    worker_report = await probe.run()
    response_out = await ResponseAgent(
        settings,
        engine,
        playbooks=load_playbooks(),
        scenario_tactic={"S-IMP": "Impact"},
        actor_read=actor_read,
    ).run(
        {
            "alert": _alert(),
            "severity": Severity.HIGH,
            "verdict": Verdict.TRUE_POSITIVE,
            "mission_risk": MissionRisk(score=2, factors={}),
        }
    )
    report_out: SOCState = await ReportAgent(
        settings,
        engine,
        actor_read=actor_read,
    ).run(
        {
            "alert": _alert(),
            "severity": Severity.HIGH,
            "verdict": Verdict.TRUE_POSITIVE,
        }
    )

    assert worker_report.auto_applied == 2
    assert f"PB 효과 {playbook_id}=0.30(1)" in (
        response_out["response"].mission_risk_note or ""
    )
    assert any(
        f"PB 효과 top-3: {playbook_id}=0.30(1)" in flag
        for flag in report_out["report"].guardrail_flags
    )
