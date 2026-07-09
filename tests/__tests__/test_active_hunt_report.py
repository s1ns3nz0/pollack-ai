"""Active hunt report exposure tests."""

from __future__ import annotations

from agents.report_agent import ReportAgent
from core.models import (
    ActiveHuntFinding,
    Alert,
    InvestigationResult,
    Severity,
    Verdict,
)
from core.settings import Settings
from core.severity import SeverityEngine


def _alert() -> Alert:
    return Alert(
        id="a1",
        scenario_id="S2-C2-HIJACK",
        title="C2 hijack",
        asset_id="UAV-1",
        asset_tier="T2-Important",
        mission_phase="ISR",
        severity_baseline="m",
        mitre={"techniques": ["T1071"], "tactics": ["CommandAndControl"]},
        signals=["지상국 미발신 명령 수신"],
        iocs=[],
        cves=[],
        sbom_components=[],
    )


async def test_report_includes_active_hunt_findings() -> None:
    finding = ActiveHuntFinding(
        direction="backward",
        technique="T1133",
        tactic="InitialAccess",
        query_id="T1133_external_remote_service",
        matched=True,
        row_count=2,
        rationale="이전 침투 흔적 확인",
    )
    agent = ReportAgent(Settings(), SeverityEngine())
    out = await agent.run(
        {
            "alert": _alert(),
            "severity": Severity.HIGH,
            "verdict": Verdict.TRUE_POSITIVE,
            "investigation": InvestigationResult(confidence=0.7),
            "active_hunt_findings": [finding],
            "guardrail_flags": [],
            "node_timings": [],
        }
    )

    report = out["report"]
    assert report.active_hunt_findings == [finding]
    assert any("active hunt matched" in flag for flag in report.guardrail_flags)
    assert any("active hunt" in fact for fact in report.commander_brief.key_facts)


def test_oscal_evidence_includes_active_hunt_findings() -> None:
    finding = ActiveHuntFinding(
        direction="forward",
        technique="T1071",
        tactic="CommandAndControl",
        query_id="T1071_c2_beaconing",
        matched=False,
        row_count=0,
        rationale="추가 비콘 흔적 없음",
    )

    from core.oscal import build_evidence

    evidence = build_evidence(
        {
            "alert": _alert(),
            "severity": Severity.HIGH,
            "verdict": Verdict.TRUE_POSITIVE,
            "investigation": InvestigationResult(confidence=0.7),
            "active_hunt_findings": [finding],
        },
        "standard",
    )

    assert evidence.active_hunt_findings == [finding]
