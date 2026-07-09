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
from core.oscal import build_evidence
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
        severity_baseline=Severity.MEDIUM,
        mitre={"techniques": ["T1071"], "tactics": ["CommandAndControl"]},
        signals=["지상국 미발신 명령 수신"],
        iocs=[],
        cves=[],
        sbom_components=[],
    )


async def test_report_includes_active_hunt_findings() -> None:
    """matched finding 존재 시 report 노출 + guardrail/brief 반영 확인."""
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
    assert report.commander_brief is not None
    assert any("active hunt" in fact for fact in report.commander_brief.key_facts)


async def test_unmatched_finding_no_guardrail_but_evidence_retained() -> None:
    """matched=False 만 존재 시 guardrail/brief 미노출 + 증거는 보존 확인."""
    finding = ActiveHuntFinding(
        direction="forward",
        technique="T1071",
        tactic="CommandAndControl",
        query_id="T1071_c2_beaconing",
        matched=False,
        row_count=0,
        rationale="추가 비콘 흔적 없음",
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
    assert not any("active hunt matched" in flag for flag in report.guardrail_flags)
    assert report.commander_brief is not None
    assert not any("active hunt" in fact for fact in report.commander_brief.key_facts)
    assert report.active_hunt_findings == [finding]


def test_oscal_evidence_includes_active_hunt_findings() -> None:
    """OSCAL 증거에 active hunt findings 포함 확인(unmatched 포함)."""
    finding = ActiveHuntFinding(
        direction="forward",
        technique="T1071",
        tactic="CommandAndControl",
        query_id="T1071_c2_beaconing",
        matched=False,
        row_count=0,
        rationale="추가 비콘 흔적 없음",
    )

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


def test_oscal_evidence_marks_stub_without_tbd_controls() -> None:
    """OSCAL 미매핑 상태는 TBD control ref 가 아니라 명시 상태로 노출한다."""
    evidence = build_evidence(
        {
            "alert": _alert(),
            "severity": Severity.HIGH,
            "verdict": Verdict.TRUE_POSITIVE,
        },
        "summary",
    )

    assert evidence.implementation_status == "stub"
    assert evidence.control_refs == []
    assert all("TBD" not in ref for ref in evidence.control_refs)
