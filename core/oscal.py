"""OSCAL 증거 빌더.

실제 OSCAL 모델/스키마는 인프라·컴플라이언스 lane. 여기서는 Report Agent 가 남길
증거의 최소 형태만 등급별 수준 차등으로 생성한다. 통제 매핑이 없는 동안은
`implementation_status="stub"` 으로 명시하고 근거 없는 control ref 를 채우지 않는다.
"""

from __future__ import annotations

from core.models import Alert, OscalEvidence, SOCState


def build_evidence(state: SOCState, evidence_level: str) -> OscalEvidence:
    """파이프라인 상태에서 OSCAL 증거를 구성한다.

    Args:
        state: 완료된 SOC 상태.
        evidence_level: 등급별 증거 수준(full|standard|summary|log-only).

    Returns:
        구성된 증거 모델.
    """
    alert: Alert = state["alert"]
    ev = OscalEvidence(
        evidence_level=evidence_level,
        alert_id=alert.id,
        scenario_id=alert.scenario_id,
        severity=state.get("severity"),
        verdict=state.get("verdict"),
        mitre=alert.mitre,
        implementation_status="stub",
        control_refs=[],
        pipeline_trace=state.get("trace", []),
    )
    if evidence_level in ("full", "standard"):
        ev.investigation = state.get("investigation")
        ev.response = state.get("response")
        ev.severity_rationale = state.get("severity_rationale")
        ev.active_hunt_findings = list(state.get("active_hunt_findings", []))
    return ev
