"""정보 산출물 — Commander Brief(BLUF) 결정론 합성기(순수·읽기전용·자문).

평판 SOCReport 필드-백을 지휘관 결심용 단일 BLUF 로 합성한다. **결정론 템플릿(LLM
무관)** — 지휘관 결심 입력에 환각·인젝션 유입 차단(재현·감사가능). **기존 authoritative
필드만 재조립 — 새 주장·verdict/severity/CAT 변경 없음(순수 함수).**

정직성 세탁 금지(핵심): provisional 을 confirmed 로, decision_advantage unknown 을
margin 으로, kill_web breadth 를 SPOF-free 로 위장하지 않는다 — 각 렌즈의 불확실성
주석을 caveats 로 그대로 승계한다.

Spec: docs/superpowers/specs/2026-07-09-commander-brief-design.md
"""

from __future__ import annotations

from typing import Literal

from core.models import Alert, CommanderBrief, SOCReport

Confidence = Literal["provisional", "authoritative", "unknown"]


class CommanderBriefBuilder:
    """SOCReport → CommanderBrief 결정론 합성(순수·읽기전용)."""

    def build(self, report: SOCReport, alert: Alert) -> CommanderBrief:
        """리포트를 지휘관 BLUF 로 합성한다(report 무변경).

        Args:
            report: 완성된 SOCReport(읽기만).
            alert: 대상 알람(asset_id/kill_chain_advanced).

        Returns:
            지휘관 결심용 BLUF. 불확실성은 caveats 로 정직 승계.
        """
        confidence = self._confidence(report)
        decision_required, routine = self._split(report, alert)
        key_facts = self._key_facts(report, alert, confidence)
        caveats = self._caveats(report, confidence)
        ooda = (
            report.decision_advantage.ooda
            if report.decision_advantage is not None
            else {}
        )
        bluf = self._bluf(report, alert, confidence, bool(decision_required))
        return CommanderBrief(
            bluf=bluf,
            confidence=confidence,
            decision_required=decision_required,
            routine=routine,
            ooda=dict(ooda),
            key_facts=key_facts,
            caveats=caveats,
        )

    @staticmethod
    def _confidence(report: SOCReport) -> Confidence:
        """확신도 — incident_case.provisional 에 정밀 정박(세탁 금지).

        명시적 is True/is False — provisional 이 None/falsy 여도 authoritative 로
        세탁되지 않게(Codex High). None/불명 → unknown.
        """
        case = report.incident_case
        if case is None:
            return "unknown"
        if case.provisional is True:
            return "provisional"
        if case.provisional is False:
            return "authoritative"
        return "unknown"

    @staticmethod
    def _split(report: SOCReport, alert: Alert) -> tuple[list[str], list[str]]:
        """결심필요/통상 분기(fail-safe) — degraded/부재는 전부 결심필요.

        intent_assessment 가 None **또는 intent_available=False** 면 보수적으로
        전부 decision_required(은폐 금지). routine 은 은폐 아님 — 리포트 항상 존재.
        """
        intent = report.intent_assessment
        if intent is None or not intent.intent_available:
            return (["의도 미적용/degraded — 보수적 지휘관 상승"], [])
        if intent.decision_class == "routine_soc":
            basis = ", ".join(intent.matched) if intent.matched else "CAT 위임"
            return ([], [f"통상 SOC 처리(의도): {basis}"])
        # commander_decision · surfaced → 보수적 결심필요.
        label = (
            ", ".join(intent.matched) if intent.matched else (alert.asset_id or "alert")
        )
        return ([f"지휘관 결심({intent.decision_class}): {label}"], [])

    @staticmethod
    def _key_facts(
        report: SOCReport, alert: Alert, confidence: Confidence
    ) -> list[str]:
        """핵심 사실 — 고정 순서·결정론(존재 필드만)."""
        facts = [f"판정 {report.verdict} / 심각도 {report.severity}"]
        case = report.incident_case
        if case is not None:
            mark = "미확증" if case.provisional else "확정"
            facts.append(f"CAT {case.cat}({mark})")
        mc = report.mission_continuity
        if mc is not None:
            lost = f" — {mc.capability_lost}" if mc.capability_lost else ""
            facts.append(f"임무 지속성 {mc.level}{lost}")
        if report.campaign_matches:
            cm = report.campaign_matches[0]
            facts.append(f"캠페인 {cm.chain_id}({cm.matched}/{cm.total})")
        matched_hunts = [
            finding for finding in report.active_hunt_findings if finding.matched
        ]
        if matched_hunts:
            facts.append(f"active hunt matched {len(matched_hunts)}건")
        kw = report.kill_web_resilience
        if kw is not None:
            blind = (
                f", 지상 사각 {kw.blind_surface_count}"
                if kw.blind_surface_count
                else ""
            )
            facts.append(f"커버리지 breadth {kw.coverage_breadth_ratio}{blind}")
        da = report.decision_advantage
        if da is not None:
            facts.append(f"결심 여유 {da.verdict}")
        if alert.kill_chain_advanced:
            facts.append("kill chain 후반단계(C2 이후) 도달")
        return facts

    @staticmethod
    def _caveats(report: SOCReport, confidence: Confidence) -> list[str]:
        """정직성 승계 — 렌즈 불확실성 주석을 **전부** 세탁 없이 전파(Codex Medium)."""
        caveats: list[str] = []
        if confidence == "provisional":
            caveats.append("확신도 미확증(provisional) — 신뢰 관측 전")
        elif confidence == "unknown":
            caveats.append("사건 미봉합 — 확신도 판정 불가")
        da = report.decision_advantage
        if da is not None:
            # basis 전체 승계 — 비교대상·unknown 사유 등 후속 주석 누락 금지.
            caveats.extend(da.basis)
        kw = report.kill_web_resilience
        if kw is not None:
            caveats.extend(kw.rationale)  # 기법수≠센서 등 전체.
        intent = report.intent_assessment
        if intent is not None and not intent.intent_available:
            caveats.append("지휘관 의도 정책 degraded")
        return caveats

    @staticmethod
    def _bluf(
        report: SOCReport, alert: Alert, confidence: Confidence, needs_decision: bool
    ) -> str:
        """BLUF 한 줄 — 고정 순서 조립(존재 조각만, 세탁 금지)."""
        parts: list[str] = []
        intent = report.intent_assessment
        if intent is not None and intent.priority == "main_effort":
            parts.append("[주력]")
        if alert.asset_id:
            parts.append(alert.asset_id)
        vs = f"{report.verdict}/{report.severity}"
        if confidence == "provisional":
            vs += "(미확증)"
        parts.append(vs)
        mc = report.mission_continuity
        if mc is not None:
            parts.append(f"임무 {mc.level}")
        da = report.decision_advantage
        if da is not None:
            parts.append(f"결심여유 {da.verdict}")  # unknown 도 그대로(세탁 금지)
        if report.coa_options:
            parts.append(f"권고: {report.coa_options[0].action}")
        prefix = "[결심필요]" if needs_decision else "[통상]"
        return f"{prefix} " + " · ".join(parts)
