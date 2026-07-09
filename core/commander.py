"""Incident Commander — 인시던트 생명주기 오케스트레이션(DoD SOC).

Case 신호(state·CAT·severity_peak·reopen_count·report_due_at)를 읽어 결정론
**지시(IncidentDirective)** 를 산출한다. COA·hunt 와 동일하게 *자문·읽기전용* —
Case 상태 변이·외향 행동(통보/태스킹 실행) 없음. 순수·무 I/O·total 매핑이라
어떤 case 로도 예외를 던지지 않는다(정책 YAML 없음 — 교리상수 사용).

2모드 계약: 같은 함수가 provisional case(report-time, CAT6/8)엔 bounded 지시를,
권위 case(CONFIRMED_TP 후 CAT1/4/7)엔 full-high 지시를 산출한다. HITL/tier3 하드
게이트는 권위 신호에만 걸려, 위조 가능한 provisional severity 로는 격상되지 않는다.

Spec: docs/superpowers/specs/2026-07-08-incident-commander-design.md
"""

from __future__ import annotations

from core.incident import is_case_overdue, is_cisa_overdue, is_cisa_reportable
from core.models import IncidentCase, IncidentDirective, IncidentState, Severity

# 교리상수(CJCSM 6510 CAT × 에스컬레이션) — 정책 I/O 없음(graceful 표면 소멸).
_HIGH_CAT = frozenset({"CAT1", "CAT4", "CAT7"})  # root 침해 / DoS / 악성로직
_MED_CAT = frozenset({"CAT2"})  # user-level 침해
_RANK_LABEL = ("low", "medium", "high")

# 전 IncidentState → 권고 조치(F3: total 매핑, NEW 포함).
_ACTION: dict[IncidentState, str] = {
    IncidentState.NEW: "트리아지 착수(초기 분류·중복 봉합)",
    IncidentState.ANALYSIS: "Tier2 조사·영향 범위 산정",
    IncidentState.CONTAINMENT: "격리·확산 차단",
    IncidentState.ERADICATION: "위협 축출(잔존 제거)",
    IncidentState.RECOVERY: "복구·정상화 검증",
    IncidentState.CLOSED: "교훈 정리·사후검토",
}
_REOPEN_ACTION = "재교전 — 재범 사건 재격리·헌팅"


class IncidentCommander:
    """Case → IncidentDirective 결정론 조율(무상태·자문)."""

    def direct(self, case: IncidentCase, now_iso: str = "") -> IncidentDirective:
        """Case 신호를 읽어 오케스트레이션 지시를 산출한다.

        순수·total — 부작용 없음, 예외 던지지 않음(자문만). HITL/tier3 는 권위
        신호(provisional=False 고위험 CAT ∨ reopen)에만 걸린다.

        Args:
            case: 대상 Incident Case(report-time provisional 또는 권위).
            now_iso: 현재 시각(ISO). 미가용 시 report_overdue 는 False.

        Returns:
            자문 지시(escalation·hitl·tier·action·overdue·provisional·rationale).
        """
        rationale: list[str] = []
        authoritative = not case.provisional

        # 에스컬레이션 rank(F5): base(CAT) + 소프트범프, high 에서 포화.
        if case.cat in _HIGH_CAT:
            rank = 2
            rationale.append(f"고위험 CAT({case.cat}) → base high")
        elif case.cat in _MED_CAT:
            rank = 1
            rationale.append(f"user-level CAT({case.cat}) → base medium")
        else:
            rank = 0
            rationale.append(f"CAT({case.cat}) → base low")

        if case.reopen_count > 0:
            rank += 1
            rationale.append(f"재범 재개방 {case.reopen_count}회 → 에스컬레이션 +1")
        if case.severity_peak == Severity.HIGH:
            rank += 1
            label = "" if authoritative else "(baseline-derived·미확증)"
            rationale.append(f"severity_peak HIGH{label} → 에스컬레이션 +1")
        rank = min(rank, 2)

        # HITL(F1): 권위 신호만 — provisional severity 단독으로는 강제 못함.
        hitl = (authoritative and case.cat in _HIGH_CAT) or case.reopen_count > 0
        if hitl:
            rationale.append("권위 고위험 신호 → HITL 필수")

        # 티어: HITL(권위게이트) → tier3, 그 외 tier2.
        tier = "tier3" if hitl else "tier2"

        # 권고 조치(F3): reopened 는 CONTAINMENT 만 override.
        if case.reopen_count > 0 and case.state == IncidentState.CONTAINMENT:
            action = _REOPEN_ACTION
        else:
            action = _ACTION.get(case.state, _ACTION[IncidentState.NEW])

        overdue = is_case_overdue(case, now_iso)
        if overdue:
            rationale.append("상급 보고(CJCSM) 시한 초과 — 즉시 보고")

        # CIRCIA 연방(CISA) 72h — 권위 중대 case 만(별 경로).
        cisa_reportable = is_cisa_reportable(case)
        cisa_overdue = is_cisa_overdue(case, now_iso)
        if cisa_reportable:
            rationale.append("CIRCIA 연방(CISA) 72h 보고 대상 — covered cyber incident")
        if cisa_overdue:
            rationale.append("CISA 연방 72h 시한 초과 — 즉시 연방 보고")

        return IncidentDirective(
            escalation=_RANK_LABEL[rank],
            hitl_required=hitl,
            assigned_tier=tier,
            recommended_action=action,
            report_overdue=overdue,
            cisa_reportable=cisa_reportable,
            cisa_report_overdue=cisa_overdue,
            provisional=case.provisional,
            rationale=rationale,
        )
