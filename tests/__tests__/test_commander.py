"""Incident Commander — 생명주기 오케스트레이션 지시(자문·트러스트경계)."""

from core.commander import IncidentCommander
from core.models import IncidentCase, IncidentState, Severity


def _case(
    *,
    cat: str = "CAT8",
    state: IncidentState = IncidentState.ANALYSIS,
    severity: Severity = Severity.INFO,
    provisional: bool = True,
    reopen: int = 0,
    due: str = "",
) -> IncidentCase:
    return IncidentCase(
        case_id="case:APT-X",
        actor_id="APT-X",
        state=state,
        cat=cat,
        severity_peak=severity,
        provisional=provisional,
        reopen_count=reopen,
        report_due_at=due,
    )


class TestEscalation:
    def test_authoritative_high_cat_high_hitl_tier3(self) -> None:
        """권위 CAT7 → high + HITL + tier3."""
        d = IncidentCommander().direct(
            _case(cat="CAT7", provisional=False, state=IncidentState.CONTAINMENT)
        )
        assert d.escalation == "high"
        assert d.hitl_required is True
        assert d.assigned_tier == "tier3"
        assert d.provisional is False

    def test_provisional_high_cat_no_hard_gate(self) -> None:
        """provisional CAT7(위조가능) → HITL 강제 안됨·tier2(F1 포이즈닝 봉인)."""
        d = IncidentCommander().direct(_case(cat="CAT7", provisional=True))
        assert d.hitl_required is False
        assert d.assigned_tier == "tier2"
        # provisional 이라도 base high CAT → escalation high(자문 등급은 표시).
        assert d.escalation == "high"

    def test_provisional_cat8_low(self) -> None:
        """provisional CAT8 → low + tier2 + HITL False."""
        d = IncidentCommander().direct(_case(cat="CAT8"))
        assert d.escalation == "low"
        assert d.hitl_required is False
        assert d.assigned_tier == "tier2"

    def test_med_cat_medium(self) -> None:
        """CAT2 → base medium."""
        d = IncidentCommander().direct(_case(cat="CAT2"))
        assert d.escalation == "medium"


class TestTrustBoundary:
    def test_provisional_severity_bump_not_gate(self) -> None:
        """provisional severity HIGH → escalation 범프하나 HITL/tier3 아님(F1)."""
        d = IncidentCommander().direct(
            _case(cat="CAT8", severity=Severity.HIGH, provisional=True)
        )
        assert d.escalation == "medium"  # low + severity 범프
        assert d.hitl_required is False
        assert d.assigned_tier == "tier2"
        assert any("baseline-derived" in r for r in d.rationale)

    def test_reopen_is_authoritative_gate(self) -> None:
        """reopen_count>0(권위 재확정) → HITL True + tier3."""
        d = IncidentCommander().direct(_case(cat="CAT2", provisional=False, reopen=1))
        assert d.hitl_required is True
        assert d.assigned_tier == "tier3"


class TestRankCap:
    def test_rank_saturates_at_high(self) -> None:
        """고위험 + reopen + HIGH severity 중첩 → high 포화(overflow 없음)."""
        d = IncidentCommander().direct(
            _case(
                cat="CAT1",
                provisional=False,
                reopen=2,
                severity=Severity.HIGH,
                state=IncidentState.CONTAINMENT,
            )
        )
        assert d.escalation == "high"


class TestRecommendedAction:
    def test_all_states_mapped(self) -> None:
        """전 IncidentState → 비어있지 않은 권고 조치(NEW 포함)."""
        for st in IncidentState:
            d = IncidentCommander().direct(_case(state=st))
            assert d.recommended_action != ""

    def test_reopened_containment_reengage(self) -> None:
        """reopen>0 + CONTAINMENT → 재교전(override)."""
        d = IncidentCommander().direct(
            _case(
                cat="CAT2",
                provisional=False,
                reopen=1,
                state=IncidentState.CONTAINMENT,
            )
        )
        assert "재교전" in d.recommended_action

    def test_reopened_recovery_not_overridden(self) -> None:
        """reopen>0 이어도 RECOVERY 는 복구 조치(F3: CONTAINMENT 만 override)."""
        d = IncidentCommander().direct(
            _case(
                cat="CAT2",
                provisional=False,
                reopen=1,
                state=IncidentState.RECOVERY,
            )
        )
        assert "재교전" not in d.recommended_action
        assert "복구" in d.recommended_action


class TestReportOverdue:
    def test_overdue_true(self) -> None:
        """보고 시한 지난 case + now → report_overdue True."""
        d = IncidentCommander().direct(
            _case(due="2026-07-08T00:00:00Z"), now_iso="2026-07-08T01:00:00Z"
        )
        assert d.report_overdue is True

    def test_no_now_false(self) -> None:
        """now 미가용 → report_overdue False(graceful)."""
        d = IncidentCommander().direct(_case(due="2026-07-08T00:00:00Z"))
        assert d.report_overdue is False
