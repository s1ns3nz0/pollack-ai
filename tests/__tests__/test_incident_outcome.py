"""Incident Case 후반 생명주기 — 신뢰관측 전이 + 권위 CAT + reconciliation."""

from core.incident import (
    CaseManager,
    IncidentState,
    InMemoryIncidentStore,
    _authoritative_cat,
)
from core.models import Alert, EnvVerdict, Severity


def _alert(
    *,
    aid: str = "a1",
    actor_id: str | None = "APT-X",
    tactic: str = "CommandAndControl",
    advanced: bool = True,
) -> Alert:
    return Alert(
        id=aid,
        scenario_id="S2",
        title="t",
        severity_baseline=Severity.HIGH,
        signals=["sig"],
        mitre={"tactics": [tactic], "techniques": ["T1071"]},
        actor_id=actor_id,
        kill_chain_advanced=advanced,
    )


def _mgr() -> CaseManager:
    return CaseManager(InMemoryIncidentStore())


class TestOutcomeTransitions:
    def test_confirmed_tp_to_containment(self) -> None:
        """CONFIRMED_TP → CONTAINMENT + provisional=False + 권위 CAT."""
        c = _mgr().observe_outcome(_alert(), EnvVerdict.CONFIRMED_TP)
        assert c is not None
        assert c.state == IncidentState.CONTAINMENT
        assert c.provisional is False
        assert c.cat == "CAT1"  # C2(order 11) → root intrusion

    def test_inconclusive_never_advances(self) -> None:
        """INCONCLUSIVE → 전진 안 함(None, Codex M1)."""
        assert _mgr().observe_outcome(_alert(), EnvVerdict.INCONCLUSIVE) is None

    def test_stepwise_lifecycle(self) -> None:
        """순차 전진: CONTAINMENT→ERADICATION→RECOVERY→CLOSED(스텝와이즈)."""
        mgr = _mgr()
        mgr.observe_outcome(_alert(aid="a1"), EnvVerdict.CONFIRMED_TP)
        c = mgr.observe_outcome(
            _alert(aid="a2"), EnvVerdict.CONFIRMED_TP, recovery_applied=True
        )
        assert c is not None and c.state == IncidentState.ERADICATION
        c = mgr.observe_outcome(
            _alert(aid="a3"),
            EnvVerdict.CONFIRMED_TP,
            recovery_applied=True,
            reoccurred=False,
        )
        assert c is not None and c.state == IncidentState.RECOVERY
        c = mgr.observe_outcome(
            _alert(aid="a4"), EnvVerdict.CONFIRMED_FP, no_effect_sustained=True
        )
        assert c is not None and c.state == IncidentState.CLOSED

    def test_no_skip_states(self) -> None:
        """recovery_applied 라도 CONTAINMENT 이전이면 ERADICATION 스킵 안 함."""
        c = _mgr().observe_outcome(
            _alert(), EnvVerdict.CONFIRMED_TP, recovery_applied=True
        )
        # 첫 관측은 CONTAINMENT 까지만(ERADICATION 스킵 금지)
        assert c is not None and c.state == IncidentState.CONTAINMENT

    def test_reoccurred_blocks_recovery(self) -> None:
        """재발(축출 실패) → ERADICATION 에서 RECOVERY 전진 안 함."""
        mgr = _mgr()
        mgr.observe_outcome(_alert(aid="a1"), EnvVerdict.CONFIRMED_TP)
        mgr.observe_outcome(
            _alert(aid="a2"), EnvVerdict.CONFIRMED_TP, recovery_applied=True
        )
        c = mgr.observe_outcome(
            _alert(aid="a3"),
            EnvVerdict.CONFIRMED_TP,
            recovery_applied=True,
            reoccurred=True,
        )
        assert c is not None and c.state == IncidentState.ERADICATION


class TestAuthoritativeCat:
    def test_cat_precedence(self) -> None:
        assert _authoritative_cat(EnvVerdict.CONFIRMED_TP, 11) == "CAT1"
        assert _authoritative_cat(EnvVerdict.CONFIRMED_TP, 5) == "CAT2"
        assert _authoritative_cat(EnvVerdict.CONFIRMED_TP, 1) == "CAT6"
        assert _authoritative_cat(EnvVerdict.CONFIRMED_TP, 0) == "CAT2"
        assert _authoritative_cat(EnvVerdict.CONFIRMED_FP, 11) == "CAT3"


class TestReconciliation:
    def test_fp_case_merged_into_explicit(self) -> None:
        """report 잠정 fp-case → outcome explicit-case 로 병합(Codex H2)."""
        store = InMemoryIncidentStore()
        mgr = CaseManager(store)
        # report 경로: actor_id 없는 위생 alert → fp-case 개설
        sanitized = _alert(aid="a1", actor_id=None)
        fp_case = mgr.observe_alert(sanitized, Severity.HIGH)
        assert fp_case is not None and fp_case.case_id.startswith("case:fp:")
        before = store.open_count()
        # outcome 경로: 같은 alert(explicit actor_id) → explicit case 로 병합, fp 삭제
        explicit = _alert(aid="a1", actor_id="APT-X")
        c = mgr.observe_outcome(explicit, EnvVerdict.CONFIRMED_TP)
        assert c is not None and c.case_id == "case:APT-X"
        assert "a1" in c.member_alert_ids  # fp-case member 흡수
        assert store.load(fp_case.case_id) is None  # fp-case 삭제됨
        assert store.open_count() == before  # 병합 — 순증 아님

    def test_no_false_merge_on_fingerprint_collision(self) -> None:
        """다른 actor·같은 threat 속성이라도 alert.id 안 겹치면 오병합 안 함(NEW-A)."""
        store = InMemoryIncidentStore()
        mgr = CaseManager(store)
        # actor 없는 위생 alert(a1) → fp-case 개설
        mgr.observe_alert(_alert(aid="a1", actor_id=None), Severity.HIGH)
        # 다른 alert(a2, 같은 threat 속성이라 같은 fingerprint) explicit actor 관측
        c = mgr.observe_outcome(
            _alert(aid="a2", actor_id="APT-Y"), EnvVerdict.CONFIRMED_TP
        )
        assert c is not None and c.case_id == "case:APT-Y"
        assert "a1" not in c.member_alert_ids  # a1(다른 사건) 흡수 안 함

    def test_no_actor_id_skips(self) -> None:
        """obs actor_id 없으면(빈 fp) → 전진 스킵."""
        empty = Alert(
            id="e", scenario_id="S", title="t", severity_baseline=Severity.INFO
        )
        assert _mgr().observe_outcome(empty, EnvVerdict.CONFIRMED_TP) is None
