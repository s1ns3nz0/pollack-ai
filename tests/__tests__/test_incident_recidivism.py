"""Incident 캡스톤 — CLOSED 재개방(재범, 바운드) + CAT4(DoS) 권위분류."""

from core.incident import (
    _MAX_REOPEN,
    CaseManager,
    IncidentState,
    InMemoryIncidentStore,
    _authoritative_cat,
    _is_dos_scenario,
)
from core.models import Alert, EnvVerdict, Severity


def _alert(
    *, aid: str, actor_id: str = "APT-X", scenario: str = "S2-C2", advanced: bool = True
) -> Alert:
    return Alert(
        id=aid,
        scenario_id=scenario,
        title="t",
        severity_baseline=Severity.HIGH,
        signals=["sig"],
        mitre={"tactics": ["CommandAndControl"], "techniques": ["T1071"]},
        actor_id=actor_id,
        kill_chain_advanced=advanced,
    )


def _mgr() -> CaseManager:
    return CaseManager(InMemoryIncidentStore())


def _drive_to_closed(mgr: CaseManager, base: str) -> None:
    """case 를 CLOSED 까지 몬다."""
    mgr.observe_outcome(_alert(aid=f"{base}1"), EnvVerdict.CONFIRMED_TP)
    mgr.observe_outcome(
        _alert(aid=f"{base}2"), EnvVerdict.CONFIRMED_TP, recovery_applied=True
    )
    mgr.observe_outcome(
        _alert(aid=f"{base}3"),
        EnvVerdict.CONFIRMED_TP,
        recovery_applied=True,
        reoccurred=False,
    )
    mgr.observe_outcome(
        _alert(aid=f"{base}4"), EnvVerdict.CONFIRMED_FP, no_effect_sustained=True
    )


class TestRecidivism:
    def test_closed_reopens_on_new_tp(self) -> None:
        """CLOSED + 새 CONFIRMED_TP → CONTAINMENT 재개방 + reopen_count=1."""
        mgr = _mgr()
        _drive_to_closed(mgr, "a")
        c = mgr.observe_outcome(_alert(aid="new1"), EnvVerdict.CONFIRMED_TP)
        assert c is not None
        assert c.state == IncidentState.CONTAINMENT
        assert c.reopen_count == 1

    def test_same_alert_no_reopen(self) -> None:
        """이미 member 인 alert.id 재관측 → 재개방 안 함(순환 봉인, Codex H)."""
        mgr = _mgr()
        _drive_to_closed(mgr, "a")
        # a1 은 이미 member — 재관측해도 재개방 안 함
        c = mgr.observe_outcome(_alert(aid="a1"), EnvVerdict.CONFIRMED_TP)
        assert c is not None and c.state == IncidentState.CLOSED
        assert c.reopen_count == 0

    def test_closed_fp_no_reopen(self) -> None:
        """CLOSED + FP/INCONCLUSIVE → 재개방 안 함."""
        mgr = _mgr()
        _drive_to_closed(mgr, "a")
        c = mgr.observe_outcome(_alert(aid="new1"), EnvVerdict.CONFIRMED_FP)
        assert c is not None and c.state == IncidentState.CLOSED

    def test_reopen_cap_bounds(self) -> None:
        """reopen_count 캡 도달 시 더 이상 재개방 안 함(무한순환 방지)."""
        store = InMemoryIncidentStore()
        mgr = CaseManager(store)
        case = mgr.observe_outcome(_alert(aid="seed"), EnvVerdict.CONFIRMED_TP)
        assert case is not None
        case.state = IncidentState.CLOSED
        case.reopen_count = _MAX_REOPEN  # 캡 도달
        store.save(case)
        c = mgr.observe_outcome(_alert(aid="over"), EnvVerdict.CONFIRMED_TP)
        assert c is not None and c.state == IncidentState.CLOSED  # 재개방 안 함


class TestCat4Dos:
    def test_dos_scenario_cat4(self) -> None:
        """DoS 시나리오 CONFIRMED_TP → CAT4(단계보다 우선)."""
        mgr = _mgr()
        c = mgr.observe_outcome(
            _alert(aid="d1", scenario="S9-SWARM-SATURATION"), EnvVerdict.CONFIRMED_TP
        )
        assert c is not None and c.cat == "CAT4"

    def test_non_dos_uses_stage_cat(self) -> None:
        """비-DoS(C2) → 단계 기반 CAT1."""
        mgr = _mgr()
        c = mgr.observe_outcome(
            _alert(aid="n1", scenario="S2-C2"), EnvVerdict.CONFIRMED_TP
        )
        assert c is not None and c.cat == "CAT1"

    def test_is_dos_marker(self) -> None:
        assert _is_dos_scenario("S9-SWARM-SATURATION") is True
        assert _is_dos_scenario("S10-SATCOM-DISABLE") is True
        assert _is_dos_scenario("S2-C2-HIJACK") is False

    def test_authoritative_cat_dos_precedence(self) -> None:
        """DoS 는 FP 다음·단계 이전 우선순위."""
        assert _authoritative_cat(EnvVerdict.CONFIRMED_TP, 11, is_dos=True) == "CAT4"
        assert _authoritative_cat(EnvVerdict.CONFIRMED_FP, 11, is_dos=True) == "CAT3"
