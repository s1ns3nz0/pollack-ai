"""임무형 지휘 — Commander's Intent 필터. 비대칭 게이팅·fail-safe·스키마 검증."""

import pytest

from core.exceptions import PolicyError
from core.intent import CommanderIntent, IntentFilter
from core.models import (
    Alert,
    IncidentCase,
    IncidentState,
    Severity,
)


def _intent(**kw: object) -> CommanderIntent:
    base: dict[str, object] = {
        "main_effort_assets": ["MUAV-AKS-001"],
        "protected_scenarios": ["S9"],
        "protected_mission_phases": ["strike"],
        "surface_cats": ["CAT1", "CAT2", "CAT4", "CAT7"],
        "delegate_cats": ["CAT6", "CAT8"],
    }
    base.update(kw)
    return CommanderIntent.model_validate(base)


def _alert(**kw: object) -> Alert:
    base: dict[str, object] = {
        "id": "a1",
        "scenario_id": "S2",
        "title": "t",
        "severity_baseline": Severity.MEDIUM,
    }
    base.update(kw)
    return Alert.model_validate(base)


def _case(cat: str, provisional: bool) -> IncidentCase:
    return IncidentCase(
        case_id="c1",
        actor_id="APT-X",
        state=IncidentState.ANALYSIS,
        cat=cat,
        severity_peak=Severity.HIGH,
        provisional=provisional,
    )


class TestPriority:
    def test_main_effort_asset(self) -> None:
        f = IntentFilter(_intent())
        r = f.assess(_alert(asset_id="MUAV-AKS-001"), None)
        assert r.priority == "main_effort"
        assert r.decision_class == "commander_decision"  # 주력은 CAT 무관 상승

    def test_protected_scenario_and_phase(self) -> None:
        f = IntentFilter(_intent())
        assert f.assess(_alert(scenario_id="S9"), None).priority == "main_effort"
        assert f.assess(_alert(mission_phase="strike"), None).priority == "main_effort"

    def test_routine_when_no_match(self) -> None:
        f = IntentFilter(_intent())
        r = f.assess(_alert(asset_id="OTHER"), None)
        assert r.priority == "routine" and r.decision_class == "surfaced"


class TestAsymmetricGating:
    def test_surface_cat_fires_on_provisional(self) -> None:
        """핵심 불변식 — surface CAT 은 provisional(위조가능)로도 상승(fail-safe)."""
        f = IntentFilter(_intent())
        r = f.assess(_alert(), _case("CAT4", provisional=True))
        assert r.decision_class == "commander_decision"

    def test_surface_cat_fires_on_authoritative(self) -> None:
        f = IntentFilter(_intent())
        r = f.assess(_alert(), _case("CAT1", provisional=False))
        assert r.decision_class == "commander_decision"

    def test_delegate_only_when_authoritative(self) -> None:
        """delegate CAT 은 authoritative 확정에만 routine_soc — provisional 은 안 됨."""
        f = IntentFilter(_intent())
        auth = f.assess(_alert(), _case("CAT6", provisional=False))
        prov = f.assess(_alert(), _case("CAT6", provisional=True))
        assert auth.decision_class == "routine_soc"
        # provisional 위조 저CAT 로 은폐 불가 — surfaced 유지(포이즈닝 차단).
        assert prov.decision_class == "surfaced"

    def test_unmatched_cat_defaults_surfaced(self) -> None:
        # CAT3 은 surface/delegate 어느 집합에도 없음 → 기본 surfaced.
        f = IntentFilter(_intent())
        r = f.assess(_alert(), _case("CAT3", provisional=False))
        assert r.decision_class == "surfaced"


class TestSchemaValidation:
    def test_unknown_cat_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017 - ValidationError
            _intent(surface_cats=["CAT1", "CAT99"])

    def test_overlap_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            _intent(surface_cats=["CAT1", "CAT4", "CAT7"], delegate_cats=["CAT4"])

    def test_bad_risk_rejected(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            _intent(risk_tolerance="reckless")

    def test_mandatory_surface_cats_enforced(self) -> None:
        """치명 CAT(CAT1/4/7) 누락 정책 거부 — 오타로 은폐 불가(Codex Medium)."""
        with pytest.raises(Exception):  # noqa: B017
            _intent(surface_cats=["CAT1", "CAT4"])  # CAT7 누락
        with pytest.raises(Exception):  # noqa: B017
            _intent(surface_cats=[])  # 빈/부분 정책

    def test_critical_cat_cannot_be_delegated(self) -> None:
        """CAT4 를 delegate 로 오기해도 필수상승 위반으로 거부(은폐 원천차단)."""
        with pytest.raises(Exception):  # noqa: B017
            _intent(surface_cats=["CAT1", "CAT7"], delegate_cats=["CAT4"])


class TestFailSafe:
    def test_degraded_when_policy_missing(self) -> None:
        """정책 부재 → degraded: intent_available=False + surfaced(delegate 비활성)."""
        f = IntentFilter.from_yaml("/tmp/__no_intent__.yaml")
        r = f.assess(_alert(asset_id="MUAV-AKS-001"), _case("CAT6", provisional=False))
        assert r.intent_available is False
        assert r.decision_class == "surfaced"  # degraded 는 절대 은폐 안 함

    def test_default_policy_loads(self) -> None:
        f = IntentFilter.from_yaml()
        r = f.assess(_alert(), None)
        assert r.intent_available is True

    def test_broken_policy_degrades_not_raises(self, tmp_path: object) -> None:
        """스키마 오류(미지 CAT)는 예외 아니라 degraded — 파이프라인·가시성 보호."""
        p = tmp_path / "bad.yaml"  # type: ignore[operator]
        p.write_text("surface_cats: [CAT1, BOGUS]\n", encoding="utf-8")
        f = IntentFilter.from_yaml(str(p))
        assert f.assess(_alert(), None).intent_available is False

    def test_partial_policy_degrades(self, tmp_path: object) -> None:
        """유효 CAT이나 치명 CAT 누락한 부분 정책 → degraded(전부 surfaced)."""
        p = tmp_path / "partial.yaml"  # type: ignore[operator]
        p.write_text("surface_cats: [CAT1]\n", encoding="utf-8")  # CAT4/7 누락
        f = IntentFilter.from_yaml(str(p))
        r = f.assess(_alert(), _case("CAT4", provisional=True))
        assert r.intent_available is False and r.decision_class == "surfaced"

    def test_policy_error_type(self) -> None:
        """PolicyError 는 예외 계층(from_yaml 이 잡는 타입)."""
        assert issubclass(PolicyError, Exception)


class TestNoAuthorityCreep:
    def test_advisory_label_only(self) -> None:
        """decision_class 는 표현 라벨 — verdict/severity/CAT 무변경(자문)."""
        f = IntentFilter(_intent())
        case = _case("CAT6", provisional=False)
        r = f.assess(_alert(), case)
        # 판정은 case 를 변이하지 않음.
        assert case.cat == "CAT6" and case.provisional is False
        assert r.decision_class == "routine_soc"
