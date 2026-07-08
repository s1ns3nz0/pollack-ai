"""CAT7(악성 로직) — 신뢰 확정 SBOM 변조 신호 → 권위 분류(분류전용)."""

from core.incident import (
    CaseManager,
    InMemoryIncidentStore,
    _authoritative_cat,
)
from core.models import Alert, EnvVerdict, Severity


def _alert(*, aid: str = "a1", scenario: str = "S2-C2") -> Alert:
    return Alert(
        id=aid,
        scenario_id=scenario,
        title="t",
        severity_baseline=Severity.HIGH,
        signals=["sig"],
        mitre={"tactics": ["CommandAndControl"], "techniques": ["T1071"]},
        actor_id="APT-X",
        kill_chain_advanced=True,
    )


def _mgr() -> CaseManager:
    return CaseManager(InMemoryIncidentStore())


class TestCat7:
    def test_sbom_tampered_cat7(self) -> None:
        """sbom_tampered=True + CONFIRMED_TP → CAT7."""
        c = _mgr().observe_outcome(
            _alert(), EnvVerdict.CONFIRMED_TP, sbom_tampered=True
        )
        assert c is not None and c.cat == "CAT7"

    def test_no_tamper_uses_stage_cat(self) -> None:
        """sbom_tampered=False → 기존 CAT(C2 order11 → CAT1)."""
        c = _mgr().observe_outcome(_alert(), EnvVerdict.CONFIRMED_TP)
        assert c is not None and c.cat == "CAT1"

    def test_fp_ignores_tamper(self) -> None:
        """CONFIRMED_FP → CAT3(악성로직 무관 — tamper 여도 CAT7 아님)."""
        assert (
            _authoritative_cat(
                EnvVerdict.CONFIRMED_FP, 11, is_malicious_logic=True
            )
            == "CAT3"
        )


class TestPrecedence:
    def test_malicious_logic_dominates_dos_and_stage(self) -> None:
        """CAT7 > CAT4(DoS) > 단계 — 중첩 시 first-match CAT7."""
        # 악성로직 + DoS + 후반단계 동시 → CAT7 지배
        assert (
            _authoritative_cat(
                EnvVerdict.CONFIRMED_TP, 11, is_dos=True, is_malicious_logic=True
            )
            == "CAT7"
        )
        # DoS 만 → CAT4
        assert _authoritative_cat(EnvVerdict.CONFIRMED_TP, 11, is_dos=True) == "CAT4"
        # 둘 다 없음 → 단계 CAT1
        assert _authoritative_cat(EnvVerdict.CONFIRMED_TP, 11) == "CAT1"


class TestWorkerPlumbing:
    def test_submit_case_passes_sbom_tampered(self) -> None:
        """OutcomeProbe 가 obs.sbom_tampered 를 observe_outcome 로 전달."""
        from core.outcome import Observation

        obs = Observation.model_validate(
            {
                "alert_id": "w1",
                "scenario_id": "S4-FW-TAMPER",
                "ts": "t",
                "actor_id": "APT-X",
                "mission_effect_observed": True,
                "sbom_tampered": True,
            }
        )
        assert obs.sbom_tampered is True  # 필드 신뢰 관측 채널에 존재
