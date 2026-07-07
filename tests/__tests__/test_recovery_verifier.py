"""RecoveryVerifier 테스트 — 축출 후 재발 관측 → 축출 실패 감지(검증 폐루프)."""

from app.metrics import metrics
from core.outcome import Observation
from core.recovery import EvictionOutcome, RecoveryVerifier


def _obs(*, recovery_applied: bool, reoccurred: bool) -> Observation:
    return Observation(
        alert_id="a1",
        scenario_id="S2",
        recovery_applied=recovery_applied,
        reoccurred=reoccurred,
        ts="t",
    )


class TestRecoveryVerifier:
    def test_recovery_then_reoccur_is_failed(self) -> None:
        """축출 실행 후 재발 → EVICTION_FAILED(공격자 잔존)."""
        v = RecoveryVerifier()

        out = v.check(_obs(recovery_applied=True, reoccurred=True))

        assert out == EvictionOutcome.FAILED

    def test_recovery_no_reoccur_is_success(self) -> None:
        """축출 실행 후 무재발 → EVICTION_SUCCESS."""
        v = RecoveryVerifier()

        out = v.check(_obs(recovery_applied=True, reoccurred=False))

        assert out == EvictionOutcome.SUCCESS

    def test_no_recovery_not_applicable(self) -> None:
        """축출 미실행이면 검증 대상 아님(NA)."""
        v = RecoveryVerifier()

        out = v.check(_obs(recovery_applied=False, reoccurred=True))

        assert out == EvictionOutcome.NOT_APPLICABLE

    def test_failed_increments_metric(self) -> None:
        """축출 실패 시 soc_eviction_failed_total 증가."""
        v = RecoveryVerifier()
        before = metrics().eviction_failed_total

        v.check(_obs(recovery_applied=True, reoccurred=True))

        assert metrics().eviction_failed_total == before + 1

    def test_success_no_metric(self) -> None:
        """축출 성공은 실패 카운터 불변."""
        v = RecoveryVerifier()
        before = metrics().eviction_failed_total

        v.check(_obs(recovery_applied=True, reoccurred=False))

        assert metrics().eviction_failed_total == before
