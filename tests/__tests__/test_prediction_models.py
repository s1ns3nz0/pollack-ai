"""예측 폐루프 모델 단위 테스트 — PendingPrediction / ActorProfile / Alert 확장."""

from core.models import ActorProfile, Alert, PendingPrediction, Severity


class TestPendingPrediction:
    """PendingPrediction 모델 테스트."""

    def test_defaults(self) -> None:
        """필수 필드 + 기본값(발행 직후 상태) 확인."""
        pred = PendingPrediction(
            technique="T0855",
            probability=0.67,
            source_alert_id="A-1",
        )

        assert pred.technique == "T0855"
        assert pred.status == "pending"
        assert pred.age_alerts == 0
        assert pred.issued_at == ""


class TestActorProfilePredictions:
    """ActorProfile.pending_predictions 확장 테스트."""

    def test_profile_has_prediction_fields(self) -> None:
        """pending_predictions + hit/miss 누적 카운터 기본값 확인."""
        profile = ActorProfile(actor_id="fp:abc")

        assert profile.pending_predictions == []
        assert profile.prediction_hits == 0
        assert profile.prediction_misses == 0

    def test_fingerprint_covers_pending_predictions(self) -> None:
        """pending_predictions 변조 시 fingerprint 변화 — 서명 무결성 대상."""
        base = ActorProfile(actor_id="fp:abc")
        tampered = ActorProfile(
            actor_id="fp:abc",
            pending_predictions=[
                PendingPrediction(
                    technique="T0855", probability=0.9, source_alert_id="A-1"
                )
            ],
        )

        assert base.fingerprint() != tampered.fingerprint()

    def test_fingerprint_covers_hit_counters(self) -> None:
        """hit/miss 카운터 변조 시 fingerprint 변화."""
        base = ActorProfile(actor_id="fp:abc")
        tampered = ActorProfile(actor_id="fp:abc", prediction_hits=3)

        assert base.fingerprint() != tampered.fingerprint()


class TestAlertPredictionMatch:
    """Alert.prediction_match 플래그 테스트."""

    def test_default_false(self) -> None:
        """기본값 False — 대조 전 상태."""
        alert = Alert(
            id="A-1",
            scenario_id="S1",
            title="t",
            severity_baseline=Severity.HIGH,
        )

        assert alert.prediction_match is False
