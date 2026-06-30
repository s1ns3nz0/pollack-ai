"""ExperienceRecord — 경험메모리 레코드 스키마 + 지문(fingerprint) 검증."""

from core.models import (
    EnvVerdict,
    ExperienceRecord,
    JudgeFeatures,
    Provenance,
    Severity,
    Verdict,
)


def _record(**overrides: object) -> ExperienceRecord:
    base: dict[str, object] = {
        "scenario_id": "UAV-GPS-SPOOF-001",
        "signals": ["EKF 글리치", "위성 급감"],
        "asset_id": "GNSS",
        "asset_tier": "T1-Critical",
        "verdict": Verdict.TRUE_POSITIVE,
        "severity": Severity.HIGH,
        "judge_features": JudgeFeatures(
            has_signal=True, has_rule=True, corroborated=True, confidence=0.82
        ),
        "playbook_id": "PB-NAV-RTB-01",
        "env_verdict": EnvVerdict.CONFIRMED_TP,
        "provenance": Provenance.ENV_VERIFIED,
    }
    base.update(overrides)
    return ExperienceRecord.model_validate(base)


class TestFingerprint:
    """의미 동일성 지문 — 중복 제거 키."""

    def test_fingerprint_is_deterministic(self) -> None:
        """같은 내용은 같은 지문."""
        assert _record().fingerprint() == _record().fingerprint()

    def test_signal_order_does_not_change_fingerprint(self) -> None:
        """신호 순서만 다르면 동일 지문(정렬 후 해시)."""
        a = _record(signals=["EKF 글리치", "위성 급감"])
        b = _record(signals=["위성 급감", "EKF 글리치"])
        assert a.fingerprint() == b.fingerprint()

    def test_ts_and_provenance_excluded_from_fingerprint(self) -> None:
        """시점·출처등급만 달라도 동일 경험은 같은 지문."""
        a = _record(ts="2026-06-28T00:00:00Z", provenance=Provenance.ENV_VERIFIED)
        b = _record(ts="2026-06-28T09:00:00Z", provenance=Provenance.REDGT_OFFLINE)
        assert a.fingerprint() == b.fingerprint()

    def test_verdict_change_changes_fingerprint(self) -> None:
        """판정이 다르면 다른 경험 → 다른 지문."""
        a = _record(verdict=Verdict.TRUE_POSITIVE)
        b = _record(verdict=Verdict.FALSE_POSITIVE)
        assert a.fingerprint() != b.fingerprint()


class TestSchema:
    """레코드 스키마 — 산문 필드 부재(포이즈닝 표면 제거) 확인."""

    def test_no_free_prose_field(self) -> None:
        """LLM 산문(summary 등) 필드는 스키마에 없어야 한다."""
        fields = set(ExperienceRecord.model_fields)
        assert "summary" not in fields
        assert "judge_features" in fields

    def test_round_trip_serialization(self) -> None:
        """직렬화 → 역직렬화 후 동등."""
        rec = _record()
        restored = ExperienceRecord.model_validate(rec.model_dump())
        assert restored == rec
