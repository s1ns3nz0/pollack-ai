"""재심(cold-case) 모델 확장 테스트 — ExperienceRecord actor_fingerprint/revoked."""

from core.models import (
    EnvVerdict,
    ExperienceRecord,
    JudgeFeatures,
    Provenance,
    Severity,
    Verdict,
)


def _record(**kw: object) -> ExperienceRecord:
    base: dict[str, object] = {
        "scenario_id": "S2",
        "signals": ["명령 시퀀스 불연속"],
        "verdict": Verdict.FALSE_POSITIVE,
        "severity": Severity.LOW,
        "judge_features": JudgeFeatures(
            has_signal=True, has_rule=False, corroborated=False, confidence=0.3
        ),
        "env_verdict": EnvVerdict.CONFIRMED_FP,
        "provenance": Provenance.ENV_VERIFIED,
    }
    base.update(kw)
    return ExperienceRecord(**base)  # type: ignore[arg-type]


class TestColdCaseFields:
    """재심용 신규 필드 기본값 + 의미."""

    def test_defaults(self) -> None:
        """actor_fingerprint 빈값 + revoked False + reopened_reason 빈값."""
        rec = _record()

        assert rec.actor_fingerprint == ""
        assert rec.revoked is False
        assert rec.reopened_reason == ""

    def test_actor_fingerprint_changes_fingerprint(self) -> None:
        """actor_fingerprint 는 대조 키 — fingerprint()에 반영(중복제거 구분)."""
        base = _record()
        with_actor = _record(actor_fingerprint="fp:abc")

        assert base.fingerprint() != with_actor.fingerprint()

    def test_revoked_does_not_change_fingerprint(self) -> None:
        """revoked 는 상태 — fingerprint() 불변(revoke 후에도 서명 검증 유지)."""
        active = _record(actor_fingerprint="fp:abc")
        revoked = _record(
            actor_fingerprint="fp:abc", revoked=True, reopened_reason="동일 actor 확정"
        )

        assert active.fingerprint() == revoked.fingerprint()

    def test_empty_actor_fingerprint_backward_compatible(self) -> None:
        """빈 actor_fingerprint 는 fingerprint 제외 — 구버전 해시와 하위호환(Codex).

        actor_fingerprint 도입 전 레코드(빈값)의 해시·서명이 유지돼야 회상에서
        누락되지 않는다. 빈값이면 key 자체를 payload 에 넣지 않아 기존 해시와 동일.
        """
        import hashlib
        import json

        rec = _record()  # actor_fingerprint=""
        legacy_payload = {
            "scenario_id": rec.scenario_id,
            "signals": sorted(rec.signals),
            "asset_id": rec.asset_id,
            "asset_tier": rec.asset_tier,
            "verdict": rec.verdict.value,
            "severity": rec.severity.value,
            "env_verdict": rec.env_verdict.value,
            "judge_features": rec.judge_features.model_dump(),
        }
        legacy_hash = hashlib.sha256(
            json.dumps(legacy_payload, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        assert rec.fingerprint() == legacy_hash
