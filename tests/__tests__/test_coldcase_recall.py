"""재심 revoked 레코드 회상 제외 테스트 — 억제 무효화 반영."""

import pytest

from core.experience import (
    InMemoryExperienceStore,
    MemoryReadGate,
    RecallPurpose,
    Sha256Signer,
)
from core.models import (
    EnvVerdict,
    ExperienceRecord,
    JudgeFeatures,
    Provenance,
    Severity,
    Verdict,
)

_SCENARIO = "S2"


def _fp_rec(**overrides: object) -> ExperienceRecord:
    base: dict[str, object] = {
        "scenario_id": _SCENARIO,
        "signals": ["명령 시퀀스 불연속"],
        "verdict": Verdict.FALSE_POSITIVE,
        "severity": Severity.LOW,
        "judge_features": JudgeFeatures(
            has_signal=True, has_rule=False, corroborated=False, confidence=0.3
        ),
        "env_verdict": EnvVerdict.CONFIRMED_FP,
        "provenance": Provenance.ENV_VERIFIED,
    }
    base.update(overrides)
    return ExperienceRecord.model_validate(base)


def _signed(record: ExperienceRecord, signer: Sha256Signer) -> ExperienceRecord:
    fp = record.fingerprint()
    return record.model_copy(update={"content_hash": fp, "signature": signer.sign(fp)})


class TestRevokedRecallExclusion:
    """revoked 억제 레코드는 SUPPRESSION 회상에서 빠진다."""

    @pytest.mark.asyncio
    async def test_active_fp_recalled(self) -> None:
        """미revoke 억제 레코드는 정상 회상(대조군)."""
        store = InMemoryExperienceStore()
        signer = Sha256Signer()
        await store.awrite(_signed(_fp_rec(), signer))
        reader = MemoryReadGate(store, signer)

        hits = await reader.recall(_SCENARIO, RecallPurpose.SUPPRESSION)

        assert len(hits) == 1

    @pytest.mark.asyncio
    async def test_revoked_fp_excluded(self) -> None:
        """revoked=True 억제 레코드는 회상 제외 — 다음 유사 알람이 재억제되지 않음."""
        store = InMemoryExperienceStore()
        signer = Sha256Signer()
        await store.awrite(
            _signed(_fp_rec(revoked=True, reopened_reason="동일 actor 확정"), signer)
        )
        reader = MemoryReadGate(store, signer)

        hits = await reader.recall(_SCENARIO, RecallPurpose.SUPPRESSION)

        assert hits == []

    @pytest.mark.asyncio
    async def test_revoked_survives_signature_check(self) -> None:
        """revoke 후에도 서명 검증 통과 — revoked 는 fingerprint 불포함."""
        signer = Sha256Signer()
        rec = _signed(_fp_rec(actor_fingerprint="fp:x"), signer)
        revoked = rec.model_copy(update={"revoked": True})

        reader = MemoryReadGate(InMemoryExperienceStore(), signer)

        assert reader._verify(revoked) is True
