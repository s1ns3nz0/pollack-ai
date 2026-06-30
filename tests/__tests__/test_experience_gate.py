"""MemoryWriteGate — 경험메모리 적립 정책(포이즈닝 방어) 검증."""

import pytest

from core.experience import (
    InMemoryExperienceStore,
    MemoryWriteGate,
    Sha256Signer,
    WriteStatus,
)
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


class TestAcceptedWrites:
    """정상 적립 경로."""

    @pytest.mark.asyncio
    async def test_env_verified_tp_is_written(self) -> None:
        """환경검증 정탐 → 적립."""
        store = InMemoryExperienceStore()
        gate = MemoryWriteGate(store)
        decision = await gate.submit(_record())
        assert decision.status == WriteStatus.WRITTEN
        assert decision.written
        assert len(store) == 1

    @pytest.mark.asyncio
    async def test_auto_tp_is_allowed(self) -> None:
        """탐지 학습(CONFIRMED_TP)은 AUTO 출처도 허용(안전 방향)."""
        gate = MemoryWriteGate(InMemoryExperienceStore())
        decision = await gate.submit(
            _record(provenance=Provenance.AUTO, env_verdict=EnvVerdict.CONFIRMED_TP)
        )
        assert decision.status == WriteStatus.WRITTEN

    @pytest.mark.asyncio
    async def test_trusted_suppression_is_allowed(self) -> None:
        """억제 학습(CONFIRMED_FP)도 신뢰 출처면 허용."""
        gate = MemoryWriteGate(InMemoryExperienceStore())
        decision = await gate.submit(
            _record(
                provenance=Provenance.ENV_VERIFIED,
                env_verdict=EnvVerdict.CONFIRMED_FP,
                verdict=Verdict.FALSE_POSITIVE,
            )
        )
        assert decision.status == WriteStatus.WRITTEN


class TestRejectedWrites:
    """포이즈닝 방어 — 거부 경로."""

    @pytest.mark.asyncio
    async def test_inconclusive_is_rejected(self) -> None:
        """보류(INCONCLUSIVE)는 적립하지 않는다."""
        store = InMemoryExperienceStore()
        gate = MemoryWriteGate(store)
        decision = await gate.submit(_record(env_verdict=EnvVerdict.INCONCLUSIVE))
        assert decision.status == WriteStatus.REJECTED_INCONCLUSIVE
        assert len(store) == 0

    @pytest.mark.asyncio
    async def test_auto_suppression_is_rejected(self) -> None:
        """AUTO 출처의 억제 학습(CONFIRMED_FP)은 차단(미신뢰 억제)."""
        store = InMemoryExperienceStore()
        gate = MemoryWriteGate(store)
        decision = await gate.submit(
            _record(
                provenance=Provenance.AUTO,
                env_verdict=EnvVerdict.CONFIRMED_FP,
                verdict=Verdict.FALSE_POSITIVE,
            )
        )
        assert decision.status == WriteStatus.REJECTED_UNTRUSTED_SUPPRESSION
        assert len(store) == 0


class TestDedupAndSigning:
    """중복 제거 + 변조탐지 서명."""

    @pytest.mark.asyncio
    async def test_duplicate_is_skipped(self) -> None:
        """동일 내용 재제출 → 중복 생략(한 번만 적립)."""
        store = InMemoryExperienceStore()
        gate = MemoryWriteGate(store)
        first = await gate.submit(_record())
        second = await gate.submit(_record())
        assert first.status == WriteStatus.WRITTEN
        assert second.status == WriteStatus.SKIPPED_DUPLICATE
        assert first.fingerprint == second.fingerprint
        assert len(store) == 1

    @pytest.mark.asyncio
    async def test_written_record_is_signed(self) -> None:
        """적립 레코드는 지문·서명이 채워진다."""
        store = InMemoryExperienceStore()
        gate = MemoryWriteGate(store, signer=Sha256Signer())
        decision = await gate.submit(_record())
        stored = store._by_fingerprint[decision.fingerprint]
        assert stored.content_hash == decision.fingerprint
        assert stored.signature == Sha256Signer().sign(decision.fingerprint)
        assert stored.signature != ""
