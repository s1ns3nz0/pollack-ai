"""MemoryReadGate — 비대칭 회상 + 서명 검증(읽기 측 포이즈닝 방어) 검증."""

import pytest

from core.experience import (
    InMemoryExperienceStore,
    MemoryReadGate,
    MemoryWriteGate,
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

_SCENARIO = "UAV-GPS-SPOOF-001"


def _rec(**overrides: object) -> ExperienceRecord:
    base: dict[str, object] = {
        "scenario_id": _SCENARIO,
        "signals": ["EKF 글리치"],
        "asset_id": "GNSS",
        "asset_tier": "T1-Critical",
        "verdict": Verdict.TRUE_POSITIVE,
        "severity": Severity.HIGH,
        "judge_features": JudgeFeatures(
            has_signal=True, has_rule=True, corroborated=True, confidence=0.8
        ),
        "playbook_id": "PB-NAV-RTB-01",
        "env_verdict": EnvVerdict.CONFIRMED_TP,
        "provenance": Provenance.ENV_VERIFIED,
    }
    base.update(overrides)
    return ExperienceRecord.model_validate(base)


def _signed(record: ExperienceRecord, signer: Sha256Signer) -> ExperienceRecord:
    """쓰기 게이트를 거치지 않고 직접 서명된 레코드를 만든다(주입 공격 테스트용)."""
    fp = record.fingerprint()
    return record.model_copy(update={"content_hash": fp, "signature": signer.sign(fp)})


class TestDetectionRecall:
    """탐지 강화 회상 — 과거 정탐(전 출처 허용)."""

    @pytest.mark.asyncio
    async def test_recalls_tp_from_any_provenance(self) -> None:
        """env_verified TP + auto TP 모두 탐지 회상에 잡힌다."""
        store = InMemoryExperienceStore()
        gate = MemoryWriteGate(store)
        await gate.submit(_rec(signals=["s-env"], provenance=Provenance.ENV_VERIFIED))
        await gate.submit(_rec(signals=["s-auto"], provenance=Provenance.AUTO))
        reader = MemoryReadGate(store)
        hits = await reader.recall(_SCENARIO, RecallPurpose.DETECTION)
        assert len(hits) == 2
        assert all(h.env_verdict == EnvVerdict.CONFIRMED_TP for h in hits)

    @pytest.mark.asyncio
    async def test_detection_excludes_fp(self) -> None:
        """탐지 회상은 오탐(CONFIRMED_FP)을 반환하지 않는다."""
        store = InMemoryExperienceStore()
        gate = MemoryWriteGate(store)
        await gate.submit(_rec(signals=["tp"]))
        await gate.submit(
            _rec(
                signals=["fp"],
                env_verdict=EnvVerdict.CONFIRMED_FP,
                verdict=Verdict.FALSE_POSITIVE,
            )
        )
        reader = MemoryReadGate(store)
        hits = await reader.recall(_SCENARIO, RecallPurpose.DETECTION)
        assert len(hits) == 1
        assert hits[0].signals == ["tp"]


class TestSuppressionRecall:
    """억제 판단 회상 — 과거 오탐(신뢰 출처만)."""

    @pytest.mark.asyncio
    async def test_recalls_trusted_fp(self) -> None:
        """env_verified 오탐은 억제 회상에 잡힌다."""
        store = InMemoryExperienceStore()
        gate = MemoryWriteGate(store)
        await gate.submit(
            _rec(env_verdict=EnvVerdict.CONFIRMED_FP, verdict=Verdict.FALSE_POSITIVE)
        )
        reader = MemoryReadGate(store)
        hits = await reader.recall(_SCENARIO, RecallPurpose.SUPPRESSION)
        assert len(hits) == 1
        assert hits[0].env_verdict == EnvVerdict.CONFIRMED_FP

    @pytest.mark.asyncio
    async def test_suppression_excludes_auto_fp(self) -> None:
        """저장소에 직접 주입된 서명된 AUTO 오탐도 억제 회상에서 제외(미신뢰)."""
        store = InMemoryExperienceStore()
        signer = Sha256Signer()
        injected = _signed(
            _rec(
                provenance=Provenance.AUTO,
                env_verdict=EnvVerdict.CONFIRMED_FP,
                verdict=Verdict.FALSE_POSITIVE,
            ),
            signer,
        )
        await store.awrite(injected)
        reader = MemoryReadGate(store, signer=signer)
        hits = await reader.recall(_SCENARIO, RecallPurpose.SUPPRESSION)
        assert hits == []

    @pytest.mark.asyncio
    async def test_suppression_excludes_tp(self) -> None:
        """억제 회상은 정탐(CONFIRMED_TP)을 반환하지 않는다."""
        store = InMemoryExperienceStore()
        gate = MemoryWriteGate(store)
        await gate.submit(_rec())
        reader = MemoryReadGate(store)
        hits = await reader.recall(_SCENARIO, RecallPurpose.SUPPRESSION)
        assert hits == []


class TestSignatureDefense:
    """쓰기 게이트 우회 주입 방어 — 미서명/위조 폐기."""

    @pytest.mark.asyncio
    async def test_unsigned_record_dropped(self) -> None:
        """서명 없이 직접 주입된 레코드는 회상에서 폐기된다."""
        store = InMemoryExperienceStore()
        await store.awrite(_rec())  # content_hash/signature 비어 있음
        reader = MemoryReadGate(store)
        hits = await reader.recall(_SCENARIO, RecallPurpose.DETECTION)
        assert hits == []

    @pytest.mark.asyncio
    async def test_tampered_record_dropped(self) -> None:
        """서명 후 내용이 변조된 레코드는 지문 불일치로 폐기된다."""
        store = InMemoryExperienceStore()
        signer = Sha256Signer()
        signed = _signed(_rec(), signer)
        tampered = signed.model_copy(update={"verdict": Verdict.FALSE_POSITIVE})
        await store.awrite(tampered)
        reader = MemoryReadGate(store, signer=signer)
        hits = await reader.recall(_SCENARIO, RecallPurpose.DETECTION)
        assert hits == []


class TestLimit:
    """회상 개수 제한."""

    @pytest.mark.asyncio
    async def test_k_limit(self) -> None:
        """k 를 넘는 회상은 잘린다."""
        store = InMemoryExperienceStore()
        gate = MemoryWriteGate(store)
        for i in range(3):
            await gate.submit(_rec(signals=[f"s{i}"]))
        reader = MemoryReadGate(store)
        hits = await reader.recall(_SCENARIO, RecallPurpose.DETECTION, k=2)
        assert len(hits) == 2
