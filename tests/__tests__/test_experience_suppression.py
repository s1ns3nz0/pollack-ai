"""경험메모리 억제 배선 — 맥락 FP 억제 + 미믹리/포이즈닝 가드 검증.

위험 방향(TP→FP)이므로: 신뢰 출처·동일 신호패턴일 때만 억제되고, 진짜 공격(다른
신호)·미신뢰 출처(AUTO)로는 억제되지 않음을 확인한다.
"""

import pytest

from agents.investigation_agent import InvestigationAgent
from agents.validation_agent import signal_judge
from core.experience import (
    InMemoryExperienceStore,
    MemoryReadGate,
    MemoryWriteGate,
    Sha256Signer,
)
from core.models import (
    Alert,
    EnvVerdict,
    ExperienceRecord,
    InvestigationResult,
    JudgeFeatures,
    Provenance,
    RetrievedChunk,
    Severity,
    SOCState,
    Verdict,
)
from core.settings import Settings

_SCENARIO = "UAV-AUTH-RETASK-001"
_SIGNALS = ["기체 재지정 1건(인가 계정·근무시간·화이트리스트)"]


def _settings() -> Settings:
    return Settings()


def _alert(signals: list[str] | None = None, **overrides: object) -> Alert:
    base: dict[str, object] = {
        "id": "A",
        "scenario_id": _SCENARIO,
        "title": "인가 재지정",
        "asset_tier": "T2-Important",
        "mission_phase": "on-station",
        "severity_baseline": Severity.MEDIUM,
        "signals": list(_SIGNALS) if signals is None else signals,
        "expected_detection": {"sigma_rule": "retask.yml"},
        "ground_truth": Verdict.FALSE_POSITIVE,
    }
    base.update(overrides)
    return Alert.model_validate(base)


def _fp_record(
    signals: list[str] | None = None,
    provenance: Provenance = Provenance.ENV_VERIFIED,
) -> ExperienceRecord:
    return ExperienceRecord.model_validate(
        {
            "scenario_id": _SCENARIO,
            "signals": list(_SIGNALS) if signals is None else signals,
            "asset_id": "UAV",
            "asset_tier": "T2-Important",
            "verdict": Verdict.FALSE_POSITIVE,
            "severity": Severity.LOW,
            "judge_features": JudgeFeatures(
                has_signal=True, has_rule=True, corroborated=True, confidence=0.6
            ),
            "env_verdict": EnvVerdict.CONFIRMED_FP,
            "provenance": provenance,
        }
    )


def _signed(record: ExperienceRecord, signer: Sha256Signer) -> ExperienceRecord:
    fp = record.fingerprint()
    return record.model_copy(update={"content_hash": fp, "signature": signer.sign(fp)})


def _inv(**overrides: object) -> InvestigationResult:
    base: dict[str, object] = {
        "similar_cases": [],
        "confidence": 0.6,  # 근거충분 → 기본 TP 후보
        "experience_corroboration": 0,
        "suppression_corroboration": 0,
    }
    base.update(overrides)
    return InvestigationResult.model_validate(base)


class _StubRetriever:
    """kb/ 신뢰 청크를 반환 → similar_cases 채워 corroborated(기본 TP)."""

    async def aretrieve(self, query: str, k: int = 5) -> list[RetrievedChunk]:
        return [RetrievedChunk(text="유사사례", source="kb/case.md", score=0.9)]


class TestSuppressionRecall:
    """Investigation 의 억제 회상 — 좁은(동일 신호패턴·신뢰출처) 집계."""

    @pytest.mark.asyncio
    async def test_matching_trusted_fp_is_counted(self) -> None:
        """동일 신호패턴 신뢰 과거 오탐 → suppression_corroboration 채워짐."""
        store = InMemoryExperienceStore()
        await MemoryWriteGate(store).submit(_fp_record())
        agent = InvestigationAgent(_settings(), None, experience=MemoryReadGate(store))
        out = await agent.run({"alert": _alert()})
        assert out["investigation"].suppression_corroboration == 1

    @pytest.mark.asyncio
    async def test_different_signals_not_counted(self) -> None:
        """다른 신호(진짜 공격)면 억제 집계 0 — 묻히지 않음."""
        store = InMemoryExperienceStore()
        await MemoryWriteGate(store).submit(_fp_record())
        agent = InvestigationAgent(_settings(), None, experience=MemoryReadGate(store))
        out = await agent.run({"alert": _alert(signals=["실제 GNSS 스푸핑 잔차 급증"])})
        assert out["investigation"].suppression_corroboration == 0

    @pytest.mark.asyncio
    async def test_auto_fp_not_counted_poisoning_guard(self) -> None:
        """저장소에 직접 주입된 서명된 AUTO 오탐도 억제에 안 잡힘(미신뢰)."""
        store = InMemoryExperienceStore()
        signer = Sha256Signer()
        await store.awrite(_signed(_fp_record(provenance=Provenance.AUTO), signer))
        agent = InvestigationAgent(
            _settings(), None, experience=MemoryReadGate(store, signer=signer)
        )
        out = await agent.run({"alert": _alert()})
        assert out["investigation"].suppression_corroboration == 0


class TestJudgeSuppression:
    """signal_judge — 동일패턴 신뢰 과거 오탐일 때만 TP→FP 억제."""

    def test_tp_suppressed_by_trusted_fp(self) -> None:
        """기본 TP(신호+룰+근거)인데 억제 근거 있으면 FP."""
        state: SOCState = {
            "alert": _alert(),
            "investigation": _inv(suppression_corroboration=1),
        }
        assert signal_judge(state) == Verdict.FALSE_POSITIVE

    def test_tp_unchanged_without_suppression(self) -> None:
        """억제 근거 없으면 기본 TP 유지(과억제 방지)."""
        state: SOCState = {
            "alert": _alert(),
            "investigation": _inv(suppression_corroboration=0),
        }
        assert signal_judge(state) == Verdict.TRUE_POSITIVE


class TestEndToEndNarrowSuppression:
    """통합 — 맥락 FP는 억제, 같은 시나리오 진짜 공격은 억제 안 됨."""

    @pytest.mark.asyncio
    async def test_context_fp_suppressed_but_attack_survives(self) -> None:
        """동일 신호 = 억제(FP), 다른 신호(공격) = 통과(TP)."""
        store = InMemoryExperienceStore()
        await MemoryWriteGate(store).submit(_fp_record())
        agent = InvestigationAgent(
            _settings(), _StubRetriever(), experience=MemoryReadGate(store)
        )

        benign = _alert()  # 과거 FP 와 동일 신호
        out_b = await agent.run({"alert": benign})
        verdict_b = signal_judge(
            {"alert": benign, "investigation": out_b["investigation"]}
        )
        assert verdict_b == Verdict.FALSE_POSITIVE  # 맥락 FP 억제

        attack = _alert(signals=["실제 GNSS 스푸핑 잔차 급증"])  # 다른 신호
        out_a = await agent.run({"alert": attack})
        verdict_a = signal_judge(
            {"alert": attack, "investigation": out_a["investigation"]}
        )
        assert verdict_a == Verdict.TRUE_POSITIVE  # 진짜 공격은 통과
