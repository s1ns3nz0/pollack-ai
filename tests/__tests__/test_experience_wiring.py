"""경험메모리 배선 — Investigation 회상 부스트 + signal_judge 자문(하한 불변) 검증."""

import pytest

from agents.investigation_agent import InvestigationAgent
from agents.validation_agent import signal_judge
from core.exceptions import ExperienceStoreError
from core.experience import (
    InMemoryExperienceStore,
    MemoryReadGate,
    MemoryWriteGate,
)
from core.models import (
    Alert,
    EnvVerdict,
    ExperienceRecord,
    InvestigationResult,
    JudgeFeatures,
    Provenance,
    Severity,
    SOCState,
    Verdict,
)
from core.settings import Settings

_SCENARIO = "UAV-GPS-SPOOF-001"


def _settings() -> Settings:
    return Settings()


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "id": "ALERT-TEST",
        "scenario_id": _SCENARIO,
        "title": "GPS 스푸핑",
        "asset_tier": "T1-Critical",
        "mission_phase": "ingress",
        "severity_baseline": Severity.HIGH,
        "signals": ["GNSS-INS 잔차 급증"],
        "expected_detection": {"sigma_rule": "uav_gps_spoof_residual.yml"},
        "defense_playbook": {"id": "PB-NAV-RTB-01", "actions": ["INS 페일오버"]},
        "ground_truth": Verdict.TRUE_POSITIVE,
    }
    base.update(overrides)
    return Alert.model_validate(base)


def _exp_record(**overrides: object) -> ExperienceRecord:
    base: dict[str, object] = {
        "scenario_id": _SCENARIO,
        "signals": ["GNSS-INS 잔차 급증"],
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


def _inv(**overrides: object) -> InvestigationResult:
    base: dict[str, object] = {
        "similar_cases": [],
        "confidence": 0.3,
        "experience_corroboration": 0,
    }
    base.update(overrides)
    return InvestigationResult.model_validate(base)


class _FailingStore:
    """조회 시 장애를 던지는 저장소(graceful degrade 검증용)."""

    async def aexists(self, fingerprint: str) -> bool:
        return False

    async def awrite(self, record: ExperienceRecord) -> None:
        return None

    async def aquery(self, scenario_id: str, k: int = 20) -> list[ExperienceRecord]:
        raise ExperienceStoreError("저장소 조회 장애")


async def _seed(store: InMemoryExperienceStore) -> None:
    """신뢰 과거 정탐 1건을 게이트 경유로 적립(서명됨)."""
    await MemoryWriteGate(store).submit(_exp_record())


class TestInvestigationExperience:
    """Investigation 의 exp/ 회상 부스트."""

    @pytest.mark.asyncio
    async def test_recall_boosts_confidence_and_corroboration(self) -> None:
        """과거 정탐 회상 → experience_corroboration 채워지고 신뢰도 상승."""
        store = InMemoryExperienceStore()
        await _seed(store)
        agent = InvestigationAgent(_settings(), None, experience=MemoryReadGate(store))
        out = await agent.run({"alert": _alert()})
        inv = out["investigation"]
        assert inv.experience_corroboration == 1
        assert inv.confidence >= 0.5  # 0.3 기준 + 0.2 경험 부스트

    @pytest.mark.asyncio
    async def test_no_experience_reader_is_zero(self) -> None:
        """경험 게이트 미주입이면 보강 0(기존 동작 불변)."""
        agent = InvestigationAgent(_settings(), None)
        out = await agent.run({"alert": _alert()})
        assert out["investigation"].experience_corroboration == 0

    @pytest.mark.asyncio
    async def test_store_failure_degrades_gracefully(self) -> None:
        """저장소 장애 시 보강 0 으로 강등(핫패스 계속 — 크래시 없음)."""
        agent = InvestigationAgent(
            _settings(), None, experience=MemoryReadGate(_FailingStore())
        )
        out = await agent.run({"alert": _alert()})
        assert out["investigation"].experience_corroboration == 0


class TestJudgeExperienceAdvisory:
    """signal_judge — 경험 자문은 corroboration 으로만, 하한은 불변."""

    def test_novel_tp_caught_via_experience(self) -> None:
        """근거부족(유사사례 0·conf 0.3)이라도 과거 정탐 있으면 정탐."""
        state: SOCState = {
            "alert": _alert(),
            "investigation": _inv(experience_corroboration=1),
        }
        assert signal_judge(state) == Verdict.TRUE_POSITIVE

    def test_without_experience_stays_fp(self) -> None:
        """경험 없고 근거부족이면 오탐(기존 보수 동작)."""
        state: SOCState = {
            "alert": _alert(),
            "investigation": _inv(experience_corroboration=0),
        }
        assert signal_judge(state) == Verdict.FALSE_POSITIVE

    def test_floor_unchanged_without_rule(self) -> None:
        """매칭 룰 없으면 경험이 아무리 많아도 오탐(결정론 하한 불변)."""
        state: SOCState = {
            "alert": _alert(expected_detection={}),
            "investigation": _inv(experience_corroboration=5),
        }
        assert signal_judge(state) == Verdict.FALSE_POSITIVE
