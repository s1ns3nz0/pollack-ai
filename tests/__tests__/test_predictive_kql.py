"""예측 gap → AutoKql 연결 테스트 — 미커버 예측 TTP 를 KQL draft 로."""

import pytest

from agents.auto_kql_rule_agent import AutoKqlRuleAgent
from core.models import AttackPrediction, RulePullRequest
from core.predictive_kql import gap_techniques, run_kql_for_predictions
from core.settings import Settings
from core.staging import DefenseStager
from tools.coverage import Archetype, CoverageMatrix, GapTechnique, TacticCoverage


def _matrix() -> CoverageMatrix:
    archetypes = {
        "C_encrypted_c2": Archetype(
            id="C_encrypted_c2", name="암호 C2", strategy="메타데이터 분석"
        )
    }
    tactics = [
        TacticCoverage(
            name="Lateral Movement",
            order=8,
            covered=["T0855"],
            planned=["T0812"],
            uncovered=[
                GapTechnique(
                    id="T1573",
                    name="Encrypted Channel",
                    tactic="C2",
                    archetype="C_encrypted_c2",
                    strategy="메타데이터 분석",
                )
            ],
        )
    ]
    return CoverageMatrix(tactics, archetypes)


def _pred(technique: str) -> AttackPrediction:
    return AttackPrediction(
        next_technique=technique,
        probability=0.8,
        support_count=3,
        basis_actor_id="APT-X",
    )


class _FakeLLM:
    """항상 유효 KQL 블록을 반환하는 LLM 더블."""

    async def acomplete(self, system: str, user: str) -> str:
        return "```kql\nSecurityEvent | where EventID == 4688\n```"


class _StubPublisher:
    async def apublish(self, pr: RulePullRequest) -> RulePullRequest:
        return pr.model_copy(update={"status": "opened", "url": "https://pr/1"})


class TestGapTechniques:
    """staged_defenses 에서 gap(미커버) technique 만 추출."""

    def test_extracts_only_gap(self) -> None:
        stager = DefenseStager(matrix=_matrix())
        preds = [_pred("T0855"), _pred("T0812"), _pred("T1573"), _pred("T9999")]

        gaps = gap_techniques(preds, stager)

        # T0855=staged(covered), T0812=accelerate(planned) 제외.
        # T1573·T9999=gap 만.
        assert set(gaps) == {"T1573", "T9999"}

    def test_empty_predictions(self) -> None:
        stager = DefenseStager(matrix=_matrix())
        assert gap_techniques([], stager) == []

    def test_all_covered_no_gap(self) -> None:
        stager = DefenseStager(matrix=_matrix())
        assert gap_techniques([_pred("T0855")], stager) == []


class TestRunKqlForPredictions:
    """gap 예측 → AutoKqlRuleAgent.run_for 호출."""

    @pytest.mark.asyncio
    async def test_gap_predictions_drafted(self) -> None:
        """gap technique 이 KQL draft 로 처리됨(applied 증가)."""
        stager = DefenseStager(matrix=_matrix())
        agent = AutoKqlRuleAgent(Settings(), llm=_FakeLLM(), publisher=_StubPublisher())
        preds = [_pred("T0855"), _pred("T1573")]

        report = await run_kql_for_predictions(preds, stager, agent)

        # T1573(gap) 1건만 draft — T0855(covered)는 제외.
        assert report.auto_applied == 1

    @pytest.mark.asyncio
    async def test_no_gap_no_draft(self) -> None:
        """gap 없으면 draft 시도 안 함."""
        stager = DefenseStager(matrix=_matrix())
        agent = AutoKqlRuleAgent(Settings(), llm=_FakeLLM(), publisher=_StubPublisher())

        report = await run_kql_for_predictions([_pred("T0855")], stager, agent)

        assert report.auto_applied == 0
