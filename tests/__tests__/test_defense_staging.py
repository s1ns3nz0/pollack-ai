"""DefenseStager 단위 테스트 — 예측 TTP 선제 스테이징(결정론)."""

import pytest

from core.models import AttackPrediction, StagedDefense
from core.staging import DefenseStager
from tools.coverage import Archetype, CoverageMatrix, GapTechnique, TacticCoverage


def _matrix() -> CoverageMatrix:
    archetypes = {
        "C_encrypted_c2": Archetype(
            id="C_encrypted_c2",
            name="암호·터널·난독 C2",
            strategy="메타데이터·행위분석",
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
                    tactic="Command and Control",
                    archetype="C_encrypted_c2",
                    strategy="메타데이터·행위분석",
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


class TestDefenseStager:
    """coverage 조회 기반 스테이징 판정."""

    def test_covered_technique_staged(self) -> None:
        """기존 탐지룰 보유 → staged (감시 강화 후보)."""
        stager = DefenseStager(matrix=_matrix())

        result = stager.stage([_pred("T0855")])

        assert len(result) == 1
        staged = result[0]
        assert isinstance(staged, StagedDefense)
        assert staged.technique == "T0855"
        assert staged.status == "staged"

    def test_planned_technique_accelerate(self) -> None:
        """룰 계획(planned) 상태 → accelerate (배치 가속 후보)."""
        stager = DefenseStager(matrix=_matrix())

        result = stager.stage([_pred("T0812")])

        assert result[0].status == "accelerate"

    def test_uncovered_technique_gap_with_strategy(self) -> None:
        """미커버 → gap + archetype 대응전략 노트."""
        stager = DefenseStager(matrix=_matrix())

        result = stager.stage([_pred("T1573")])

        assert result[0].status == "gap"
        assert "메타데이터" in result[0].note

    def test_unknown_technique_gap(self) -> None:
        """매트릭스에 아예 없는 technique → gap (전략 노트 없음)."""
        stager = DefenseStager(matrix=_matrix())

        result = stager.stage([_pred("T9999")])

        assert result[0].status == "gap"

    def test_empty_predictions_empty_result(self) -> None:
        """예측 없으면 빈 결과."""
        stager = DefenseStager(matrix=_matrix())

        assert stager.stage([]) == []

    def test_default_matrix_loads_from_yaml(self) -> None:
        """matrix 미주입 시 data/attack_coverage.yaml 자동 적재."""
        stager = DefenseStager()

        result = stager.stage([_pred("T0855")])

        assert len(result) == 1


class TestReportStagingIntegration:
    """ReportAgent — 예측 있으면 staged_defenses 노출."""

    @pytest.mark.asyncio
    async def test_report_exposes_staged_defenses(self) -> None:
        """investigation.predictions → report.staged_defenses 채워짐."""
        from agents.report_agent import ReportAgent
        from core.models import (
            Alert,
            InvestigationResult,
            Severity,
            SOCState,
            Verdict,
        )
        from core.settings import Settings
        from core.severity import SeverityEngine

        agent = ReportAgent(
            Settings(), SeverityEngine(), stager=DefenseStager(matrix=_matrix())
        )
        state: SOCState = {
            "alert": Alert(
                id="a1",
                scenario_id="S2",
                title="t",
                severity_baseline=Severity.MEDIUM,
                signals=["sig"],
            ),
            "severity": Severity.MEDIUM,
            "verdict": Verdict.TRUE_POSITIVE,
            "investigation": InvestigationResult(
                predictions=[_pred("T0855"), _pred("T1573")]
            ),
        }

        out = await agent.run(state)

        staged = out["report"].staged_defenses
        assert [s.status for s in staged] == ["staged", "gap"]
