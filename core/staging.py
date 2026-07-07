"""예측 TTP 선제 방어 스테이징 — coverage 매트릭스 결정론 조회(예측 폐루프).

SequencePredictor 가 발행한 다음 technique 후보를 `data/attack_coverage.yaml`
탐지상태와 대조해 스테이징 판정을 만든다. LLM 없음 — 전 과정 결정론.
Watch List / AutoKql 발행 훅은 AutoKqlRuleAgent(A-2) 후속 PR 에서 연결한다.
"""

from __future__ import annotations

from core.models import AttackPrediction, StagedDefense
from tools.coverage import CoverageMatrix
from utils.logging import get_logger

_logger = get_logger("DefenseStager")


class DefenseStager:
    """예측 → 스테이징 판정기(결정론).

    Args:
        matrix: 커버리지 매트릭스. 생략 시 기본 YAML 자동 적재.
    """

    def __init__(self, matrix: CoverageMatrix | None = None) -> None:
        self._matrix = matrix or CoverageMatrix.from_yaml()
        # technique → (status, tactic, strategy_note) 역인덱스(결정론).
        self._index: dict[str, tuple[str, str, str]] = {}
        for tactic in self._matrix.tactics:
            for tech in tactic.covered:
                self._index.setdefault(tech, ("staged", tactic.name, ""))
            for tech in tactic.planned:
                self._index.setdefault(tech, ("accelerate", tactic.name, ""))
            for gap in tactic.uncovered:
                self._index.setdefault(gap.id, ("gap", tactic.name, gap.strategy))

    def stage(self, predictions: list[AttackPrediction]) -> list[StagedDefense]:
        """예측 목록을 스테이징 판정으로 변환한다.

        Args:
            predictions: SequencePredictor 발행 다음 technique 후보.

        Returns:
            예측 순서 그대로의 스테이징 판정 목록. 예측 없으면 빈 리스트.
        """
        out: list[StagedDefense] = []
        for pred in predictions:
            status, tactic, note = self._index.get(pred.next_technique, ("gap", "", ""))
            out.append(
                StagedDefense(
                    technique=pred.next_technique,
                    status=status,
                    tactic=tactic,
                    probability=pred.probability,
                    note=note,
                )
            )
            _logger.info(
                "선제 스테이징: tech=%s status=%s p=%.2f",
                pred.next_technique,
                status,
                pred.probability,
            )
        return out
