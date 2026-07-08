"""Recovery Matrix — 정탐 후 공격자 축출 → 시스템 복구 → 검증(D3FEND Evict/Restore).

DoD DCO 교리(D3FEND Evict/Restore)의 결정론 구현. 정탐 확정(CONFIRMED_TP) 후
공격자의 현재 도달 tactic 에 매핑된 축출·복구·검증 절차를 `recovery-matrix.yaml`
에서 조립해 report 에 제시한다(실행권은 defense_playbook).

참신 포인트 — 검증 폐루프: 축출 후 outcome_probe 가 reoccurred(재발)를 관측하면
"축출 실패, 공격자 잔존" 으로 판정한다(RecoveryVerifier). 재심·outcome 과 동형의
사후 검증. LLM 무관, 전 과정 결정론.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from core.models import RecoveryPlan, RecoveryStep
from core.outcome import Observation
from core.policy_loader import load_policy_mapping
from tools.coverage import CoverageMatrix
from utils.logging import get_logger

_logger = get_logger("recovery")


class EvictionOutcome(StrEnum):
    """축출 검증 결과."""

    SUCCESS = "success"  # 축출 후 무재발 — 공격자 제거 확인
    FAILED = "failed"  # 축출 후 재발 — 공격자 잔존(재축출 필요)
    NOT_APPLICABLE = "not_applicable"  # 축출 미실행 — 검증 대상 아님


_POLICY = Path(__file__).resolve().parent / "policy" / "recovery-matrix.yaml"


def _steps(raw: object) -> list[RecoveryStep]:
    """YAML 단계 목록 → RecoveryStep 리스트(action 있는 것만)."""
    if not isinstance(raw, list):
        return []
    out: list[RecoveryStep] = []
    for item in raw:
        if isinstance(item, dict) and item.get("action"):
            out.append(
                RecoveryStep(
                    action=str(item["action"]),
                    d3fend_id=str(item.get("d3fend", "")),
                )
            )
    return out


class RecoveryMatrix:
    """recovery-matrix.yaml 정책 로더 — tactic → 축출/복구/검증 플랜."""

    def __init__(self, matrix: dict[str, RecoveryPlan]) -> None:
        self._matrix = matrix

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> RecoveryMatrix:
        """Recovery 매트릭스 YAML 을 적재한다.

        Args:
            path: 정책 경로. 생략 시 기본 recovery-matrix.yaml.

        Returns:
            로드된 RecoveryMatrix.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        raw = load_policy_mapping(path, _POLICY, label="Recovery 매트릭스")
        matrix: dict[str, RecoveryPlan] = {}
        raw_matrix = raw.get("matrix", {})
        if isinstance(raw_matrix, dict):
            for tactic, cell in raw_matrix.items():
                if not isinstance(cell, dict):
                    continue
                matrix[str(tactic)] = RecoveryPlan(
                    tactic=str(tactic),
                    evict_steps=_steps(cell.get("evict")),
                    restore_steps=_steps(cell.get("restore")),
                    verify=str(cell.get("verify", "")),
                )
        return cls(matrix)

    def plan_for(self, tactic: str) -> RecoveryPlan | None:
        """tactic 의 recovery 플랜을 반환한다(미정의면 None)."""
        return self._matrix.get(tactic)


class RecoveryPlanner:
    """정탐 alert 의 도달 tactic → RecoveryPlan 조립(최고 order 단계 기준).

    Args:
        coverage: tactic order 매핑 커버리지 매트릭스.
        recovery: tactic → 축출/복구/검증 매트릭스.
    """

    def __init__(self, coverage: CoverageMatrix, recovery: RecoveryMatrix) -> None:
        self._cov = coverage
        self._recovery = recovery

    def plan(self, tactics: list[str]) -> RecoveryPlan | None:
        """도달 tactic 중 recovery 가 정의된 최고 order 단계의 플랜을 반환한다.

        Args:
            tactics: 정탐 alert 이 도달한 tactic 목록.

        Returns:
            최고 order recovery 플랜, 없으면 None.
        """
        best: RecoveryPlan | None = None
        best_order = -1
        for tactic in tactics:
            plan = self._recovery.plan_for(tactic)
            if plan is None:
                continue
            order = self._cov.tactic_order(tactic) or 0
            if order > best_order:
                best_order = order
                best = plan
        return best


class RecoveryVerifier:
    """축출 검증 폐루프 — 축출 후 재발(reoccurred) 관측 시 축출 실패 판정.

    RecoveryPlan 실행 후 outcome_probe 가 같은 위협의 재발을 관측하면 축출이
    실패한 것(공격자 잔존)이다. 재심·outcome 과 동형의 사후 검증 — 축출 실패는
    metrics 로 계측해 재축출·격리확대 재발령의 근거가 된다.
    """

    def check(self, obs: Observation) -> EvictionOutcome:
        """관측을 축출 검증 결과로 판정한다.

        Args:
            obs: 시뮬 후속 관측(recovery_applied·reoccurred 포함).

        Returns:
            SUCCESS(무재발) | FAILED(재발) | NOT_APPLICABLE(축출 미실행).
        """
        if not obs.recovery_applied:
            return EvictionOutcome.NOT_APPLICABLE
        if obs.reoccurred:
            from app.metrics import metrics

            metrics().record_eviction_failed()
            _logger.warning(
                "eviction FAILED: alert=%s 축출 후 재발 — 공격자 잔존",
                obs.alert_id,
            )
            return EvictionOutcome.FAILED
        return EvictionOutcome.SUCCESS
