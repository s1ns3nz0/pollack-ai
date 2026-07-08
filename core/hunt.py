"""Tier3 위협 헌팅 — 예측/campaign/coverage-gap 신호 융합 hunt 백로그(결정론).

DoD CSSP tiered SOC 의 Tier3(위협 헌팅) 기능. 흩어진 선제 신호(예측 next-technique·
campaign next_expected·현 tactic 범위 미탐)를 **우선순위 hunt 가설**로 융합.
"헌터가 지금 뭘 선제로 찾아야 하나". 순수 결정론·읽기전용(자문) — 자동 대응·룰 변경·
메모리 변이 없음.

필드 소유권(중복 회피): staged_defenses=방어 준비/스테이징, hunt_hypotheses=분석가 hunt
백로그, hunt_candidates=legacy 예측나열(병존). AutoKQL 은 별 lane(쿼리 초안).

트러스트(Codex 반영): predictions/campaign 은 신뢰 파이프라인 산출, coverage 정적.
alert 파생 scenario_id/tactics 는 자문 hunt 를 *스코프* 할 뿐 — 대응 실행·메모리 변이·룰
변경 불가. 가용 시 profile 산 tactic 선호.

Spec: docs/superpowers/specs/2026-07-08-tier3-threat-hunt-design.md
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from pydantic import BaseModel

from core.models import HuntHypothesis
from tools.coverage import CoverageMatrix


@runtime_checkable
class PredictionLike(Protocol):
    """예측 최소 계약 — AttackPrediction 이 구조적으로 만족."""

    next_technique: str
    probability: float


# 소스 base 가중 + 정렬 rank(동점 tiebreak) — 예측 > campaign > gap.
_BASE_PRED = 100
_BASE_CAMP = 80
_BASE_GAP = 50
_SOURCE_RANK = {"prediction": 0, "campaign": 1, "coverage_gap": 2}
_DEFAULT_TOP_K = 10
# coverage-gap 스코프 — 현 tactic order 로부터 ±범위(Codex H: 전역 gap 홍수 방지).
_GAP_SCOPE = 1


class _PredLike(BaseModel):
    """HuntPlanner 가 받는 예측 최소 계약(AttackPrediction 호환)."""

    next_technique: str
    probability: float = 0.0


class HuntPlanner:
    """예측/campaign/coverage-gap → 우선순위 hunt 가설(결정론·읽기전용).

    Args:
        coverage: coverage-gap 스코프·tactic order 산정용. 미주입 시 gap 소스 생략.
        top_k: 반환 상한(기본 10).
    """

    def __init__(
        self, coverage: CoverageMatrix | None = None, top_k: int = _DEFAULT_TOP_K
    ) -> None:
        self._cov = coverage
        self._top_k = top_k

    def plan(
        self,
        predictions: Sequence[PredictionLike] | None = None,
        campaign_next: list[tuple[str, int]] | None = None,
        current_tactics: object = None,
    ) -> list[HuntHypothesis]:
        """세 신호를 융합해 우선순위 hunt 가설을 산출한다(결정론 전순서).

        Args:
            predictions: 예측(next_technique·probability). None→생략.
            campaign_next: (next_expected 시나리오, matched 진행도) 목록. None→생략.
            current_tactics: 현 tactic 목록(None/비-list/미매핑 → [] 정규화).

        Returns:
            (-priority, source_rank, tactic, focus) 전순서 정렬 top_k. 입력 부재 시 빈.
        """
        tactics = self._norm_tactics(current_tactics)
        out: list[HuntHypothesis] = []
        out.extend(self._from_predictions(predictions or []))
        out.extend(self._from_campaign(campaign_next or []))
        out.extend(self._from_gaps(tactics))
        return self._finalize(out)

    def _from_predictions(
        self, preds: Sequence[PredictionLike]
    ) -> list[HuntHypothesis]:
        res: list[HuntHypothesis] = []
        for p in preds:
            if not p.next_technique:
                continue
            prob = max(0.0, min(1.0, p.probability))
            tactic = self._cov.tactic_of(p.next_technique) if self._cov else ""
            res.append(
                HuntHypothesis(
                    focus=p.next_technique,
                    source="prediction",
                    priority=_BASE_PRED + round(prob * 20),
                    tactic=tactic or "",
                    rationale=f"예측 다음 technique(p={prob:.2f})",
                    target_hint=f"tactic={tactic or '미상'}",
                )
            )
        return res

    def _from_campaign(self, camp: list[tuple[str, int]]) -> list[HuntHypothesis]:
        res: list[HuntHypothesis] = []
        for scenario, matched in camp:
            if not scenario:
                continue
            res.append(
                HuntHypothesis(
                    focus=scenario,
                    source="campaign",
                    priority=_BASE_CAMP + max(0, matched),
                    rationale=f"campaign 다음 예상 시나리오(진행 {matched}단계)",
                    target_hint=f"scenario={scenario}",
                )
            )
        return res

    def _from_gaps(self, tactics: list[str]) -> list[HuntHypothesis]:
        if self._cov is None or not tactics:
            return []
        orders = {o for t in tactics if (o := self._cov.tactic_order(t)) is not None}
        if not orders:
            return []
        scope = {o + d for o in orders for d in range(-_GAP_SCOPE, _GAP_SCOPE + 1)}
        res: list[HuntHypothesis] = []
        # 결정론: (tactic_order, gap.id) 정렬로 안정화.
        gaps = sorted(
            self._cov.gaps(),
            key=lambda g: (self._cov.tactic_order(g.tactic) or 0, g.id),  # type: ignore[union-attr]
        )
        for g in gaps:
            order = self._cov.tactic_order(g.tactic)
            if order is None or order not in scope:
                continue
            res.append(
                HuntHypothesis(
                    focus=g.id,
                    source="coverage_gap",
                    priority=_BASE_GAP + order,
                    tactic=g.tactic,
                    rationale=f"현 단계 인접 미탐 기법({g.tactic})",
                    target_hint=f"tactic={g.tactic}",
                )
            )
        return res

    def _finalize(self, items: list[HuntHypothesis]) -> list[HuntHypothesis]:
        """focus dedup(최고 우선) + 전순서 정렬 + top_k."""
        best: dict[str, HuntHypothesis] = {}
        for h in items:
            cur = best.get(h.focus)
            if cur is None or self._sort_key(h) < self._sort_key(cur):
                best[h.focus] = h
        ordered = sorted(best.values(), key=self._sort_key)
        return ordered[: self._top_k]

    @staticmethod
    def _sort_key(h: HuntHypothesis) -> tuple[int, int, str, str]:
        """전순서 키 — 우선순위 내림차 → 소스 rank → tactic → focus(안정 tiebreak)."""
        return (-h.priority, _SOURCE_RANK.get(h.source, 9), h.tactic, h.focus)

    @staticmethod
    def _norm_tactics(raw: object) -> list[str]:
        """current_tactics 정규화 — None/비-list → []."""
        if not isinstance(raw, list):
            return []
        return [str(t) for t in raw if t]
