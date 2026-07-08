"""Tier3 위협 헌팅 — 예측/campaign/gap 융합·결정론 우선순위·gap 스코프."""

from core.hunt import HuntPlanner, _PredLike
from tools.coverage import CoverageMatrix


def _pred(tech: str, prob: float) -> _PredLike:
    return _PredLike(next_technique=tech, probability=prob)


class TestSources:
    def test_prediction_hypotheses(self) -> None:
        hs = HuntPlanner(None).plan(predictions=[_pred("T1071", 0.9)])
        assert len(hs) == 1
        assert hs[0].focus == "T1071" and hs[0].source == "prediction"

    def test_campaign_hypotheses(self) -> None:
        hs = HuntPlanner(None).plan(campaign_next=[("S7", 2)])
        assert hs[0].focus == "S7" and hs[0].source == "campaign"

    def test_higher_probability_first(self) -> None:
        hs = HuntPlanner(None).plan(
            predictions=[_pred("T-low", 0.1), _pred("T-high", 0.95)]
        )
        assert hs[0].focus == "T-high"  # 높은 확률 먼저

    def test_prediction_outranks_campaign(self) -> None:
        """소스 base 가중: 예측 > campaign."""
        hs = HuntPlanner(None).plan(
            predictions=[_pred("T1", 0.5)], campaign_next=[("S9", 3)]
        )
        assert hs[0].source == "prediction"


class TestDedupAndOrder:
    def test_dedup_by_focus(self) -> None:
        hs = HuntPlanner(None).plan(
            predictions=[_pred("T1071", 0.3), _pred("T1071", 0.9)]
        )
        assert len(hs) == 1 and hs[0].priority >= 100 + round(0.9 * 20)

    def test_top_k(self) -> None:
        preds = [_pred(f"T{i}", 0.5) for i in range(20)]
        hs = HuntPlanner(None, top_k=5).plan(predictions=preds)
        assert len(hs) == 5

    def test_deterministic_stable_order(self) -> None:
        """동일 입력 → 동일 순서(전순서 tiebreak)."""
        preds = [_pred("Tb", 0.5), _pred("Ta", 0.5)]
        a = [h.focus for h in HuntPlanner(None).plan(predictions=preds)]
        b = [h.focus for h in HuntPlanner(None).plan(predictions=preds)]
        assert a == b
        assert a == ["Ta", "Tb"]  # 동점 → focus 알파벳 안정


class TestGapScope:
    def test_gaps_scoped_to_current_tactic(self) -> None:
        """gap 은 현 tactic order±1 로만 스코프(전역 홍수 방지, Codex H)."""
        cov = CoverageMatrix.from_yaml()
        planner = HuntPlanner(cov)
        # Reconnaissance(order 1) 근방 gap 만 — 후반단계 gap 은 제외
        hs = planner.plan(current_tactics=["Reconnaissance"])
        gap_tactics = {h.tactic for h in hs if h.source == "coverage_gap"}
        # 스코프 밖(예: 후반 CommandAndControl) gap 은 안 나옴
        assert "CommandAndControl" not in gap_tactics

    def test_no_coverage_no_gaps(self) -> None:
        assert HuntPlanner(None).plan(current_tactics=["Reconnaissance"]) == []

    def test_none_tactics_normalized(self) -> None:
        assert HuntPlanner(CoverageMatrix.from_yaml()).plan(current_tactics=None) == []


class TestGraceful:
    def test_empty_inputs(self) -> None:
        assert HuntPlanner(None).plan() == []
