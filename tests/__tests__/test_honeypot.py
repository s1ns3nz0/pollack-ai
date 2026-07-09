"""HoneypotPlanner 단위 테스트 — 예측 유도 디코이 배치(결정론).

예측된 다음 TTP 표적 자산에 디코이를 미리 배치하고, 디코이 접촉(signature 노출)을
확정 정탐으로 판정한다. 전 과정 결정론 — LLM 무관.
"""

import pytest

from core.honeypot import (
    TECHNIQUE_DECOY_MAP,
    DecoyType,
    HoneypotPlanner,
)
from core.models import AttackPrediction, DecoyPlacement


def _pred(technique: str, probability: float = 0.8) -> AttackPrediction:
    return AttackPrediction(
        next_technique=technique,
        probability=probability,
        support_count=3,
        basis_actor_id="APT-X",
    )


class TestHoneypotPlan:
    """예측 → 디코이 배치안 생성(결정론)."""

    def test_prediction_maps_to_decoy_placement(self) -> None:
        """C2 계열 예측(T0855) → GCS_SESSION 디코이 배치."""
        planner = HoneypotPlanner()

        placements = planner.plan([_pred("T0855")])

        assert len(placements) == 1
        placement = placements[0]
        assert isinstance(placement, DecoyPlacement)
        assert placement.decoy_type == DecoyType.GCS_SESSION
        assert placement.target_technique == "T0855"
        assert placement.probability == 0.8
        assert placement.signature  # 비어있지 않은 결정론 토큰
        assert placement.decoy_id

    def test_each_mapped_decoy_type_covered(self) -> None:
        """4대 디코이 유형 각각 대표 technique 이 매핑된다."""
        planner = HoneypotPlanner()
        cases = {
            "T0855": DecoyType.GCS_SESSION,
            "T0859": DecoyType.CREDENTIAL,
            "T0811": DecoyType.FILE_BAIT,
            "T0801": DecoyType.TELEMETRY_ENDPOINT,
        }
        for technique, expected in cases.items():
            placement = planner.plan([_pred(technique)])[0]
            assert placement.decoy_type == expected

    def test_signature_is_deterministic(self) -> None:
        """동일 (technique, target_asset) 입력 → 동일 signature/decoy_id."""
        planner = HoneypotPlanner()

        first = planner.plan([_pred("T0855")], asset_hint="uav-01")[0]
        second = planner.plan([_pred("T0855")], asset_hint="uav-01")[0]

        assert first.signature == second.signature
        assert first.decoy_id == second.decoy_id
        assert first.target_asset == "uav-01"

    def test_different_asset_yields_different_signature(self) -> None:
        """target_asset 이 다르면 signature 도 갈린다(자산별 미끼 구분)."""
        planner = HoneypotPlanner()

        a = planner.plan([_pred("T0855")], asset_hint="uav-01")[0]
        b = planner.plan([_pred("T0855")], asset_hint="uav-02")[0]

        assert a.signature != b.signature

    def test_unmapped_technique_skipped(self) -> None:
        """매핑 없는 technique 은 디코이 배치에서 제외."""
        planner = HoneypotPlanner()

        placements = planner.plan([_pred("T9999")])

        assert placements == []

    def test_mixed_predictions_only_mapped_placed(self) -> None:
        """매핑/비매핑 혼재 시 매핑된 것만 순서대로 배치."""
        planner = HoneypotPlanner()

        placements = planner.plan([_pred("T9999"), _pred("T0855"), _pred("T0859")])

        assert [p.target_technique for p in placements] == ["T0855", "T0859"]

    def test_empty_predictions_empty_result(self) -> None:
        """예측 없으면 빈 배치안."""
        planner = HoneypotPlanner()

        assert planner.plan([]) == []

    def test_map_is_module_constant(self) -> None:
        """technique→DecoyType 매핑은 모듈 상수로 노출된다."""
        assert TECHNIQUE_DECOY_MAP["T0855"] == DecoyType.GCS_SESSION


class TestDecoyHit:
    """디코이 접촉(signature 노출) = 확정 정탐 탐지."""

    def test_decoy_hit_detected(self) -> None:
        """알람 신호에 디코이 signature 가 나타나면 그 placement 반환."""
        planner = HoneypotPlanner()
        placements = planner.plan([_pred("T0855")])
        sig = placements[0].signature

        hit = planner.is_decoy_hit(["some_signal", sig], placements)

        assert hit is placements[0]

    def test_no_contact_returns_none(self) -> None:
        """디코이 미접촉(signature 부재) → None."""
        planner = HoneypotPlanner()
        placements = planner.plan([_pred("T0855")])

        assert planner.is_decoy_hit(["unrelated", "signal"], placements) is None

    def test_empty_placements_returns_none(self) -> None:
        """배치안이 비면 hit 없음."""
        planner = HoneypotPlanner()

        assert planner.is_decoy_hit(["anything"], []) is None


class TestDecoyMetrics:
    """디코이 배치/접촉 카운터 + 렌더."""

    def test_record_and_ratio(self) -> None:
        """placed 3 / 예측디코이 hit 1 → hit_ratio 0.333(전용 카운터)."""
        from app.metrics import _Counters

        c = _Counters()
        c.record_decoy_placed(3)
        c.record_decoy_placement_hit()

        stats = c.decoy_stats()
        assert stats["placed"] == 3
        assert stats["hits"] == 1
        assert stats["hit_ratio"] == 0.333

    def test_ratio_not_conflated_with_canary_hits(self) -> None:
        """deception canary hit 은 예측-디코이 hit_ratio 에 섞이지 않음(Codex)."""
        from app.metrics import _Counters

        c = _Counters()
        c.record_decoy_placed(2)
        c.record_decoy_hit()  # deception canary — 별 population
        stats = c.decoy_stats()
        assert stats["hits"] == 0 and stats["hit_ratio"] == 0.0

    def test_empty_stats(self) -> None:
        """배치 0건이면 통계 없음(division 방지)."""
        from app.metrics import _Counters

        assert _Counters().decoy_stats() == {}

    def test_render_text_exposes_decoy_metrics(self) -> None:
        """/metrics 텍스트에 soc_decoy 라인 노출."""
        from app.metrics import metrics, render_text

        metrics().record_decoy_placed()
        metrics().record_decoy_hit()

        text = render_text()
        assert "soc_decoy_placed_total" in text
        assert "soc_decoy_hit_total" in text
        assert "soc_decoy_hit_ratio" in text


class TestReportHoneypotIntegration:
    """ReportAgent — 예측 있으면 planner 주입 시 decoy_placements 노출."""

    @pytest.mark.asyncio
    async def test_report_exposes_decoy_placements(self) -> None:
        """investigation.predictions → report.decoy_placements 채워짐."""
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

        agent = ReportAgent(Settings(), SeverityEngine(), planner=HoneypotPlanner())
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
                predictions=[_pred("T0855"), _pred("T9999"), _pred("T0859")]
            ),
        }

        out = await agent.run(state)

        placements = out["report"].decoy_placements
        assert [p.target_technique for p in placements] == ["T0855", "T0859"]
        assert [p.decoy_type for p in placements] == [
            DecoyType.GCS_SESSION,
            DecoyType.CREDENTIAL,
        ]

    @pytest.mark.asyncio
    async def test_report_no_planner_no_placements(self) -> None:
        """planner 미주입 시 decoy_placements 는 빈 리스트."""
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

        agent = ReportAgent(Settings(), SeverityEngine())
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
            "investigation": InvestigationResult(predictions=[_pred("T0855")]),
        }

        out = await agent.run(state)

        assert out["report"].decoy_placements == []
