"""OODA 결심 여유 — 템포 판정·양델타·degenerate 엣지·정직성."""

from core.models import ActorKillChainStep
from core.ooda import (
    OODA_SOURCES,
    DecisionAdvantageAssessor,
    ooda_alignment,
)


def _kc(*ts_list: str) -> list[ActorKillChainStep]:
    return [
        ActorKillChainStep(ts=ts, alert_id=f"a{i}", scenario_id="S1", technique="T1")
        for i, ts in enumerate(ts_list)
    ]


class TestTempo:
    def test_margin_when_latency_below_cadence(self) -> None:
        """브리핑 지연 < 적 진행 간격 → margin(결심 여유)."""
        kc = _kc("2026-07-09T00:00:00Z", "2026-07-09T00:05:00Z")  # 5분 = 300000ms
        r = DecisionAdvantageAssessor().assess(200.0, kc)
        assert r.adversary_cadence_ms == 300000.0
        assert r.verdict == "margin"
        assert r.soc_latency_partial is True

    def test_contested_when_latency_above_cadence(self) -> None:
        kc = _kc("2026-07-09T00:00:00.000Z", "2026-07-09T00:00:00.100Z")  # 100ms
        r = DecisionAdvantageAssessor().assess(5000.0, kc)
        assert r.verdict == "contested"

    def test_median_of_multiple_deltas(self) -> None:
        kc = _kc(
            "2026-07-09T00:00:00Z",
            "2026-07-09T00:00:01Z",  # +1000
            "2026-07-09T00:00:04Z",  # +3000
            "2026-07-09T00:00:06Z",  # +2000
        )
        r = DecisionAdvantageAssessor().assess(1.0, kc)
        assert r.adversary_cadence_ms == 2000.0  # median(1000,3000,2000)
        assert r.advance_count == 4


class TestDegenerate:
    def test_single_step_unknown(self) -> None:
        r = DecisionAdvantageAssessor().assess(1.0, _kc("2026-07-09T00:00:00Z"))
        assert r.verdict == "unknown" and r.adversary_cadence_ms is None

    def test_empty_unknown(self) -> None:
        r = DecisionAdvantageAssessor().assess(1.0, [])
        assert r.verdict == "unknown"

    def test_duplicate_ts_no_positive_delta(self) -> None:
        """한 alert 다기법=동일 ts → 0 델타 제외 → unknown(거짓 contested 아님)."""
        kc = _kc("2026-07-09T00:00:00Z", "2026-07-09T00:00:00Z")
        r = DecisionAdvantageAssessor().assess(1.0, kc)
        assert r.verdict == "unknown" and r.adversary_cadence_ms is None

    def test_out_of_order_negative_delta_excluded(self) -> None:
        """역순 ts(음델타) 제외 — 양델타만 유효."""
        kc = _kc("2026-07-09T00:00:05Z", "2026-07-09T00:00:00Z")  # 역순
        r = DecisionAdvantageAssessor().assess(1.0, kc)
        assert r.verdict == "unknown"

    def test_unparseable_ts_skipped(self) -> None:
        kc = _kc("not-a-date", "2026-07-09T00:00:00Z")
        r = DecisionAdvantageAssessor().assess(1.0, kc)
        # 유효 stamp 1개 → 델타 없음 → unknown(크래시 아님).
        assert r.verdict == "unknown"

    def test_no_bridge_over_invalid_middle_step(self) -> None:
        """valid,invalid,valid → 비인접 쌍으로 안 이음(양 쌍 무효)→unknown(Codex)."""
        kc = _kc(
            "2026-07-09T00:00:00Z",
            "not-a-date",  # 중간 unparseable
            "2026-07-09T00:05:00Z",
        )
        r = DecisionAdvantageAssessor().assess(1.0, kc)
        assert r.verdict == "unknown" and r.adversary_cadence_ms is None

    def test_naive_ts_rejected_no_crash(self) -> None:
        """offset 없는 naive ts 는 거부 — aware 와 혼합 subtract 크래시 차단(Codex)."""
        kc = _kc("2026-07-09T00:00:00", "2026-07-09T00:00:02Z")  # naive, aware
        r = DecisionAdvantageAssessor().assess(1.0, kc)
        # naive 거부 → 유효 stamp 1개 → 델타 없음 → unknown(크래시 아님).
        assert r.verdict == "unknown"

    def test_mixed_valid_and_zero_delta(self) -> None:
        """중복 + 양델타 혼재 → 양델타만 median."""
        kc = _kc(
            "2026-07-09T00:00:00Z",
            "2026-07-09T00:00:00Z",  # 0 델타(제외)
            "2026-07-09T00:00:02Z",  # +2000
        )
        r = DecisionAdvantageAssessor().assess(1.0, kc)
        assert r.adversary_cadence_ms == 2000.0 and r.verdict == "margin"


class TestOodaAlignment:
    def test_present_artifacts_mapped(self) -> None:
        present = {"signals": True, "diamond": True, "coa_options": False}
        a = ooda_alignment(present)
        assert "signals" in a["observe"]
        assert "diamond" in a["orient"]
        assert "coa_options" not in a["decide"]
        assert set(a) == set(OODA_SOURCES)

    def test_assessor_carries_ooda(self) -> None:
        r = DecisionAdvantageAssessor().assess(1.0, [], ooda={"observe": ["signals"]})
        assert r.ooda == {"observe": ["signals"]}


class TestHonesty:
    def test_basis_explains_comparison(self) -> None:
        """basis 는 무엇 vs 무엇 + unknown 사유를 정직히 노출(과장 금지)."""
        r = DecisionAdvantageAssessor().assess(1.0, [])
        assert any("적-OODA 직접비교 아님" in b for b in r.basis)
        assert any("cadence 측정 불가" in b for b in r.basis)
