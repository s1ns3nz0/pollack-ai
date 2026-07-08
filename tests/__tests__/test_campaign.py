"""CampaignDetector 테스트 — actor 시나리오 이력 → 캠페인 체인 매칭."""

from core.campaign import CampaignChains, CampaignDetector
from core.models import CampaignMatch


class TestCampaignChains:
    def test_loads_from_yaml(self) -> None:
        chains = CampaignChains.from_yaml()
        assert chains.count == 7

    def test_chain_has_sequence(self) -> None:
        chains = CampaignChains.from_yaml()

        c1 = chains.chain("C1")

        assert c1 is not None
        assert c1.sequence == ["S6", "S13", "S15", "S11"]


class TestCampaignDetector:
    """관측 시나리오 이력 → 진행 중 캠페인 + 진행도 + 다음 예상."""

    def _detector(self) -> CampaignDetector:
        return CampaignDetector(CampaignChains.from_yaml())

    def test_full_prefix_match(self) -> None:
        """C2 시퀀스 앞부분(S14,S4) 관측 → C2 매칭 + 다음 예상 S1."""
        matches = self._detector().detect(["S14", "S4"])

        c2 = next(m for m in matches if m.chain_id == "C2")
        assert c2.matched == 2
        assert c2.total == 3
        assert c2.next_expected == "S1"

    def test_completed_campaign_no_next(self) -> None:
        """전 시퀀스 관측 → 진행도 100%, 다음 예상 없음."""
        matches = self._detector().detect(["S14", "S4", "S1"])

        c2 = next(m for m in matches if m.chain_id == "C2")
        assert c2.matched == 3
        assert c2.next_expected == ""

    def test_out_of_order_no_match(self) -> None:
        """순서 안 맞으면(prefix 아님) 매칭 안 됨."""
        # S4 먼저, S14 없음 → C2 prefix(S14,..) 불일치
        matches = self._detector().detect(["S4", "S1"])

        assert not any(m.chain_id == "C2" for m in matches)

    def test_interleaved_history_matches_subsequence(self) -> None:
        """중간에 무관 시나리오 껴도 순서 보존되면 매칭(캠페인은 시간 상관)."""
        # S6 → (무관 S99) → S13 → S15 : C1 prefix(S6,S13,S15) subsequence
        matches = self._detector().detect(["S6", "S99", "S13", "S15"])

        c1 = next(m for m in matches if m.chain_id == "C1")
        assert c1.matched == 3
        assert c1.next_expected == "S11"

    def test_no_history_empty(self) -> None:
        assert self._detector().detect([]) == []

    def test_next_expected_not_already_observed(self) -> None:
        """다음 예상이 이미 관측된 시나리오면 예측 안 함(out-of-order 거짓예측 방지).

        C2=[S14,S4,S1]. history [S14,S1,S4] → S14→S4 매칭되나 S1(종단)이 S4 전에
        이미 발생 → next_expected=S1 은 거짓. 이미 본 시나리오는 예측하지 않는다.
        """
        matches = self._detector().detect(["S14", "S1", "S4"])

        c2 = next((m for m in matches if m.chain_id == "C2"), None)
        if c2 is not None:
            assert c2.next_expected != "S1"

    def test_match_carries_severity(self) -> None:
        """매칭은 캠페인 severity 를 담는다."""
        matches = self._detector().detect(["S6", "S13"])

        c1 = next(m for m in matches if m.chain_id == "C1")
        assert c1.severity == "critical"
        assert isinstance(c1, CampaignMatch)

    def test_only_first_element_no_match(self) -> None:
        """첫 시나리오만으론 캠페인 확정 안 함(matched>=2 요구)."""
        matches = self._detector().detect(["S6"])

        # S6 은 C1/C4/C7 시작이지만 1개만으론 매칭 미확정
        assert matches == []
