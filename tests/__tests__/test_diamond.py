"""Diamond Model — 4 정점 사상 + 정점 공유 피벗(결정론)."""

from core.diamond import DiamondAnalyzer
from core.models import (
    ActorIocPattern,
    ActorProfile,
    ActorTtpStat,
    Alert,
    Severity,
)


def _alert(
    *,
    actor_id: str = "APT-X",
    techs: list[str] | None = None,
    iocs: list[str] | None = None,
    asset: str = "GNSS",
) -> Alert:
    return Alert(
        id="a1",
        scenario_id="S1",
        title="t",
        asset_id=asset,
        asset_tier="T1-Critical",
        mission_phase="ingress",
        severity_baseline=Severity.MEDIUM,
        signals=["sig"],
        iocs=iocs or [],
        mitre={"tactics": ["c2"], "techniques": techs or ["T1071"]},
        actor_id=actor_id,
    )


class TestDiamondBuild:
    """alert(+프로필) → 4 정점 사상."""

    def test_build_from_alert(self) -> None:
        ev = DiamondAnalyzer().build(_alert(techs=["T1071"], iocs=["1.2.3.4"]))
        assert ev.adversary == "APT-X"
        assert ev.capabilities == ["T1071"]
        assert ev.infrastructure == ["1.2.3.4"]
        assert ev.victim == "GNSS"

    def test_profile_enriches_vertices(self) -> None:
        """프로필 누적 TTP/IOC 가 정점에 합류."""
        prof = ActorProfile(
            actor_id="APT-X",
            ttp_stats=[
                ActorTtpStat(tactic="c2", technique="T1090", count=1, last_seen="t")
            ],
            ioc_patterns=[
                ActorIocPattern(
                    kind="ip_24", value="10.0.0.0/24", count=1, last_seen="t"
                )
            ],
        )
        ev = DiamondAnalyzer().build(_alert(techs=["T1071"]), profile=prof)
        assert "T1071" in ev.capabilities and "T1090" in ev.capabilities
        assert "10.0.0.0/24" in ev.infrastructure


class TestDiamondPivot:
    """정점 공유 상관."""

    def test_shared_infrastructure_pivots(self) -> None:
        """서로 다른 공격자 2가 같은 인프라 공유 → infrastructure 피벗."""
        a = DiamondAnalyzer()
        e1 = a.build(_alert(actor_id="APT-X", iocs=["9.9.9.9"]))
        e2 = a.build(_alert(actor_id="APT-Y", iocs=["9.9.9.9"]))
        pivots = a.pivot([e1, e2])
        infra = [p for p in pivots if p.vertex == "infrastructure"]
        assert infra and infra[0].value == "9.9.9.9"
        assert infra[0].adversaries == ["APT-X", "APT-Y"]

    def test_same_adversary_not_correlated(self) -> None:
        """동일 공격자 반복은 상관 아님(공유 공격자 1)."""
        a = DiamondAnalyzer()
        e1 = a.build(_alert(actor_id="APT-X", iocs=["9.9.9.9"]))
        e2 = a.build(_alert(actor_id="APT-X", iocs=["9.9.9.9"]))
        assert a.pivot([e1, e2]) == []

    def test_shared_capability_pivots(self) -> None:
        """공유 technique → capability 피벗."""
        a = DiamondAnalyzer()
        e1 = a.build(_alert(actor_id="X", techs=["T1071"]))
        e2 = a.build(_alert(actor_id="Y", techs=["T1071"]))
        caps = [p for p in a.pivot([e1, e2]) if p.vertex == "capability"]
        assert caps and caps[0].value == "T1071" and caps[0].count == 2

    def test_no_correlation_empty(self) -> None:
        """공유 정점 없음 → 빈 리스트."""
        a = DiamondAnalyzer()
        e1 = a.build(
            _alert(actor_id="X", techs=["T1071"], iocs=["1.1.1.1"], asset="GNSS")
        )
        e2 = a.build(
            _alert(actor_id="Y", techs=["T1055"], iocs=["2.2.2.2"], asset="SATCOM")
        )
        assert a.pivot([e1, e2]) == []
