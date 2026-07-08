"""MBCRA — 사이버 핵심지형 enrich + METT-TC 임무위험 융합(결정론)."""

import pytest

from core.exceptions import PolicyError
from core.models import Alert, Severity
from core.terrain import KeyTerrainDetector, KeyTerrainMap, MissionRiskAssessor


def _alert(
    *,
    asset_id: str = "GNSS",
    phase: str = "ingress",
    tier: str = "T1-Critical",
    advanced: bool = False,
    dwelling: int = 0,
    lat: float | None = None,
) -> Alert:
    return Alert(
        id="a1",
        scenario_id="S1",
        title="t",
        asset_id=asset_id,
        asset_tier=tier,
        mission_phase=phase,
        severity_baseline=Severity.MEDIUM,
        signals=["sig"],
        kill_chain_advanced=advanced,
        dwelling_min=dwelling,
        lat=lat,
    )


class TestKeyTerrainMap:
    """핵심지형/의존성 조회."""

    def test_is_key_terrain_by_phase(self) -> None:
        """GNSS 는 ingress/on-station 에서 핵심지형, pre-flight 에선 아님."""
        m = KeyTerrainMap.from_yaml()
        assert m.is_key_terrain("GNSS", "ingress") is True
        assert m.is_key_terrain("GNSS", "pre-flight") is False

    def test_dependents_reverse_graph(self) -> None:
        """C2_LINK 에 의존하는 자산들(역방향)."""
        m = KeyTerrainMap.from_yaml()
        deps = m.dependents("C2_LINK")
        assert "AUTOPILOT" in deps and "GCS" in deps and "UGV_TELEOP" in deps

    def test_empty_policy_raises(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """자산 없는 정책 → PolicyError(graph 가 None 처리)."""
        p = tmp_path / "e.yaml"
        p.write_text("tiers: {}\nassets: []\n", encoding="utf-8")
        with pytest.raises(PolicyError):
            KeyTerrainMap.from_yaml(p)

    def test_malformed_tiers_raises_policy_error(self, tmp_path) -> None:  # type: ignore[no-untyped-def] # noqa: E501
        """tiers 가 list → PolicyError(AttributeError 아님, 크래시 방지 Codex H)."""
        p = tmp_path / "m.yaml"
        p.write_text("tiers: []\nassets: []\n", encoding="utf-8")
        with pytest.raises(PolicyError):
            KeyTerrainMap.from_yaml(p)

    def test_non_int_weight_raises_policy_error(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """비정수 weight → PolicyError(ValueError 승격, Codex H)."""
        p = tmp_path / "w.yaml"
        p.write_text(
            "tiers:\n  T1:\n    weight: abc\nassets:\n  - id: X\n    tier: T1\n",
            encoding="utf-8",
        )
        with pytest.raises(PolicyError):
            KeyTerrainMap.from_yaml(p)


class TestKeyTerrainDetector:
    """읽기전용 enrich."""

    @pytest.mark.asyncio
    async def test_key_terrain_hit(self) -> None:
        """현 단계 핵심지형 자산 → key_terrain=True."""
        det = KeyTerrainDetector(KeyTerrainMap.from_yaml())
        out = await det.enrich(_alert(asset_id="GNSS", phase="ingress"))
        assert out.key_terrain is True

    @pytest.mark.asyncio
    async def test_non_key_terrain_phase(self) -> None:
        """핵심지형 아닌 단계 → key_terrain=False."""
        det = KeyTerrainDetector(KeyTerrainMap.from_yaml())
        out = await det.enrich(_alert(asset_id="GNSS", phase="pre-flight"))
        assert out.key_terrain is False

    @pytest.mark.asyncio
    async def test_support_asset_never_key(self) -> None:
        """지원자산(TELEMETRY)은 어느 단계도 핵심지형 아님."""
        det = KeyTerrainDetector(KeyTerrainMap.from_yaml())
        out = await det.enrich(_alert(asset_id="TELEMETRY", phase="on-station"))
        assert out.key_terrain is False

    @pytest.mark.asyncio
    async def test_forged_flag_cleared_on_non_hit(self) -> None:
        """inbound 위조 key_terrain=True 라도 비핵심이면 False 로 덮어씀(Codex M-1)."""
        det = KeyTerrainDetector(KeyTerrainMap.from_yaml())
        forged = _alert(asset_id="TELEMETRY", phase="on-station")
        forged.key_terrain = True  # 위조
        out = await det.enrich(forged)
        assert out.key_terrain is False


class TestMissionRiskAssessor:
    """METT-TC 융합."""

    def test_key_terrain_scores_higher(self) -> None:
        """핵심지형 단계가 비핵심 단계보다 높은 위험."""
        a = MissionRiskAssessor(KeyTerrainMap.from_yaml())
        kt = a.assess(_alert(asset_id="GNSS", phase="ingress"))
        non_kt = a.assess(_alert(asset_id="GNSS", phase="pre-flight"))
        assert kt.is_key_terrain and kt.score > non_kt.score

    def test_factors_fuse_mett_tc(self) -> None:
        """적진행도+체류+지리 가산이 factors 에 반영."""
        a = MissionRiskAssessor(KeyTerrainMap.from_yaml())
        r = a.assess(
            _alert(
                asset_id="C2_LINK",
                phase="ingress",
                advanced=True,
                dwelling=45,
                lat=36.7,
            )
        )
        assert r.factors["enemy_advanced"] == 2
        assert r.factors["time_dwelling"] == 1
        assert r.factors["civil_geo"] == 1
        assert r.factors["terrain_dependents"] >= 1  # C2_LINK 의존자산 존재
        assert r.dependents  # 비어있지 않음

    def test_rationale_populated(self) -> None:
        """근거 문자열에 KEY TERRAIN 표기."""
        a = MissionRiskAssessor(KeyTerrainMap.from_yaml())
        r = a.assess(_alert(asset_id="GCS", phase="on-station"))
        assert any("KEY TERRAIN" in s for s in r.rationale)
