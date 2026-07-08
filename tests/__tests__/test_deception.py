"""Deception 레이어 — decoy/canary enrich(읽기전용) + canary→CONFIRMED_TP(신뢰관측).

핵심 불변식 회귀 가드:
- asset/canary 접촉 → decoy_hit enrich, verdict 불변(untrusted → TP 승격 없음).
- 위조 canary 를 alert 본문에 심어도 actor 적립 0(포이즈닝 면역).
- 신뢰 관측 채널(Observation.canary_hit)만 CONFIRMED_TP 승격.
"""

import hashlib

import pytest

from core.deception import DecoyDetector
from core.exceptions import PolicyError
from core.models import Alert, EnvVerdict, Severity
from core.outcome import Observation, ProbeEngine

# canary-tokens.yaml 데모 토큰 원본(레지스트리엔 sha256 해시만 커밋됨).
_DEMO_TOKEN = "CANARY-DEMO-GCS-CRED-9f2c"


def _detector() -> DecoyDetector:
    return DecoyDetector(
        decoy_assets={"GCS_HONEY"},
        canary_hashes={hashlib.sha256(_DEMO_TOKEN.encode()).hexdigest()},
    )


def _alert(*, asset_id: str = "", iocs: list[str] | None = None) -> Alert:
    return Alert(
        id="a1",
        scenario_id="S2",
        title="t",
        asset_id=asset_id,
        severity_baseline=Severity.MEDIUM,
        signals=["sig"],
        iocs=iocs or [],
        mitre={"tactics": ["c2"], "techniques": ["T1071"]},
    )


class TestDecoyEnrich:
    """DecoyDetector — 읽기전용 미끼 접촉 탐지."""

    @pytest.mark.asyncio
    async def test_asset_hit_sets_flag(self) -> None:
        """decoy 자산 접촉 → decoy_hit=True."""
        out = await _detector().enrich(_alert(asset_id="GCS_HONEY"))
        assert out.decoy_hit is True

    @pytest.mark.asyncio
    async def test_canary_ioc_hit_sets_flag(self) -> None:
        """canary 토큰이 iocs 에 등장 → decoy_hit=True."""
        out = await _detector().enrich(_alert(iocs=[_DEMO_TOKEN]))
        assert out.decoy_hit is True

    @pytest.mark.asyncio
    async def test_miss_keeps_original(self) -> None:
        """미끼 미접촉 → 플래그 미설정, 원본 그대로."""
        alert = _alert(asset_id="GNSS", iocs=["1.2.3.4"])
        out = await _detector().enrich(alert)
        assert out.decoy_hit is False

    @pytest.mark.asyncio
    async def test_enrich_does_not_promote_tp(self) -> None:
        """enrich 는 verdict 를 안 건드린다(untrusted → TP 승격 없음)."""
        alert = _alert(asset_id="GCS_HONEY")
        out = await _detector().enrich(alert)
        assert out.decoy_hit is True
        assert out.ground_truth == alert.ground_truth  # verdict 불변


class TestDecoyPolicyLoad:
    """정책 로더 graceful-degrade."""

    def test_default_yaml_loads(self) -> None:
        """기본 정책 파일 적재 성공(자산+canary)."""
        det = DecoyDetector.from_yaml()
        assert isinstance(det, DecoyDetector)

    def test_both_empty_raises(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """두 정책 모두 비면 PolicyError(그래프가 detector=None 처리)."""
        empty = tmp_path / "empty.yaml"
        empty.write_text("decoy_assets: []\n", encoding="utf-8")
        empty2 = tmp_path / "empty2.yaml"
        empty2.write_text("canary_hashes: []\n", encoding="utf-8")
        with pytest.raises(PolicyError):
            DecoyDetector.from_yaml(decoy_path=empty, canary_path=empty2)

    def test_missing_files_raise(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """두 파일 모두 부재 → 빈 정책 → PolicyError."""
        with pytest.raises(PolicyError):
            DecoyDetector.from_yaml(
                decoy_path=tmp_path / "no.yaml",
                canary_path=tmp_path / "no2.yaml",
            )


class TestCanaryProbePromotion:
    """신뢰 관측 채널(Observation.canary_hit)만 CONFIRMED_TP 승격."""

    def _obs(self, **kw: object) -> Observation:
        base: dict[str, object] = {"alert_id": "a1", "scenario_id": "S2", "ts": "t"}
        base.update(kw)
        return Observation.model_validate(base)

    def test_canary_hit_is_confirmed_tp(self) -> None:
        """신뢰 센서 canary 접촉 관측 → CONFIRMED_TP."""
        decision = ProbeEngine().decide(self._obs(canary_hit=True))
        assert decision.env_verdict == EnvVerdict.CONFIRMED_TP

    def test_no_canary_stays_inconclusive(self) -> None:
        """canary 미관측 + 효과 미관측 → INCONCLUSIVE(승격 없음)."""
        decision = ProbeEngine().decide(self._obs(canary_hit=False))
        assert decision.env_verdict == EnvVerdict.INCONCLUSIVE

    def test_mission_effect_precedes_canary(self) -> None:
        """mission_effect(효과 등급) 가 canary 분기보다 우선(effect 세분 보존)."""
        decision = ProbeEngine().decide(
            self._obs(mission_effect_observed=True, reoccurred=True, canary_hit=True)
        )
        assert decision.env_verdict == EnvVerdict.CONFIRMED_TP
        assert decision.effect == 0.0  # reoccurred → PB 완전 실패 등급 유지
