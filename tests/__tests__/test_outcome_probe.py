"""OutcomeProbe — 대응 후 텔레메트리 → 환경검증 라벨(결정론) 검증."""

from core.models import EnvVerdict
from sim_bridge.models import TelemetryRecord
from sim_bridge.outcome import OutcomeProbe

_GLITCH = 0x8000


def _ekf(*, flags: int = 0, phv: float = 0.2, vv: float = 0.02) -> TelemetryRecord:
    """위협 신호를 단순화한 EKF_STATUS_REPORT 레코드."""
    return TelemetryRecord.model_validate(
        {
            "MsgType": "EKF_STATUS_REPORT",
            "EkfFlags": flags,
            "PosHorizVariance": phv,
            "VelocityVariance": vv,
        }
    )


def _clean(n: int) -> list[TelemetryRecord]:
    """정상(위협 신호 없음) 레코드 n건."""
    return [_ekf() for _ in range(n)]


def _threat(n: int) -> list[TelemetryRecord]:
    """위협 지속(글리치 플래그) 레코드 n건."""
    return [_ekf(flags=_GLITCH) for _ in range(n)]


class TestConfirmedTp:
    """물리 효과 관측 → 정탐 확정(탐지 학습, 안전 방향)."""

    def test_sustained_effect_is_tp(self) -> None:
        """위협 신호가 effect_min 이상 연속 지속되면 CONFIRMED_TP."""
        probe = OutcomeProbe(effect_min=5, min_observations=30)
        result = probe.assess(_clean(40) + _threat(6) + _clean(10))
        assert result.env_verdict == EnvVerdict.CONFIRMED_TP
        assert result.sustained_effect_records >= 5

    def test_tp_allowed_in_short_window(self) -> None:
        """TP 는 짧은 윈도우에서도 인정(탐지 학습은 길이 무관)."""
        probe = OutcomeProbe(effect_min=5, min_observations=30)
        result = probe.assess(_threat(5))  # 윈도우 5 < min_observations 30
        assert result.env_verdict == EnvVerdict.CONFIRMED_TP

    def test_recovery_after_effect_still_tp(self) -> None:
        """효과가 관측된 뒤 회복돼도 정탐(대응 성공한 진짜 위협 → 억제 학습 금지)."""
        probe = OutcomeProbe(effect_min=5, min_observations=30)
        result = probe.assess(_threat(7) + _clean(40))
        assert result.env_verdict == EnvVerdict.CONFIRMED_TP


class TestConfirmedFp:
    """충분한 윈도우 내 무효과 → 오탐 확정(억제 학습, 위험 방향 — 보수적)."""

    def test_long_clean_window_is_fp(self) -> None:
        """위협 신호 전무 + 윈도우 ≥ min_observations → CONFIRMED_FP."""
        probe = OutcomeProbe(effect_min=5, min_observations=30)
        result = probe.assess(_clean(30))
        assert result.env_verdict == EnvVerdict.CONFIRMED_FP
        assert result.sustained_effect_records == 0


class TestInconclusive:
    """애매한 경우 → 적립 보류(적이 노리는 회색지대 배제)."""

    def test_short_clean_window_is_inconclusive(self) -> None:
        """무효과지만 윈도우가 부족하면 FP 로 단정하지 않고 보류."""
        probe = OutcomeProbe(effect_min=5, min_observations=30)
        result = probe.assess(_clean(10))
        assert result.env_verdict == EnvVerdict.INCONCLUSIVE

    def test_brief_transient_is_inconclusive(self) -> None:
        """긴 윈도우라도 단발 트랜지언트(effect_min 미만)는 보류."""
        probe = OutcomeProbe(effect_min=5, min_observations=30)
        result = probe.assess(_clean(35) + _threat(3) + _clean(5))
        assert result.env_verdict == EnvVerdict.INCONCLUSIVE

    def test_empty_window_is_inconclusive(self) -> None:
        """관측이 없으면 판정 불가 → 보류."""
        probe = OutcomeProbe()
        result = probe.assess([])
        assert result.env_verdict == EnvVerdict.INCONCLUSIVE


class TestThreatSignals:
    """개별 위협 신호 종류별 탐지(글리치/잔차/위성)."""

    def test_high_residual_counts_as_threat(self) -> None:
        """PosHorizVariance 임계 초과가 effect_min 연속이면 TP."""
        probe = OutcomeProbe(effect_min=3, min_observations=30, pos_var_threshold=0.8)
        result = probe.assess([_ekf(phv=4.8) for _ in range(3)])
        assert result.env_verdict == EnvVerdict.CONFIRMED_TP

    def test_low_satellites_counts_as_threat(self) -> None:
        """위성수 급감이 지속되면 위협 지속으로 본다."""
        probe = OutcomeProbe(effect_min=3, min_observations=30, min_satellites=7)
        rec = TelemetryRecord.model_validate(
            {"MsgType": "GPS_RAW_INT", "SatellitesVisible": 4}
        )
        result = probe.assess([rec, rec, rec])
        assert result.env_verdict == EnvVerdict.CONFIRMED_TP
