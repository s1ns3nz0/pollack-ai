"""Deception 레이어 — decoy 자산/canary 토큰 접촉 → `decoy_hit` enrich(읽기 전용).

미끼(decoy asset / canary token)를 심고 상대가 건드리면, 그 접촉 자체가 거짓양성
거의 0 인 고신뢰 공격자 신호다(정상 임무는 미끼에 접근할 이유가 없다). 다만 inbound
alert 는 위조 가능(untrusted)하므로 **여기서는 읽기전용 `decoy_hit` 플래그까지만**
세운다 — CONFIRMED_TP 승격은 하지 않는다. 위조 canary 를 alert 본문에 심어 강제
TP 를 만드는 포이즈닝 벡터를 막기 위해, TP 적립은 신뢰 관측 채널(`core/outcome.py`
의 `Observation.canary_hit` → `ProbeEngine`)이 전담한다.

PredictionMatcher / KillChainProgressor 와 동형 — 읽기 전용 enrich(프로필 변이 없음),
격상 판정권은 정책 severity 엔진.

Spec: docs/superpowers/specs/2026-07-08-deception-decoy-layer-design.md
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from core.exceptions import PolicyError
from core.models import Alert

_DECOY_POLICY = Path(__file__).resolve().parent / "policy" / "decoy-assets.yaml"
_CANARY_POLICY = Path(__file__).resolve().parent / "policy" / "canary-tokens.yaml"

# 커밋되는 canary 레지스트리는 sha256(token) 해시만 담는다(원본 토큰 노출 0).
# 토큰은 고엔트로피 랜덤 비밀이라 rainbow 위험이 없어 salt 없이도 안전하다.
_HASH_PREFIX = "sha256:"


def _canary_hash(value: str) -> str:
    """IOC 문자열의 canary 매칭용 정규화 sha256 hex."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class DecoyDetector:
    """decoy 자산/canary 접촉 → `alert.decoy_hit` enrich(읽기 전용).

    Args:
        decoy_assets: decoy 로 지정된 자산 id 집합(위조 가능 라벨 — enrich 전용).
        canary_hashes: canary 토큰 sha256 hex 집합(비밀 유지 — 원본 미보관).
    """

    def __init__(self, decoy_assets: set[str], canary_hashes: set[str]) -> None:
        self._decoy_assets = decoy_assets
        self._canary_hashes = canary_hashes

    def _is_hit(self, alert: Alert) -> bool:
        """asset 라벨 매칭 또는 canary 해시 매칭 여부(결정론)."""
        if alert.asset_id and alert.asset_id in self._decoy_assets:
            return True
        return any(_canary_hash(ioc) in self._canary_hashes for ioc in alert.iocs)

    async def enrich(self, alert: Alert) -> Alert:
        """decoy 자산/canary 접촉 시 `decoy_hit=True` 복사본, 아니면 원본.

        Args:
            alert: 파이프라인 진입 알람(untrusted — asset_id/iocs 위조 가능).

        Returns:
            미끼 접촉 시 `decoy_hit=True` 사본. TP 승격은 하지 않는다(enrich 전용).
        """
        if self._is_hit(alert):
            return alert.model_copy(update={"decoy_hit": True})
        return alert

    @classmethod
    def from_yaml(
        cls,
        decoy_path: str | Path | None = None,
        canary_path: str | Path | None = None,
    ) -> DecoyDetector:
        """decoy-assets.yaml + canary-tokens.yaml 을 적재한다.

        각 파일은 독립적으로 부재를 허용(빈 집합)하되, 존재하면 파싱·구조를 검증한다.
        둘 다 비면 미끼 미배포로 보고 PolicyError(그래프가 detector=None 처리).

        Args:
            decoy_path: decoy 자산 정책 경로. 생략 시 기본 decoy-assets.yaml.
            canary_path: canary 토큰 해시 정책 경로. 생략 시 기본 canary-tokens.yaml.

        Returns:
            로드된 DecoyDetector.

        Raises:
            PolicyError: 존재 파일 파싱/구조 실패, 또는 두 정책 모두 비어있을 때.
        """
        decoy_assets = _load_str_list(
            Path(decoy_path) if decoy_path is not None else _DECOY_POLICY,
            key="decoy_assets",
        )
        raw_hashes = _load_str_list(
            Path(canary_path) if canary_path is not None else _CANARY_POLICY,
            key="canary_hashes",
        )
        canary_hashes = {
            h[len(_HASH_PREFIX) :].lower() if h.startswith(_HASH_PREFIX) else h.lower()
            for h in raw_hashes
        }
        if not decoy_assets and not canary_hashes:
            raise PolicyError("decoy 정책이 비어있음(자산·canary 모두 없음).")
        return cls(set(decoy_assets), canary_hashes)


def _load_str_list(path: Path, key: str) -> list[str]:
    """정책 YAML 에서 문자열 리스트를 안전 적재한다(파일 부재 시 빈 리스트).

    Raises:
        PolicyError: 파일이 존재하나 파싱/구조가 어긋날 때.
    """
    if not path.is_file():
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"decoy 정책 적재 실패({path.name}): {exc}") from exc
    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise PolicyError(f"decoy 정책 구조 오류({path.name}, 최상위 dict 아님).")
    items = raw.get(key, []) or []
    if not isinstance(items, list):
        raise PolicyError(f"decoy 정책 구조 오류({path.name}, {key} 리스트 아님).")
    return [str(x) for x in items]
