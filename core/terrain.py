"""MBCRA — 임무 기반 사이버 위험평가 + 사이버 핵심지형(DoD METT-TC / JP 3-12 KT-C).

정적 asset tier 를 넘어 **임무관련지형(MRT-C)** 을 모델링한다. asset-tiers.yaml 의
`key_terrain`(자산이 핵심지형인 임무단계) + `depends_on`(손상 전파 그래프)을 읽어
(1) 읽기전용 `key_terrain` enrich(현 단계 핵심지형 접촉 → severity 격상 입력),
(2) METT-TC 융합 임무위험 점수(MissionRiskAssessor)를 산출한다.

전 과정 결정론·정책구동(Detection-as-Code). LLM 무관. PredictionMatcher/
KillChainProgressor/DecoyDetector 와 동형(읽기 전용 enrich, 격상권은 정책 엔진).

Spec: docs/superpowers/specs/2026-07-08-mbcra-key-terrain-design.md
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.exceptions import PolicyError
from core.models import Alert, MissionRisk

_POLICY = Path(__file__).resolve().parent / "policy" / "asset-tiers.yaml"

# tier→기본 가중(asset-tiers.yaml tiers 의 weight 를 참조하되, 파일 부재 대비 폴백).
_TIER_WEIGHT_FALLBACK = {
    "T0-AI": 4,
    "T1-Critical": 4,
    "T2-Important": 3,
    "T3-Support": 1,
}


class _AssetTerrain:
    """자산 1건의 지형 메타(정규화)."""

    __slots__ = ("asset_id", "tier", "key_terrain", "depends_on")

    def __init__(
        self, asset_id: str, tier: str, key_terrain: list[str], depends_on: list[str]
    ) -> None:
        self.asset_id = asset_id
        self.tier = tier
        self.key_terrain = key_terrain
        self.depends_on = depends_on


class KeyTerrainMap:
    """asset-tiers.yaml → 사이버 핵심지형/의존성 조회(결정론).

    Args:
        assets: asset_id → _AssetTerrain 매핑.
        tier_weights: tier → 가중치.
    """

    def __init__(
        self, assets: dict[str, _AssetTerrain], tier_weights: dict[str, int]
    ) -> None:
        self._assets = assets
        self._tier_weights = tier_weights

    def is_key_terrain(self, asset_id: str, mission_phase: str) -> bool:
        """자산이 해당 임무단계의 핵심지형인지 여부."""
        a = self._assets.get(asset_id)
        return bool(a and mission_phase and mission_phase in a.key_terrain)

    def dependents(self, asset_id: str) -> list[str]:
        """이 자산에 의존하는(손상 시 영향받는) 자산 목록(역방향, 정렬)."""
        return sorted(
            other.asset_id
            for other in self._assets.values()
            if asset_id in other.depends_on
        )

    def tier_weight(self, tier: str) -> int:
        """tier 가중치(미정의 → 0)."""
        return int(self._tier_weights.get(tier, 0))

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> KeyTerrainMap:
        """asset-tiers.yaml 을 적재한다.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치/자산 없음 시.
        """
        p = Path(path) if path is not None else _POLICY
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"자산 지형 적재 실패: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError("자산 지형 구조 오류(최상위 dict 아님).")
        tiers_raw = raw.get("tiers") or {}
        if not isinstance(tiers_raw, dict):
            raise PolicyError("자산 지형 구조 오류(tiers 가 dict 아님).")
        try:
            weights = {
                str(name): int(meta.get("weight", 0))
                for name, meta in tiers_raw.items()
                if isinstance(meta, dict)
            } or dict(_TIER_WEIGHT_FALLBACK)
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"자산 지형 tier weight 형식 오류: {exc}") from exc
        assets_raw = raw.get("assets") or []
        if not isinstance(assets_raw, list):
            raise PolicyError("자산 지형 구조 오류(assets 가 리스트 아님).")
        assets: dict[str, _AssetTerrain] = {}
        for item in assets_raw:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            aid = str(item["id"])
            kt = item.get("key_terrain") or []
            dep = item.get("depends_on") or []
            assets[aid] = _AssetTerrain(
                asset_id=aid,
                tier=str(item.get("tier", "")),
                key_terrain=[str(x) for x in kt] if isinstance(kt, list) else [],
                depends_on=[str(x) for x in dep] if isinstance(dep, list) else [],
            )
        if not assets:
            raise PolicyError("자산 지형이 비어있음.")
        return cls(assets, weights)


class KeyTerrainDetector:
    """alert 자산이 현 임무단계 핵심지형이면 `key_terrain` enrich(읽기 전용).

    Args:
        terrain: 핵심지형 맵.
    """

    def __init__(self, terrain: KeyTerrainMap) -> None:
        self._terrain = terrain

    async def enrich(self, alert: Alert) -> Alert:
        """자산이 현 단계 핵심지형이면 `key_terrain=True` 복사본, 아니면 원본.

        Args:
            alert: 파이프라인 진입 알람(asset_id·mission_phase 참조).

        Returns:
            정책 파생값으로 `key_terrain` 을 **항상 덮어쓴** 사본(무변화 시 원본).
            inbound alert 위조 플래그를 신뢰하지 않기 위함(Codex M-1).
        """
        derived = bool(
            alert.asset_id
            and self._terrain.is_key_terrain(alert.asset_id, alert.mission_phase)
        )
        if derived != alert.key_terrain:
            return alert.model_copy(update={"key_terrain": derived})
        return alert


class MissionRiskAssessor:
    """METT-TC 융합 임무위험 산정(결정론) — 정적 tier 를 넘는 임무맥락 위험.

    METT-TC: Mission(단계)·Enemy(적 진행도)·Terrain(핵심지형+의존자산)·
    Troops(방어자산=tier)·Time(체류)·Civil(지리/부수피해). alert 에 이미 실린
    신호를 융합한다 — 새 외부 조회 없음.

    Args:
        terrain: 핵심지형/의존성 맵.
    """

    def __init__(self, terrain: KeyTerrainMap) -> None:
        self._terrain = terrain

    def assess(self, alert: Alert) -> MissionRisk:
        """alert 의 METT-TC 요소를 융합해 MissionRisk 를 산출한다.

        Args:
            alert: 대상 알람(asset_id·mission_phase·dwelling·kill_chain 등).

        Returns:
            요소별 기여·근거를 담은 MissionRisk.
        """
        aid = alert.asset_id
        phase = alert.mission_phase
        is_kt = self._terrain.is_key_terrain(aid, phase)
        dependents = self._terrain.dependents(aid)

        factors: dict[str, int] = {}
        # Terrain — 핵심지형이면 +2, 의존자산 수만큼 전파위험 가산(상한 3).
        factors["terrain_key"] = 2 if is_kt else 0
        factors["terrain_dependents"] = min(len(dependents), 3)
        # Troops — 우리 방어자산 중요도(tier 가중).
        factors["troops_tier"] = self._terrain.tier_weight(alert.asset_tier)
        # Enemy — 적 kill-chain 후반 도달.
        factors["enemy_advanced"] = 2 if alert.kill_chain_advanced else 0
        # Time — 장기 체류(30분↑).
        factors["time_dwelling"] = 1 if alert.dwelling_min >= 30 else 0
        # Civil — 지리 컨텍스트 보유(부수피해 고려 대상).
        factors["civil_geo"] = 1 if alert.lat is not None else 0

        score = sum(factors.values())
        rationale = [f"{k}={v:+d}" for k, v in factors.items() if v]
        rationale.append(f"mission_phase={phase or '미상'}")
        if is_kt:
            rationale.append(f"KEY TERRAIN({phase}) — 임무 핵심자산")
        if dependents:
            rationale.append(f"의존자산 {len(dependents)}: {','.join(dependents)}")
        return MissionRisk(
            asset_id=aid,
            mission_phase=phase,
            score=score,
            is_key_terrain=is_kt,
            dependents=dependents,
            factors=factors,
            rationale=rationale,
        )
