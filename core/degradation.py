"""Graceful degradation — 자산 손상 시 임무 지속성 판정 + 대체경로(mission assurance).

DoD mission assurance 교리의 결정론 구현. 정탐 확정(TRUE_POSITIVE) 후 손상 자산
(alert.asset_id)을 `degradation-matrix.yaml` 에서 조회해 "저하된 능력으로라도 임무를
계속할 수 있는지" 를 판정한다 — 임무 지속성 등급(SUSTAINED/MINIMAL/ABORT) + 손실
능력 + 대체 경로(fallback)를 report 에 제시한다(실행권은 페일오버 절차).

'공격받아도 임무 완수' — GNSS 손상→INS 저하항법 지속, C2 손상→자율 페일세이프.
LLM 무관, 전 과정 결정론.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.exceptions import PolicyError
from core.models import Alert, MissionContinuity, Verdict

_POLICY = Path(__file__).resolve().parent / "policy" / "degradation-matrix.yaml"


class DegradationMatrix:
    """degradation-matrix.yaml 정책 로더 — 자산 → 임무 지속성 판정."""

    def __init__(self, assets: dict[str, MissionContinuity]) -> None:
        self._assets = assets

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> DegradationMatrix:
        """Degradation 매트릭스 YAML 을 적재한다.

        Args:
            path: 정책 경로. 생략 시 기본 degradation-matrix.yaml.

        Returns:
            로드된 DegradationMatrix.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        p = Path(path) if path is not None else _POLICY
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"Degradation 매트릭스 적재 실패: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError("Degradation 매트릭스 구조 오류(최상위 dict 아님).")
        assets: dict[str, MissionContinuity] = {}
        raw_assets = raw.get("assets", {})
        if isinstance(raw_assets, dict):
            for asset_id, cell in raw_assets.items():
                if not isinstance(cell, dict):
                    continue
                assets[str(asset_id)] = MissionContinuity(
                    asset_id=str(asset_id),
                    level=str(cell.get("level", "")),
                    capability_lost=str(cell.get("capability_lost", "")),
                    fallback=str(cell.get("fallback", "")),
                    sustains=bool(cell.get("sustains", False)),
                )
        return cls(assets)

    def assess_asset(self, asset_id: str) -> MissionContinuity | None:
        """자산 id 의 임무 지속성 판정을 반환한다(미정의면 None)."""
        return self._assets.get(asset_id)


class DegradationAssessor:
    """정탐 alert 의 손상 자산 → 임무 지속성 판정(graceful degradation).

    Args:
        matrix: 자산 → 지속성 판정 매트릭스.
    """

    def __init__(self, matrix: DegradationMatrix) -> None:
        self._matrix = matrix

    def assess(self, alert: Alert, verdict: Verdict) -> MissionContinuity | None:
        """정탐 확정 시 손상 자산의 임무 지속성을 판정한다.

        Args:
            alert: 대상 알람(asset_id 포함).
            verdict: 최종 판정(정탐일 때만 판정).

        Returns:
            MissionContinuity, 오탐/자산 미상/미매핑 시 None.
        """
        if verdict != Verdict.TRUE_POSITIVE or not alert.asset_id:
            return None
        return self._matrix.assess_asset(alert.asset_id)
