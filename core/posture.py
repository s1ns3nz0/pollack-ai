"""CPCON 사이버방어태세 사다리 — 전역 태세 → 전 alert 방어강도 하한(DoD/국정원).

DoD CPCON(Cyberspace Protection Conditions 5→1) = 국정원 사이버위기경보(정상/관심/
주의/경계/심각). 외부 태세 피드나 운영자가 설정한 **전역 태세**를 파이프라인 진입 시
각 alert 의 `posture` 하한으로 스탬프한다 — 태세를 올리면 개별 시나리오 판정과 무관하게
전 alert 방어강도가 최소 그 수준으로 상향된다(severity posture_modifier·no-downgrade
lock 이 기존대로 소비). 시나리오가 더 높은 posture 를 실으면 그대로 유지(floor 의미).

전 과정 결정론·정책구동. 이건 *태세 축(시간)*, MBCRA 는 *지형 축(공간)* — 상보.

Spec: docs/superpowers/specs/2026-07-08-cpcon-posture-design.md
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError
import yaml

from core.exceptions import PolicyError
from core.models import Alert

_POLICY = Path(__file__).resolve().parent / "policy" / "cpcon-posture.yaml"

# posture 서열 — severity._POSTURE_RANK 와 정합(하한 비교용).
_POSTURE_RANK = {"normal": 0, "elevated": 1, "high": 2}


class CpconLevel(BaseModel):
    """CPCON 한 단계 정의."""

    level: int = Field(ge=1, le=5)
    name: str = ""  # 국정원 표기(정상/관심/주의/경계/심각)
    # posture 는 severity 어휘로 제약 — 오타(예 "critical")가 unknown→rank0 로 조용히
    # de-escalation 되는 것을 차단(Codex High-2).
    posture: Literal["normal", "elevated", "high"] = "normal"
    description: str = ""


class PostureLadder:
    """cpcon-posture.yaml 로더 — CPCON level(1~5) → posture 매핑."""

    def __init__(self, levels: dict[int, CpconLevel]) -> None:
        self._levels = levels

    def level(self, cpcon: int) -> CpconLevel | None:
        """CPCON 정수 level → 정의(없으면 None)."""
        return self._levels.get(cpcon)

    def posture_for(self, cpcon: int) -> str:
        """CPCON level → 기존 posture 어휘(미정의 → normal)."""
        lv = self._levels.get(cpcon)
        return lv.posture if lv is not None else "normal"

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> PostureLadder:
        """cpcon-posture.yaml 을 적재한다.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치/빈 사다리 시.
        """
        p = Path(path) if path is not None else _POLICY
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"CPCON 사다리 적재 실패: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError("CPCON 사다리 구조 오류(최상위 dict 아님).")
        items = raw.get("cpcon", []) or []
        if not isinstance(items, list):
            raise PolicyError("CPCON 사다리 구조 오류(cpcon 이 리스트 아님).")
        levels: dict[int, CpconLevel] = {}
        # model_validate 를 PolicyError 경로 안에서 — 의미적 오류(level: bad/6, posture
        # 오타)가 raw ValidationError 로 graph 를 크래시시키지 않게(Codex High-1).
        try:
            for item in items:
                if isinstance(item, dict) and "level" in item:
                    lv = CpconLevel.model_validate(item)
                    levels[lv.level] = lv
        except ValidationError as exc:
            raise PolicyError(f"CPCON 사다리 항목 검증 실패: {exc}") from exc
        if not levels:
            raise PolicyError("CPCON 사다리가 비어있음.")
        return cls(levels)


class PostureProvider:
    """전역 CPCON → alert.posture 하한 스탬프(읽기전용 enrich).

    Args:
        ladder: CPCON 사다리.
        cpcon_level: 현재 전역 태세(1~5, settings.cyber_posture_level).
    """

    def __init__(self, ladder: PostureLadder, cpcon_level: int) -> None:
        self._ladder = ladder
        self._cpcon = cpcon_level
        self._floor_posture = ladder.posture_for(cpcon_level)

    @property
    def cpcon_level(self) -> int:
        """현재 전역 CPCON level."""
        return self._cpcon

    @property
    def condition(self) -> CpconLevel | None:
        """현재 CPCON 단계 정의."""
        return self._ladder.level(self._cpcon)

    async def enrich(self, alert: Alert) -> Alert:
        """전역 태세가 alert.posture 보다 높으면 하한으로 끌어올린다.

        Args:
            alert: 파이프라인 진입 알람.

        Returns:
            전역 태세가 더 높으면 `posture` 상향 사본, 아니면 원본(시나리오 우선).
        """
        cur = _POSTURE_RANK.get(alert.posture, 0)
        floor = _POSTURE_RANK.get(self._floor_posture, 0)
        if floor > cur:
            return alert.model_copy(update={"posture": self._floor_posture})
        return alert
