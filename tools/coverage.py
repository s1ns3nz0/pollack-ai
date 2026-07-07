"""ATT&CK 커버리지 매트릭스 — KPI 산출·갭 분류·인접추론.

`data/attack_coverage.yaml`(전술별 covered/planned/uncovered + 갭 archetype)을 적재해:

- `report()`        : 전체/전술별 커버리지 수치 + archetype 별 갭 수.
- `gaps_by_archetype()`: ❌ 기법을 5 archetype 으로 묶음(대응전략 동반).
- `inference_anchors()` : 갭 기법에 대해 *같은/인접 전술의 탐지 가능 형제* 제시 —
  coverage-by-adjacency(킬체인 인접 추론)의 결정론 근거.

분석 서술: docs/attack-coverage-gaps.md. GraphRAG·KPI 모니터링이 이 모듈을 소비한다.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field
import yaml

from core.exceptions import CoverageDataError
from utils.logging import get_logger

_logger = get_logger("coverage")

DEFAULT_COVERAGE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "attack_coverage.yaml"
)


class Archetype(BaseModel):
    """갭 대응 유형(A~E)."""

    id: str
    name: str = ""
    strategy: str = ""


class GapTechnique(BaseModel):
    """미탐지(❌) 기법 + 소속 전술 + 대응 archetype."""

    id: str
    name: str = ""
    tactic: str = ""
    archetype: str = ""
    strategy: str = ""


class TacticCoverage(BaseModel):
    """한 전술의 탐지상태 집계."""

    name: str
    order: int = 0
    covered: list[str] = Field(default_factory=list)
    planned: list[str] = Field(default_factory=list)
    uncovered: list[GapTechnique] = Field(default_factory=list)

    @property
    def total(self) -> int:
        """이 전술의 기법 총수."""
        return len(self.covered) + len(self.planned) + len(self.uncovered)


class TacticStat(BaseModel):
    """전술별 리포트 행."""

    name: str
    covered: int
    planned: int
    uncovered: int


class CoverageReport(BaseModel):
    """커버리지 KPI 요약."""

    total: int
    covered: int
    planned: int
    uncovered: int
    coverage_pct: float
    addressable_pct: float  # pre-compromise(A) 갭 제외 시 커버리지
    by_archetype: dict[str, int] = Field(default_factory=dict)
    tactics: list[TacticStat] = Field(default_factory=list)


class InferenceAnchors(BaseModel):
    """갭 기법의 인접추론 근거(같은/인접 전술의 탐지 가능 형제)."""

    technique: str
    tactic: str
    same_tactic_covered: list[str] = Field(default_factory=list)
    adjacent_covered: list[str] = Field(default_factory=list)


# pre-compromise archetype — 커버리지 분모에서 제외(scope 밖).
_OUT_OF_SCOPE_ARCHETYPE = "A_pre_compromise"


class CoverageMatrix:
    """전술별 탐지상태 + archetype 을 보유하는 커버리지 매트릭스.

    Args:
        tactics: 전술별 커버리지(킬체인 order 순).
        archetypes: archetype id→정의.
    """

    def __init__(
        self, tactics: list[TacticCoverage], archetypes: dict[str, Archetype]
    ) -> None:
        self.tactics = sorted(tactics, key=lambda t: t.order)
        self.archetypes = archetypes

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> CoverageMatrix:
        """커버리지 YAML 을 적재한다.

        Raises:
            CoverageDataError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        p = Path(path) if path is not None else DEFAULT_COVERAGE_PATH
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise CoverageDataError(f"커버리지 매트릭스 적재 실패: {exc}") from exc
        if not isinstance(raw, dict):
            raise CoverageDataError(
                "커버리지 매트릭스 구조 검증 실패(최상위 dict 아님)."
            )
        archetypes = {
            aid: Archetype(id=aid, **(meta if isinstance(meta, dict) else {}))
            for aid, meta in (raw.get("archetypes") or {}).items()
        }
        tactics: list[TacticCoverage] = []
        for t in raw.get("tactics") or []:
            if not isinstance(t, dict):
                continue
            gaps = [
                GapTechnique(
                    id=str(g.get("id", "")),
                    name=str(g.get("name", "")),
                    tactic=str(t.get("name", "")),
                    archetype=str(g.get("archetype", "")),
                    strategy=archetypes.get(
                        str(g.get("archetype", "")), Archetype(id="")
                    ).strategy,
                )
                for g in (t.get("uncovered") or [])
                if isinstance(g, dict)
            ]
            tactics.append(
                TacticCoverage(
                    name=str(t.get("name", "")),
                    order=int(t.get("order", 0)),
                    covered=[str(x) for x in (t.get("covered") or [])],
                    planned=[str(x) for x in (t.get("planned") or [])],
                    uncovered=gaps,
                )
            )
        if not tactics:
            raise CoverageDataError("커버리지 매트릭스에 전술이 없음.")
        return cls(tactics, archetypes)

    def tactic_order(self, tactic: str) -> int | None:
        """tactic 이름의 kill-chain order 를 반환한다(미매핑이면 None).

        Args:
            tactic: ATT&CK tactic 이름(예: "Collection").

        Returns:
            kill-chain 진행 순서(1=초기 정찰 … 후반=영향). 매트릭스에 없으면 None.
        """
        for t in self.tactics:
            if t.name == tactic:
                return t.order
        return None

    def tactic_of(self, technique: str) -> str | None:
        """technique id 의 소속 tactic 이름을 반환한다(미매핑이면 None).

        covered/planned/uncovered 전체에서 찾는다 — kill chain 진행도·COA 에서
        예측 technique 을 단계(tactic)로 환산할 때 쓴다.

        Args:
            technique: MITRE technique id.

        Returns:
            소속 tactic 이름, 없으면 None.
        """
        for t in self.tactics:
            if technique in t.covered or technique in t.planned:
                return t.name
            if any(g.id == technique for g in t.uncovered):
                return t.name
        return None

    def max_tactic_order(self, tactics: list[str]) -> int:
        """tactic 목록 중 최고 order 를 반환한다(actor 누적 진행도용).

        미매핑 tactic(예: ATLAS MLAttackStaging)은 무시한다.

        Args:
            tactics: tactic 이름 목록.

        Returns:
            매핑된 tactic 의 최고 order. 하나도 매핑 안 되면 0.
        """
        orders = [o for t in tactics if (o := self.tactic_order(t)) is not None]
        return max(orders) if orders else 0

    def gaps(self) -> list[GapTechnique]:
        """모든 미탐지(❌) 기법을 평탄화해 반환한다."""
        return [g for t in self.tactics for g in t.uncovered]

    def gaps_by_archetype(self) -> dict[str, list[GapTechnique]]:
        """갭을 archetype 별로 묶는다."""
        grouped: dict[str, list[GapTechnique]] = {a: [] for a in self.archetypes}
        for gap in self.gaps():
            grouped.setdefault(gap.archetype, []).append(gap)
        return grouped

    def report(self) -> CoverageReport:
        """전체·전술별 커버리지 KPI 를 산출한다."""
        covered = sum(len(t.covered) for t in self.tactics)
        planned = sum(len(t.planned) for t in self.tactics)
        uncovered = sum(len(t.uncovered) for t in self.tactics)
        total = covered + planned + uncovered
        out_of_scope = len(self.gaps_by_archetype().get(_OUT_OF_SCOPE_ARCHETYPE, []))
        # addressable: scope 밖(pre-compromise) 갭을 분모에서 제외.
        addr_total = max(total - out_of_scope, 1)
        by_arch = {
            aid: len(gaps) for aid, gaps in self.gaps_by_archetype().items() if gaps
        }
        return CoverageReport(
            total=total,
            covered=covered,
            planned=planned,
            uncovered=uncovered,
            coverage_pct=round(covered / max(total, 1), 3),
            addressable_pct=round(covered / addr_total, 3),
            by_archetype=by_arch,
            tactics=[
                TacticStat(
                    name=t.name,
                    covered=len(t.covered),
                    planned=len(t.planned),
                    uncovered=len(t.uncovered),
                )
                for t in self.tactics
            ],
        )

    def inference_anchors(self, technique_id: str) -> InferenceAnchors:
        """갭 기법에 대한 인접추론 근거(같은/인접 전술의 탐지 가능 형제)를 반환한다.

        coverage-by-adjacency: 보이지 않는 기법이라도 같은 킬체인 단계(또는 직전/직후
        단계)의 탐지 가능 기법으로 활성 여부를 정황 추정한다.
        """
        idx = {t.name: i for i, t in enumerate(self.tactics)}
        host = next(
            (t for t in self.tactics if any(g.id == technique_id for g in t.uncovered)),
            None,
        )
        if host is None:
            return InferenceAnchors(technique=technique_id, tactic="")
        pos = idx[host.name]
        adjacent: list[str] = []
        for off in (-1, 1):
            j = pos + off
            if 0 <= j < len(self.tactics):
                adjacent.extend(self.tactics[j].covered)
        return InferenceAnchors(
            technique=technique_id,
            tactic=host.name,
            same_tactic_covered=list(host.covered),
            adjacent_covered=adjacent,
        )
