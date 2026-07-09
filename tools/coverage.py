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
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from core.exceptions import CoverageDataError
from core.policy_loader import load_policy_mapping, require_list, require_mapping
from utils.logging import get_logger

_logger = get_logger("coverage")

DEFAULT_COVERAGE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "attack_coverage.yaml"
)
DEFAULT_GROUND_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "ground_segment_coverage.yaml"
)


class Archetype(BaseModel):
    """갭 대응 유형(A~E)."""

    id: str
    name: str = ""
    strategy: str = ""


class TechniqueDataQuality(BaseModel):
    """기법별 탐지 품질 점수(DeTT&CT 방법론 — 선택, 점진적 채움).

    covered/planned/uncovered(이분법) 과 의미가 다르다 — "covered" 판정 자체엔
    영향 없이, 그 covered 가 실제로 얼마나 신뢰 가능한지를 별도로 표현한다.
    """

    technique: str
    visibility: int = Field(default=0, ge=0, le=3)  # 로그원 정보가치(0=없음~3=탁월)
    detection_maturity: int = Field(default=0, ge=0, le=4)  # 탐지 로직 성숙도
    quality_status: Literal[
        "native", "proxy", "reconstructed", "design_blind", "proposed_schema"
    ] = "native"
    log_source: str = ""
    notes: str = ""


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
    native_covered: int = 0
    proxy_covered: int = 0
    unscored_covered: int = 0
    quality_adjusted_pct: float = 0.0
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
        self,
        tactics: list[TacticCoverage],
        archetypes: dict[str, Archetype],
        data_quality: dict[str, TechniqueDataQuality] | None = None,
    ) -> None:
        self.tactics = sorted(tactics, key=lambda t: t.order)
        self.archetypes = archetypes
        self.data_quality = data_quality or {}

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> CoverageMatrix:
        """커버리지 YAML 을 적재한다.

        Raises:
            CoverageDataError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        raw = load_policy_mapping(
            path,
            DEFAULT_COVERAGE_PATH,
            label="커버리지 매트릭스",
            error_cls=CoverageDataError,
        )
        archetypes = {
            aid: Archetype(id=str(aid), **(meta if isinstance(meta, dict) else {}))
            for aid, meta in require_mapping(
                raw.get("archetypes"),
                label="커버리지 archetypes",
                error_cls=CoverageDataError,
            ).items()
        }
        tactics: list[TacticCoverage] = []
        for t in require_list(
            raw.get("tactics"), label="커버리지 tactics", error_cls=CoverageDataError
        ):
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
        raw_dq = raw.get("data_quality")
        try:
            data_quality = (
                {
                    str(tid): TechniqueDataQuality(
                        technique=str(tid), **(meta if isinstance(meta, dict) else {})
                    )
                    for tid, meta in raw_dq.items()
                }
                if isinstance(raw_dq, dict)
                else {}
            )
        except ValidationError as e:
            raise CoverageDataError(f"data_quality 스키마 오류: {e}") from e
        return cls(tactics, archetypes, data_quality)

    def data_quality_for(self, technique: str) -> TechniqueDataQuality | None:
        """기법의 DeTT&CT 품질 점수를 반환한다(미채점이면 None — covered 판정과 무관).

        Args:
            technique: MITRE technique id.

        Returns:
            채점돼 있으면 TechniqueDataQuality, 아니면 None.
        """
        return self.data_quality.get(technique)

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
        native_covered = 0
        proxy_covered = 0
        unscored_covered = 0
        for technique in [tech for tactic in self.tactics for tech in tactic.covered]:
            quality = self.data_quality_for(technique)
            if quality is None:
                unscored_covered += 1
            elif quality.quality_status == "native":
                native_covered += 1
            else:
                proxy_covered += 1
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
            native_covered=native_covered,
            proxy_covered=proxy_covered,
            unscored_covered=unscored_covered,
            quality_adjusted_pct=round(native_covered / max(total, 1), 3),
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


# ── 지상 세그먼트 커버리지 ──────────────────────────────────────────────
# UAV Sentinel 텔레메트리 평면(UAV*_CL) 밖 공격면(S86~S99). 항공 매트릭스와
# 물리 분리(별 파일·별 클래스) — 항공 KPI 분모에 절대 섞이지 않는다.


class GroundRemediation(BaseModel):
    """사각 해소에 필요한 계측(로그원). implemented 여야 covered_by 근거로 인정."""

    id: str
    name: str = ""
    source: str = ""
    implemented: bool = False


class GroundEvidence(BaseModel):
    """지상 surface 의 탐지 근거 항목(구조화). 백로그 라벨은 근거로 불인정."""

    remediation: str
    source_table: str = ""
    rule_id: str = ""


class GroundSurface(BaseModel):
    """지상 세그먼트 공격면 한 건(S86~S99).

    Attributes:
        scenario: 시나리오 id(예: S86).
        segment: 세그먼트 키(gcs_app 등).
        tactic: ATT&CK tactic 이름.
        technique: ATT&CK technique id.
        name: 기법 표시 이름.
        remediation: 필요 계측(remediation) id.
        covered_by: 탐지 근거. 비면 blind(구조적 사각).
    """

    scenario: str
    segment: str = ""
    tactic: str = ""
    technique: str = ""
    name: str = ""
    remediation: str = ""
    covered_by: list[GroundEvidence] = Field(default_factory=list)

    @property
    def blind(self) -> bool:
        """탐지 근거 없음(구조적 사각)."""
        return not self.covered_by


class RemediationBacklog(BaseModel):
    """계측 백로그 항목 — 로그원 추가 시 해소 가능한 blind surface 수."""

    remediation: str
    name: str = ""
    source: str = ""
    unblocks: int = 0


class NewTechniques(BaseModel):
    """지상 기법 중 항공 매트릭스에 없는 것(부모/서브 분리)."""

    exact_new: list[str] = Field(default_factory=list)
    subtechnique_of_covered: list[str] = Field(default_factory=list)


class GroundKillChain(BaseModel):
    """예시 blind 킬체인. detectable 은 항상 False(데이터로 덮어쓸 수 없음)."""

    id: str
    name: str = ""
    sequence: list[str] = Field(default_factory=list)
    detectable: bool = False


class GroundSegmentReport(BaseModel):
    """지상 세그먼트 blind KPI 요약."""

    total_surfaces: int
    blind: int
    covered: int
    coverage_pct: float
    blind_by_segment: dict[str, int] = Field(default_factory=dict)
    backlog: list[RemediationBacklog] = Field(default_factory=list)
    new_techniques: NewTechniques = Field(default_factory=NewTechniques)
    blind_kill_chains: list[GroundKillChain] = Field(default_factory=list)


class GroundSegmentCoverage:
    """지상 세그먼트 방어 커버리지(결정론·읽기전용).

    항공 CoverageMatrix 와 별개 스코프 — surface 는 항공 total/pct 에 안 섞인다.
    covered 전환은 covered_by + 참조 remediation implemented 일 때만(근거 게이트).

    Args:
        surfaces: 지상 공격면 목록.
        remediations: 계측(remediation) id→정의.
        blind_kill_chains: 예시 blind 킬체인(문서/백로그 전용).
    """

    def __init__(
        self,
        surfaces: list[GroundSurface],
        remediations: dict[str, GroundRemediation],
        blind_kill_chains: list[GroundKillChain] | None = None,
    ) -> None:
        self.surfaces = surfaces
        self.remediations = remediations
        self.blind_kill_chains = blind_kill_chains or []

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> GroundSegmentCoverage:
        """지상 커버리지 YAML 을 적재한다.

        Raises:
            CoverageDataError: 파일 부재/파싱 실패/구조 불일치, 또는 covered_by 가
                미구현(implemented=false) remediation 을 근거로 참조할 때(근거 게이트).
        """
        raw = load_policy_mapping(
            path,
            DEFAULT_GROUND_PATH,
            label="지상 커버리지",
            error_cls=CoverageDataError,
        )
        # 항공 파일 오적재 차단 — 지상 스키마는 tactics/archetypes 키를 갖지 않는다.
        if "tactics" in raw or "archetypes" in raw:
            raise CoverageDataError("지상 커버리지에 항공 전용 키 — 파일 오적재.")
        try:
            remediations = {
                rid: GroundRemediation(
                    id=str(rid), **(meta if isinstance(meta, dict) else {})
                )
                for rid, meta in require_mapping(
                    raw.get("remediations"),
                    label="지상 remediations",
                    error_cls=CoverageDataError,
                ).items()
            }
            surfaces: list[GroundSurface] = []
            for s in require_list(
                raw.get("surfaces"), label="지상 surfaces", error_cls=CoverageDataError
            ):
                if not isinstance(s, dict):
                    continue
                surf = GroundSurface(
                    scenario=str(s.get("scenario", "")),
                    segment=str(s.get("segment", "")),
                    tactic=str(s.get("tactic", "")),
                    technique=str(s.get("technique", "")),
                    name=str(s.get("name", "")),
                    remediation=str(s.get("remediation", "")),
                    covered_by=[
                        GroundEvidence(**e)
                        for e in (s.get("covered_by") or [])
                        if isinstance(e, dict)
                    ],
                )
                # 적재 시 fail-fast — 근거가 있는데 미구현 remediation 참조면 거부.
                # (covered_by 비면 정상 blind — 오류 아님.)
                if surf.covered_by and not cls._evidence_ok(surf, remediations):
                    raise CoverageDataError(
                        f"{surf.scenario} covered_by 가 미구현 remediation 참조"
                        "(governance theater 차단)."
                    )
                surfaces.append(surf)
            raw_chains = raw.get("blind_kill_chains")
            chains = [
                GroundKillChain(
                    id=str(c.get("id", "")),
                    name=str(c.get("name", "")),
                    sequence=[str(x) for x in (c.get("sequence") or [])],
                )
                for c in (raw_chains if isinstance(raw_chains, list) else [])
                if isinstance(c, dict)
            ]
        except ValidationError as e:
            raise CoverageDataError(f"지상 커버리지 스키마 오류: {e}") from e
        if not surfaces:
            raise CoverageDataError("지상 커버리지에 surface 가 없음.")
        return cls(surfaces, remediations, chains)

    @staticmethod
    def _evidence_ok(
        surf: GroundSurface, remediations: dict[str, GroundRemediation]
    ) -> bool:
        """covered 근거 유효성 — 근거 있고 전부 구현된 remediation 참조 시 True.

        비면 blind. placeholder(미구현/미지 remediation) 참조는 covered 로 안 침.
        """
        if not surf.covered_by:
            return False
        return all(
            (rem := remediations.get(ev.remediation)) is not None and rem.implemented
            for ev in surf.covered_by
        )

    def blind_spots(self) -> list[GroundSurface]:
        """탐지 근거 없는 surface(구조적 사각). 런타임 근거 게이트로 재검증."""
        return [s for s in self.surfaces if not self._evidence_ok(s, self.remediations)]

    def covered(self) -> list[GroundSurface]:
        """탐지 근거 있는 surface(런타임 근거 게이트 통과)."""
        return [s for s in self.surfaces if self._evidence_ok(s, self.remediations)]

    def instrumentation_backlog(self) -> list[RemediationBacklog]:
        """계측 백로그 — blind surface 를 해소하는 로그원 우선순위(해소 수 내림차순)."""
        counts: dict[str, int] = {}
        for s in self.blind_spots():
            counts[s.remediation] = counts.get(s.remediation, 0) + 1
        items = [
            RemediationBacklog(
                remediation=rid,
                name=self.remediations.get(rid, GroundRemediation(id=rid)).name,
                source=self.remediations.get(rid, GroundRemediation(id=rid)).source,
                unblocks=n,
            )
            for rid, n in counts.items()
        ]
        return sorted(items, key=lambda b: (-b.unblocks, b.remediation))

    def new_techniques(self, airborne: CoverageMatrix | None = None) -> NewTechniques:
        """지상 기법 중 항공 매트릭스에 없는 것을 부모/서브로 분리 산출한다.

        exact_new: 항공에 부모도 없는 완전 신규 기법. subtechnique_of_covered:
        부모(Txxxx)는 항공에 있으나 서브(.00n)는 없는 기법.

        Args:
            airborne: 대조할 항공 매트릭스. 생략 시 기본 매트릭스 적재.

        Returns:
            exact_new / subtechnique_of_covered 두 버킷.
        """
        matrix = airborne or CoverageMatrix.from_yaml()
        known: set[str] = set()
        for t in matrix.tactics:
            known.update(t.covered)
            known.update(t.planned)
            known.update(g.id for g in t.uncovered)
        exact: list[str] = []
        subs: list[str] = []
        for tech in dict.fromkeys(s.technique for s in self.surfaces if s.technique):
            if tech in known:
                continue
            parent = tech.split(".")[0]
            if "." in tech and parent in known:
                subs.append(tech)
            else:
                exact.append(tech)
        return NewTechniques(exact_new=exact, subtechnique_of_covered=subs)

    def ground_report(
        self, airborne: CoverageMatrix | None = None
    ) -> GroundSegmentReport:
        """지상 세그먼트 blind KPI 를 산출한다(항공 KPI 와 분리).

        Args:
            airborne: 신규기법 대조용 항공 매트릭스. 생략 시 기본 적재.

        Returns:
            blind/covered 집계 + 세그먼트별 blind + 백로그 + 신규기법 + blind 킬체인.
        """
        total = len(self.surfaces)
        blind = self.blind_spots()
        by_seg: dict[str, int] = {}
        for s in blind:
            by_seg[s.segment] = by_seg.get(s.segment, 0) + 1
        return GroundSegmentReport(
            total_surfaces=total,
            blind=len(blind),
            covered=total - len(blind),
            coverage_pct=round((total - len(blind)) / max(total, 1), 3),
            blind_by_segment=by_seg,
            backlog=self.instrumentation_backlog(),
            new_techniques=self.new_techniques(airborne),
            blind_kill_chains=list(self.blind_kill_chains),
        )
