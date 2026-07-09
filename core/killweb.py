"""Mosaic / Kill Web — 단계별 커버리지 breadth 그래프(결정론·읽기전용·자문).

선형 kill-chain 을 교체하지 않는다 — coverage/ground 를 단계별 커버리지 breadth
관점으로 재조명·합성만 한다. 각 킬체인 단계(tactic)에 covered ATT&CK **기법이 몇
개**인가.

**정직성(Codex Critical): 기법 수 ≠ 독립 센서/로그원.** 두 covered 기법이 같은
로그원에 의존할 수 있어 진짜 탐지경로 중복(SPOF-free)을 증명하지 않는다. 따라서
"센서 하나 죽어도 대체" 단정 금지 — coverage breadth 로만 표현하고 single_technique
를 SPOF 로 단정하지 않는다. "mosaic" 은 viz 프레이밍. 정적 posture.

Spec: docs/superpowers/specs/2026-07-09-killweb-resilience-design.md
"""

from __future__ import annotations

from core.exceptions import CoverageDataError
from core.models import KillWebResilience
from tools.coverage import CoverageMatrix, GroundSegmentCoverage, TacticCoverage
from utils.logging import get_logger

_logger = get_logger("killweb")

# pre-compromise 단계(order ≤ 2: Recon·ResourceDev) — breadth 분모 제외.
# stage-level scope. coverage.py addressable_pct(archetype 기반)와 동일 계산 아님.
_PRE_COMPROMISE_MAX_ORDER = 2

_HONESTY = "기법 수 ≠ 독립 센서/로그원 — breadth 지표(SPOF 미증명)"


def _stage_bucket(t: TacticCoverage) -> str:
    """단계를 covered 기법 수로 분류(planned 은 활성 탐지로 안 셈)."""
    n = len(t.covered)
    total = n + len(t.planned) + len(t.uncovered)
    if total == 0:
        return "empty"
    if n >= 2:
        return "multi"
    if n == 1:
        return "single"
    return "uncovered"


class KillWebBuilder:
    """coverage/ground 를 단계별 breadth 로 합성(정적·결정론).

    Args:
        matrix: 항공 커버리지 매트릭스(.tactics 로 order/covered 접근).
        ground_blind: 지상 세그먼트 구조적 사각 수(정책 실패 시 0).
        degraded: 로드 실패 여부.
        degraded_reason: 실패 사유.
    """

    def __init__(
        self,
        matrix: CoverageMatrix | None,
        ground_blind: int = 0,
        degraded: bool = False,
        degraded_reason: str = "",
    ) -> None:
        self._matrix = matrix
        self._ground_blind = ground_blind
        self._degraded = degraded
        self._degraded_reason = degraded_reason

    @classmethod
    def load(cls) -> KillWebBuilder:
        """coverage/ground 정책 적재(graceful degrade).

        coverage 또는 ground 로드 실패는 예외를 던지지 않고 degraded 빌더로 반환한다
        — 깨진 정책이 리포트 생성을 막지 못하게(fail-safe). 실패는 warning 관측.
        """
        # 정책 로더가 감싸기 전 원시 ValueError(int order)/TypeError(스칼라 iter)도
        # 낼 수 있어 함께 잡는다 — advisory posture 가 report init 크래시 못하게(Codex).
        try:
            matrix = CoverageMatrix.from_yaml()
        except (CoverageDataError, ValueError, TypeError) as exc:
            _logger.warning("killweb: 커버리지 로드 실패, degraded: %s", exc)
            return cls(None, degraded=True, degraded_reason=f"coverage: {exc}")
        try:
            ground_blind = GroundSegmentCoverage.from_yaml().ground_report().blind
        except (CoverageDataError, ValueError, TypeError) as exc:
            _logger.warning("killweb: 지상 로드 실패(blind=0 처리): %s", exc)
            ground_blind = 0
        return cls(matrix, ground_blind=ground_blind)

    def resilience(self) -> KillWebResilience:
        """단계별 커버리지 breadth 요약을 산출한다(정직·과장 금지).

        Returns:
            단계 분류 + breadth ratio + 지상 사각. degraded 시 빈 목록 + degraded=True.
        """
        if self._matrix is None:
            return KillWebResilience(
                degraded=True,
                degraded_reason=self._degraded_reason or "coverage 미로드",
                rationale=[f"degraded — {_HONESTY}"],
            )
        multi: list[str] = []
        single: list[str] = []
        uncovered: list[str] = []
        empty: list[str] = []
        # CoverageMatrix.tactics 는 order 순 정렬 — 결정론 출력.
        for t in self._matrix.tactics:
            if t.order <= _PRE_COMPROMISE_MAX_ORDER:
                continue  # pre-compromise scope 밖.
            bucket = _stage_bucket(t)
            {"multi": multi, "single": single, "uncovered": uncovered, "empty": empty}[
                bucket
            ].append(t.name)
        in_scope = len(multi) + len(single) + len(uncovered)  # empty 제외.
        rationale = [_HONESTY]
        if single:
            rationale.append(f"단일 커버 기법 단계(센서 독립성 미증명): {single}")
        if uncovered:
            rationale.append(f"미탐 단계: {uncovered}")
        if self._ground_blind:
            rationale.append(f"지상 구조적 사각 {self._ground_blind}면")
        return KillWebResilience(
            multi_technique_stages=multi,
            single_technique_stages=single,
            uncovered_stages=uncovered,
            empty_stages=empty,
            blind_surface_count=self._ground_blind,
            coverage_breadth_ratio=round(len(multi) / max(in_scope, 1), 3),
            rationale=rationale,
        )

    def to_cytoscape(self) -> dict[str, list[dict[str, object]]]:
        """tactic·technique 노드 + belongs 엣지(Cytoscape, order 순·결정론).

        Returns:
            {"nodes": [...], "edges": [...]}. degraded 시 빈 구조.
        """
        nodes: list[dict[str, object]] = []
        edges: list[dict[str, object]] = []
        if self._matrix is None:
            return {"nodes": nodes, "edges": edges}
        seen: set[str] = set()  # 노드 id 중복 제거(같은 기법이 여러 tactic 소속 가능).

        def _add_node(node_id: str, data: dict[str, object]) -> None:
            if node_id not in seen:
                seen.add(node_id)
                nodes.append({"data": data})

        for t in self._matrix.tactics:
            tac_id = f"tactic:{t.name}"
            _add_node(tac_id, {"id": tac_id, "kind": "tactic", "label": t.name})
            for status, techs in (
                ("covered", t.covered),
                ("planned", t.planned),
                ("uncovered", [g.id for g in t.uncovered]),
            ):
                for tech in techs:
                    tid = f"technique:{tech}"
                    _add_node(tid, {"id": tid, "kind": "technique", "status": status})
                    # belongs 엣지는 tactic 별 별개(기법이 여러 단계 소속) — id 부여.
                    edges.append(
                        {
                            "data": {
                                "id": f"{tid}->{tac_id}:belongs",
                                "source": tid,
                                "target": tac_id,
                                "type": "belongs",
                            }
                        }
                    )
        return {"nodes": nodes, "edges": edges}
