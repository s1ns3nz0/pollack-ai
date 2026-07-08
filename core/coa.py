"""COA(Courses of Action) Matrix — kill chain 단계 × 7D 방어 옵션(교리 COA matrix).

DoD/Lockheed 교리(JP 3-12, CTI COA matrix)의 결정론 구현. 공격자의 현재 도달
단계 + 예측 다음 단계에 대해 7D 방어(Discover·Detect·Deny·Disrupt·Degrade·
Deceive·Destroy) 옵션을 `core/policy/coa-matrix.yaml` 에서 조회한다. 정의된 셀은
우리 자산(룰=Detect / 디코이=Deceive / 격리=Deny / failover=Disrupt)으로 실행
가능(status=available), 미정의 셀은 방어 공백(gap)으로 노출한다.

실행권은 기존 defense_playbook 이 갖는다 — COA 는 "무엇을 할 수 있나" 결정론 메뉴
(LLM 무관, 운영자 제시용). CoaPlanner 가 kill chain progressor·predictor 산출을
tactic 으로 환산해 집계한다.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.engage import EngageMatrix
from core.exceptions import PolicyError
from core.models import ActorEngagement, CoaOption, EngageGoal
from tools.coverage import CoverageMatrix

_POLICY = Path(__file__).resolve().parent / "policy" / "coa-matrix.yaml"


class CoaMatrix:
    """coa-matrix.yaml 정책 로더 — tactic × 7D 방어 옵션 조회.

    Args:
        defenses: 7D 방어 축 순서.
        matrix: tactic → {defense → {action, d3fend}} 매핑.
    """

    def __init__(
        self,
        defenses: list[str],
        matrix: dict[str, dict[str, dict[str, str]]],
    ) -> None:
        self.defenses = defenses
        self._matrix = matrix

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> CoaMatrix:
        """COA 매트릭스 YAML 을 적재한다.

        Args:
            path: 정책 경로. 생략 시 기본 coa-matrix.yaml.

        Returns:
            로드된 CoaMatrix.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        p = Path(path) if path is not None else _POLICY
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"COA 매트릭스 적재 실패: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError("COA 매트릭스 구조 오류(최상위 dict 아님).")
        defenses = [str(d) for d in raw.get("defenses", [])]
        if not defenses:
            raise PolicyError("COA 매트릭스에 7D 방어 축이 없음.")
        matrix_raw = raw.get("matrix", {})
        matrix: dict[str, dict[str, dict[str, str]]] = {}
        if isinstance(matrix_raw, dict):
            for tactic, cells in matrix_raw.items():
                if not isinstance(cells, dict):
                    continue
                matrix[str(tactic)] = {
                    str(d): {
                        "action": str(c.get("action", "")),
                        "d3fend": str(c.get("d3fend", "")),
                    }
                    for d, c in cells.items()
                    if isinstance(c, dict)
                }
        return cls(defenses, matrix)

    def options_for(self, tactic: str, stage: str = "current") -> list[CoaOption]:
        """한 tactic(kill chain 단계)의 7D COA 옵션 전체를 반환한다.

        정의된 셀은 available, 미정의 7D 셀은 gap(방어 공백)으로 노출한다 —
        7D 축을 전부 포함해 교리 프레임을 유지한다.

        Args:
            tactic: kill chain 단계(tactic 이름).
            stage: "current"(도달 단계) | "predicted"(예측 다음 단계).

        Returns:
            7D 순서의 CoaOption 목록.
        """
        cells = self._matrix.get(tactic, {})
        out: list[CoaOption] = []
        for defense in self.defenses:
            cell = cells.get(defense)
            if cell and cell.get("action"):
                out.append(
                    CoaOption(
                        tactic=tactic,
                        defense=defense,
                        status="available",
                        action=cell["action"],
                        d3fend_id=cell.get("d3fend", ""),
                        stage=stage,
                    )
                )
            else:
                out.append(
                    CoaOption(tactic=tactic, defense=defense, status="gap", stage=stage)
                )
        return out


class CoaPlanner:
    """현재 도달 단계 + 예측 다음 단계 COA 를 집계한다(결정론).

    kill chain progressor(현재 단계)·predictor(다음 단계) 산출을 tactic 으로 환산해
    각 단계의 7D 방어 옵션을 모은다. 대응(current) + 선제(predicted) 통합 메뉴.

    Args:
        coverage: technique↔tactic·order 매핑 커버리지 매트릭스.
        coa: tactic × 7D 방어 옵션 매트릭스.
    """

    def __init__(
        self,
        coverage: CoverageMatrix,
        coa: CoaMatrix,
        engage: EngageMatrix | None = None,
    ) -> None:
        self._cov = coverage
        self._coa = coa
        self._engage = engage

    def plan(
        self,
        current_tactics: list[str],
        predicted_techniques: list[str],
        engagement: ActorEngagement | None = None,
    ) -> list[CoaOption]:
        """현재 최고 단계 + 예측 다음 단계들의 COA 옵션을 반환한다.

        Args:
            current_tactics: 공격자가 현재 도달한 tactic 목록(최고 order 를 채택).
            predicted_techniques: 예측된 다음 technique 목록(tactic 으로 환산).
            engagement: 현 actor 의 Engage 교전 상태. 주입 시 current 단계 Deceive
                셀에 권고 engagement 활동 + adversary_cost 를 주입(MITRE Engage 폐루프).

        Returns:
            current 단계 COA + 예측 tactic 별 COA(중복 tactic 제외). 없으면 빈 리스트.
        """
        out: list[CoaOption] = []
        seen: set[str] = set()
        cur = self._highest_tactic(current_tactics)
        if cur is not None:
            seen.add(cur)
            cur_opts = self._coa.options_for(cur, "current")
            self._enrich_deceive(cur_opts, cur, engagement)
            out.extend(cur_opts)
        for tech in predicted_techniques:
            tactic = self._cov.tactic_of(tech)
            if tactic is None or tactic in seen:
                continue
            seen.add(tactic)
            out.extend(self._coa.options_for(tactic, "predicted"))
        return out

    def _enrich_deceive(
        self,
        options: list[CoaOption],
        tactic: str,
        engagement: ActorEngagement | None,
    ) -> None:
        """current 단계 Deceive 셀에 actor Engage 상태·권고활동·cost 를 주입한다."""
        if (
            self._engage is None
            or engagement is None
            or engagement.state == EngageGoal.NONE
        ):
            return
        rec = self._engage.recommend(engagement.state, [tactic])
        activity = (
            f"{rec.activity}({rec.engage_id})" if rec is not None else "미정의 활동"
        )
        annotation = (
            f"Engage[{engagement.state.value}] → {activity} · "
            f"adv_cost={engagement.adversary_cost} · rounds={engagement.rounds}"
        )
        for opt in options:
            if opt.defense == "Deceive":
                opt.engage = annotation

    def _highest_tactic(self, tactics: list[str]) -> str | None:
        """order 가 매핑된 tactic 중 최고 order 를 반환한다(없으면 None)."""
        best: str | None = None
        best_order = 0
        for tactic in tactics:
            order = self._cov.tactic_order(tactic)
            if order is not None and order > best_order:
                best_order = order
                best = tactic
        return best
