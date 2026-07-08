"""MITRE Engage 적 교전 폐루프 — 상태 전진기 + 활동 플래너(결정론).

decoy/canary 레이어를 MITRE Engage 작전계층으로 승격한다. actor 별 Engage 목표
`NONE→EXPOSE→ELICIT→UNDERSTAND`(3 코어)를 **신뢰 canary 접촉(CONFIRMED_TP)** 에서만
전진시키고, kill-chain 지연 대리지표(adversary_cost)를 누적한다. EngagePlanner 는
(목표 × kill-chain 단계)로 다음 권고 engagement 활동을 engage-matrix.yaml 에서 조회한다.

트러스트: 전진은 신뢰 관측 채널(`ProbeDecision.engagement`)에서만. untrusted decoy_hit
(alert 본문)은 severity 색칠만 — Engage 상태를 못 바꾼다(포이즈닝 면역). 전진은 alert_id
멱등 처리해 replay 이중계상을 막는다.

Affect(능동 교란)는 이 모듈 범위 밖 — 권고까지만, 자동 외향행동은 영구 금지(HITL).

Spec: docs/superpowers/specs/2026-07-08-mitre-engage-adversary-loop-design.md
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel
import yaml

from core.exceptions import PolicyError
from core.models import ActorProfile, Alert, EngageGoal
from tools.coverage import CoverageMatrix

_POLICY = Path(__file__).resolve().parent / "policy" / "engage-matrix.yaml"

# round→목표 기본 임계(policy 로 튜닝). 1=EXPOSE, 2=ELICIT, 4=UNDERSTAND(종단).
_EXPOSE_AT = 1
_ELICIT_AT = 2
_UNDERSTAND_AT = 4
# seen_alert_ids 슬라이딩 cap — 멱등키 무한증가 방지. actor 별 실제 교전량 상한
# (kill_chain cap=50)의 수 배로 잡아, cap 축출 후 재계상(Codex M-b)은 정상 운용
# 범위 밖. 완전 무한 멱등이 필요하면 신뢰 ObservationSource 측에서 1차 dedup.
_SEEN_CAP = 500


def _alert_tactics(alert: Alert) -> list[str]:
    """alert.mitre 에서 tactic 목록을 안전 추출한다."""
    raw = alert.mitre.get("tactics", [])
    return [str(t) for t in raw] if isinstance(raw, list) else []


def _state_for_rounds(rounds: int) -> EngageGoal:
    """누적 교전 라운드 → Engage 목표(단조 전진)."""
    if rounds >= _UNDERSTAND_AT:
        return EngageGoal.UNDERSTAND
    if rounds >= _ELICIT_AT:
        return EngageGoal.ELICIT
    if rounds >= _EXPOSE_AT:
        return EngageGoal.EXPOSE
    return EngageGoal.NONE


class EngageAdvancer:
    """신뢰 canary→TP 시 actor Engage 상태 전진 + adversary_cost 누적(멱등).

    Args:
        matrix: kill-chain stage-order 산정용 커버리지 매트릭스.
        seen_cap: seen_alert_ids 슬라이딩 상한(멱등키 관리).
    """

    def __init__(
        self, matrix: CoverageMatrix | None = None, seen_cap: int = _SEEN_CAP
    ) -> None:
        self._matrix = matrix or CoverageMatrix.from_yaml()
        self._seen_cap = seen_cap

    def advance(self, profile: ActorProfile, alert: Alert) -> bool:
        """신뢰 교전 1건을 반영해 상태 전진 + cost 누적한다(alert_id 멱등).

        Args:
            profile: 전진 대상 프로필(제자리 변이).
            alert: 교전을 유발한 CONFIRMED_TP 알람(신뢰 관측 재구성).

        Returns:
            실제 전진했으면 True, id 부재 또는 이미 반영된 alert_id(멱등 skip)면 False.
        """
        eng = profile.engagement
        # 멱등키 없는(빈 alert_id) 관측은 dedup 불가 → 전진 금지(Codex M-b: 무한
        # 재계상 방지). 신뢰 ObservationSource 는 실 교전마다 고유 alert_id 를 채운다.
        if not alert.id or alert.id in eng.seen_alert_ids:
            return False
        eng.seen_alert_ids.append(alert.id)
        if len(eng.seen_alert_ids) > self._seen_cap:
            eng.seen_alert_ids = eng.seen_alert_ids[-self._seen_cap :]
        eng.rounds += 1
        eng.state = _state_for_rounds(eng.rounds)
        # adversary_cost = kill-chain 지연 대리지표: 교전 시점 최고 stage-order 누적.
        order = self._matrix.max_tactic_order(_alert_tactics(alert))
        eng.adversary_cost += max(order, 0)
        return True


class EngageRecommendation(BaseModel):
    """(Engage 목표 × kill-chain 단계) → 권고 engagement 활동 한 건."""

    goal: EngageGoal
    tactic: str = ""
    activity: str
    engage_id: str = ""


class EngageMatrix:
    """engage-matrix.yaml 로더 — (목표 × tactic) → 활동."""

    def __init__(self, matrix: dict[str, dict[str, dict[str, str]]]) -> None:
        self._matrix = matrix

    def recommend(
        self, goal: EngageGoal, tactics: list[str]
    ) -> EngageRecommendation | None:
        """목표 + tactic 목록으로 권고활동을 조회한다(tactic 우선, "*" 폴백).

        Args:
            goal: 현 Engage 목표.
            tactics: 현 alert 의 tactic 목록.

        Returns:
            매칭 EngageRecommendation. 목표/셀 미정의면 None.
        """
        cells = self._matrix.get(goal.value)
        if not cells:
            return None
        for tactic in tactics:
            cell = cells.get(tactic)
            if cell:
                return self._to_rec(goal, tactic, cell)
        star = cells.get("*")
        if star:
            return self._to_rec(goal, "*", star)
        return None

    @staticmethod
    def _to_rec(
        goal: EngageGoal, tactic: str, cell: dict[str, str]
    ) -> EngageRecommendation:
        return EngageRecommendation(
            goal=goal,
            tactic=tactic,
            activity=str(cell.get("activity", "")),
            engage_id=str(cell.get("engage_id", "")),
        )

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> EngageMatrix:
        """engage-matrix.yaml 을 적재한다.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치/빈 매트릭스 시.
        """
        p = Path(path) if path is not None else _POLICY
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"engage 매트릭스 적재 실패: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError("engage 매트릭스 구조 오류(최상위 dict 아님).")
        engage = raw.get("engage")
        if not isinstance(engage, dict) or not engage:
            raise PolicyError("engage 매트릭스가 비어있음.")
        matrix: dict[str, dict[str, dict[str, str]]] = {}
        for goal, cells in engage.items():
            if not isinstance(cells, dict):
                continue
            matrix[str(goal)] = {
                str(tac): {str(k): str(v) for k, v in cell.items()}
                for tac, cell in cells.items()
                if isinstance(cell, dict)
            }
        return cls(matrix)


class EngagePlanner:
    """actor Engage 상태 + kill-chain 단계 → 권고활동 산출(EngageMatrix 위임).

    Args:
        matrix: engage-matrix.yaml 로더. 미주입 시 기본 정책 적재.
    """

    def __init__(self, matrix: EngageMatrix | None = None) -> None:
        self._matrix = matrix or EngageMatrix.from_yaml()

    def recommend(
        self, profile: ActorProfile, tactics: list[str]
    ) -> EngageRecommendation | None:
        """프로필 현 Engage 목표 + tactic 으로 다음 권고활동을 조회한다.

        Args:
            profile: 교전 상태 보유 프로필.
            tactics: 현 alert 의 tactic 목록.

        Returns:
            권고 EngageRecommendation. 미교전(NONE)이거나 미정의면 None.
        """
        goal = profile.engagement.state
        if goal == EngageGoal.NONE:
            return None
        return self._matrix.recommend(goal, tactics)
