"""Active hunt policy/planner — template-only Sentinel KQL 후보 생성.

1차 버전은 읽기전용 evidence-only 이다. 이 모듈은 네트워크 IO 를 하지 않는다.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from core.exceptions import PolicyError
from core.models import ActiveHuntFinding, Alert, AttackPrediction, MissionRisk
from core.policy_loader import load_policy_mapping, require_mapping
from tools.coverage import CoverageMatrix, TacticCoverage

_POLICY = Path(__file__).resolve().parent / "policy" / "active-hunt.yaml"


class HuntLimits(BaseModel):
    """Active hunt 비용/지연 제한."""

    max_queries_per_alert: int = Field(default=5, ge=1)
    row_limit: int = Field(default=20, ge=1)
    query_timeout_seconds: float = Field(default=8.0, gt=0.0)
    max_lookback_hours: int = Field(default=72, ge=1)


class HuntWindows(BaseModel):
    """방향별 조회 시간창."""

    forward_default_minutes: int = Field(default=30, ge=1)
    backward_default_hours: int = Field(default=24, ge=1)
    backward_force_hours: int = Field(default=72, ge=1)


class BackwardPolicy(BaseModel):
    """Backward hunt 트리거 정책."""

    force_tactics: list[str] = Field(default_factory=list)
    cpcon_thresholds: dict[int, str] = Field(default_factory=dict)
    key_terrain_order_delta: int = -2
    high_mission_risk_order_delta: int = -2
    high_mission_risk_score: int = 8


class HuntQueryTemplate(BaseModel):
    """정책 YAML 의 KQL template 한 건."""

    technique: str
    tactic: str = ""
    direction: Literal["forward", "backward", "both"] = "both"
    table: str
    rationale: str = ""
    kql: str


@dataclass(frozen=True)
class HuntQuery:
    """렌더링 완료된 active hunt query."""

    query_id: str
    direction: Literal["forward", "backward"]
    technique: str
    tactic: str
    kql: str
    timeout_seconds: float
    row_limit: int
    time_window: str
    rationale: str


@dataclass(frozen=True)
class ActiveHuntPlan:
    """Query candidates plus non-executable findings."""

    queries: list[HuntQuery]
    unavailable_findings: list[ActiveHuntFinding]


class ActiveHuntPolicy(BaseModel):
    """Active hunt 정책 루트."""

    version: float = 0.1
    limits: HuntLimits = Field(default_factory=HuntLimits)
    windows: HuntWindows = Field(default_factory=HuntWindows)
    backward_policy: BackwardPolicy = Field(default_factory=BackwardPolicy)
    queries: dict[str, HuntQueryTemplate] = Field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> ActiveHuntPolicy:
        """active-hunt.yaml 을 적재한다.

        Args:
            path: 정책 파일 경로. None 이면 기본 정책.

        Returns:
            검증된 active hunt 정책.

        Raises:
            PolicyError: 파일 부재/파싱 실패/스키마 오류.
        """
        raw = load_policy_mapping(path, _POLICY, label="active hunt 정책")
        try:
            data = dict(raw)
            queries_raw = require_mapping(
                data.get("queries"), label="active hunt queries"
            )
            queries: dict[str, HuntQueryTemplate] = {}
            for qid, query in queries_raw.items():
                if not isinstance(query, dict):
                    raise PolicyError(
                        f"active hunt queries 항목 구조 오류({qid}: 매핑 아님)."
                    )
                queries[str(qid)] = HuntQueryTemplate.model_validate(query)
            data["queries"] = queries
            return cls.model_validate(data)
        except ValidationError as exc:
            raise PolicyError(f"active hunt 정책 검증 실패: {exc}") from exc

    def should_backward_hunt(
        self,
        alert: Alert,
        mission_risk: MissionRisk | None,
        current_order: int,
        cpcon_level: int,
        coverage: CoverageMatrix,
    ) -> bool:
        """CPCON/임무위험/핵심지형 기반 backward hunt 여부를 결정한다."""
        tactics = _alert_tactics(alert)
        if any(t in self.backward_policy.force_tactics for t in tactics):
            return True
        threshold_tactic = self.backward_policy.cpcon_thresholds.get(cpcon_level)
        threshold = coverage.tactic_order(threshold_tactic or "") or current_order + 1
        if alert.key_terrain:
            threshold += self.backward_policy.key_terrain_order_delta
        if (
            mission_risk is not None
            and mission_risk.score >= self.backward_policy.high_mission_risk_score
        ):
            threshold += self.backward_policy.high_mission_risk_order_delta
        max_order = coverage.max_tactic_order([t.name for t in coverage.tactics])
        threshold = max(1, min(max_order, threshold))
        return current_order >= threshold


class ActiveHuntPlanner:
    """Alert context → bounded active hunt query 후보."""

    def __init__(self, policy: ActiveHuntPolicy, coverage: CoverageMatrix) -> None:
        self._policy = policy
        self._coverage = coverage

    def plan(
        self,
        alert: Alert,
        predictions: Sequence[AttackPrediction],
        mission_risk: MissionRisk | None,
        cpcon_level: int,
    ) -> ActiveHuntPlan:
        """forward/backward query 후보를 생성한다."""
        queries: list[HuntQuery] = []
        unavailable: list[ActiveHuntFinding] = []
        alert_time = _alert_time(alert)
        for pred in predictions:
            tactic = self._coverage.tactic_of(pred.next_technique) or ""
            planned = self._queries_for(
                direction="forward",
                technique=pred.next_technique,
                tactic=tactic,
                start=alert_time,
                end=alert_time
                + timedelta(minutes=self._policy.windows.forward_default_minutes),
                rationale=f"예측 다음 technique(p={pred.probability:.2f})",
            )
            if planned:
                queries.extend(planned)
            else:
                unavailable.append(
                    self.unavailable_finding(
                        direction="forward",
                        technique=pred.next_technique,
                        tactic=tactic,
                        rationale="예측 technique template 없음",
                    )
                )
        current_order = self._current_order(alert)
        if self._policy.should_backward_hunt(
            alert, mission_risk, current_order, cpcon_level, self._coverage
        ):
            hours = self._backward_hours(alert)
            start = alert_time - timedelta(hours=hours)
            end = alert_time
            for previous_tactic in self._previous_tactics(current_order):
                for technique in self._techniques_for_tactic(previous_tactic.name):
                    planned = self._queries_for(
                        direction="backward",
                        technique=technique,
                        tactic=previous_tactic.name,
                        start=start,
                        end=end,
                        rationale=f"후반 단계 alert 역추적({previous_tactic.name})",
                    )
                    if planned:
                        queries.extend(planned)
                        continue
                    unavailable.append(
                        self.unavailable_finding(
                            direction="backward",
                            technique=technique,
                            tactic=previous_tactic.name,
                            rationale=(
                                f"후반 단계 alert 역추적({previous_tactic.name}) "
                                "template 없음"
                            ),
                        )
                    )
        return ActiveHuntPlan(
            queries=queries[: self._policy.limits.max_queries_per_alert],
            unavailable_findings=unavailable,
        )

    def unavailable_finding(
        self, direction: str, technique: str, tactic: str, rationale: str
    ) -> ActiveHuntFinding:
        """등록된 template 이 없을 때 report 에 남길 finding."""
        return ActiveHuntFinding(
            direction=direction,
            technique=technique,
            tactic=tactic,
            query_id="query_unavailable",
            rationale=rationale,
            error="query template unavailable",
        )

    def _queries_for(
        self,
        *,
        direction: Literal["forward", "backward"],
        technique: str,
        tactic: str,
        start: datetime,
        end: datetime,
        rationale: str,
    ) -> list[HuntQuery]:
        out: list[HuntQuery] = []
        for qid, tmpl in self._policy.queries.items():
            if tmpl.technique != technique:
                continue
            if tmpl.direction not in (direction, "both"):
                continue
            kql = tmpl.kql.format(
                start=_fmt(start),
                end=_fmt(end),
                row_limit=self._policy.limits.row_limit,
            )
            out.append(
                HuntQuery(
                    query_id=qid,
                    direction=direction,
                    technique=technique,
                    tactic=tactic or tmpl.tactic,
                    kql=kql,
                    timeout_seconds=self._policy.limits.query_timeout_seconds,
                    row_limit=self._policy.limits.row_limit,
                    time_window=f"{_fmt(start)}..{_fmt(end)}",
                    rationale=tmpl.rationale or rationale,
                )
            )
        return out

    def _current_order(self, alert: Alert) -> int:
        return self._coverage.max_tactic_order(_alert_tactics(alert))

    def _backward_hours(self, alert: Alert) -> int:
        tactics = _alert_tactics(alert)
        force = any(t in self._policy.backward_policy.force_tactics for t in tactics)
        hours = (
            self._policy.windows.backward_force_hours
            if force
            else self._policy.windows.backward_default_hours
        )
        return min(hours, self._policy.limits.max_lookback_hours)

    def _previous_tactics(self, current_order: int) -> list[TacticCoverage]:
        return [t for t in self._coverage.tactics if 0 < t.order < current_order]

    def _techniques_for_tactic(self, tactic: str) -> list[str]:
        for t in self._coverage.tactics:
            if t.name == tactic:
                techniques = [*t.covered, *t.planned, *(g.id for g in t.uncovered)]
                return list(dict.fromkeys(techniques))
        return []


def _alert_tactics(alert: Alert) -> list[str]:
    raw = alert.mitre.get("tactics", [])
    return [str(t) for t in raw] if isinstance(raw, list) else []


def _alert_time(alert: Alert) -> datetime:
    raw = getattr(alert, "timestamp", None) or getattr(alert, "time_generated", None)
    if not isinstance(raw, str) or not raw:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC)


def _fmt(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
