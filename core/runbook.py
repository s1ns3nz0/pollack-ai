"""Runbook 정책 카탈로그 — detection rule 단위 수동 실행 절차.

Playbook 은 전술 단위 "무엇을 할 것인가"이고, Runbook 은 탐지룰/시나리오 단위
"어떻게 수행할 것인가" 계약이다. v1 은 manual-only/no-exec 로 고정한다.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from core.bas import BASScenario
from core.cacao import CacaoPlaybook, select_playbook
from core.exceptions import PolicyError
from core.policy_loader import load_policy_mapping, require_list, validate_models

_POLICY = Path(__file__).resolve().parent / "policy" / "runbooks.yaml"


class _Strict(BaseModel):
    """미지 키를 거부하는 runbook 정책 기반 모델."""

    model_config = ConfigDict(extra="forbid")


class RunbookStep(_Strict):
    """운용자 수동 절차 한 단계."""

    id: str
    kind: Literal["manual"]
    action: str


class RunbookApproval(_Strict):
    """Runbook 승인 정책."""

    required: bool = False
    reason: str = ""


class RunbookEvidence(_Strict):
    """Runbook 이 확인해야 하는 evidence 필드."""

    required: list[str] = Field(default_factory=list)
    optional: list[str] = Field(default_factory=list)


class VerificationStep(_Strict):
    """복구/축출 검증 계약."""

    method: Literal["outcome_probe"]
    expected: str


class Runbook(_Strict):
    """탐지 시나리오별 실행 절차 계약."""

    id: str
    scenario_id: str
    detection_rule: str
    playbook_id: str
    tactic: str
    detail_level: Literal["generated", "curated"] = "generated"
    evidence: RunbookEvidence = Field(default_factory=RunbookEvidence)
    operator_steps: list[RunbookStep]
    approval: RunbookApproval = Field(default_factory=RunbookApproval)
    verification: VerificationStep


class RunbookReadinessSummary(BaseModel):
    """Runbook 카탈로그 품질 요약."""

    total: int = 0
    curated: int = 0
    generated: int = 0
    generated_backlog: list[str] = Field(default_factory=list)

    @property
    def readiness_ratio(self) -> float:
        """curated runbook 비율."""
        return round(self.curated / self.total, 3) if self.total else 0.0


class RunbookCatalog:
    """scenario_id 로 조회 가능한 Runbook 목록."""

    def __init__(self, runbooks: list[Runbook]) -> None:
        self.runbooks = runbooks
        self._by_scenario = {rb.scenario_id: rb for rb in runbooks}

    @classmethod
    def from_runbooks(cls, runbooks: list[Runbook]) -> RunbookCatalog:
        """검증된 Runbook 목록으로 카탈로그를 만든다."""
        return cls(runbooks)

    def by_scenario(self, scenario_id: str) -> Runbook | None:
        """scenario_id 에 정확히 일치하는 Runbook 을 반환한다."""
        return self._by_scenario.get(scenario_id)

    def readiness_summary(self) -> RunbookReadinessSummary:
        """generated scaffold 와 curated runbook 을 분리해 요약한다."""
        curated = sum(1 for rb in self.runbooks if rb.detail_level == "curated")
        generated_backlog = sorted(
            rb.scenario_id for rb in self.runbooks if rb.detail_level == "generated"
        )
        return RunbookReadinessSummary(
            total=len(self.runbooks),
            curated=curated,
            generated=len(generated_backlog),
            generated_backlog=generated_backlog,
        )

    def __iter__(self) -> Iterator[Runbook]:
        """카탈로그의 Runbook 을 순회한다."""
        return iter(self.runbooks)


def load_runbooks(path: str | Path | None = None) -> RunbookCatalog:
    """runbooks.yaml 을 적재한다.

    Args:
        path: 정책 경로. 생략 시 기본 runbooks.yaml.

    Returns:
        RunbookCatalog.

    Raises:
        PolicyError: 파일 부재/구조/스키마 오류 시.
    """
    raw = load_policy_mapping(path, _POLICY, label="Runbook")
    runbooks = validate_models(
        require_list(raw.get("runbooks"), label="Runbook runbooks"),
        Runbook,
        label="Runbook",
        skip_non_dict=False,
    )
    if not runbooks:
        raise PolicyError("Runbook 이 비어있음.")
    return RunbookCatalog(runbooks)


def validate_runbook_catalog(
    *,
    runbooks: RunbookCatalog,
    scenarios: list[BASScenario],
    playbooks: list[CacaoPlaybook],
    scenario_tactic: dict[str, str],
) -> None:
    """Runbook 카탈로그가 BAS/CACAO 계약과 일치하는지 검증한다.

    Args:
        runbooks: 검증 대상 Runbook 카탈로그.
        scenarios: BAS 시나리오 목록.
        playbooks: CACAO 플레이북 목록.
        scenario_tactic: scenario_id -> tactic 맵.

    Raises:
        PolicyError: 누락/불일치/빈 절차가 있을 때.
    """
    detection_scenarios = {s.id: s for s in scenarios if s.detection_rule}
    known_playbook_ids = {pb.id for pb in playbooks}
    seen: set[str] = set()
    errors: list[str] = []

    for rb in runbooks.runbooks:
        scenario = detection_scenarios.get(rb.scenario_id)
        if scenario is None:
            errors.append(f"{rb.id}: 미지 detection scenario {rb.scenario_id}")
            continue
        seen.add(rb.scenario_id)
        if rb.detection_rule != scenario.detection_rule:
            errors.append(f"{rb.id}: detection_rule 불일치")
        expected_tactic = scenario_tactic.get(rb.scenario_id, scenario.tactic)
        if rb.tactic != expected_tactic:
            errors.append(f"{rb.id}: tactic 불일치 {rb.tactic}!={expected_tactic}")
        if rb.playbook_id not in known_playbook_ids:
            errors.append(f"{rb.id}: 미지 playbook_id {rb.playbook_id}")
        selected = select_playbook(expected_tactic, playbooks)
        if selected is not None and rb.playbook_id != selected.id:
            errors.append(
                f"{rb.id}: playbook_id 불일치 {rb.playbook_id}!={selected.id}"
            )
        if not rb.operator_steps:
            errors.append(f"{rb.id}: operator_steps 비어있음")
        if not rb.verification.method:
            errors.append(f"{rb.id}: verification 누락")

    missing = sorted(set(detection_scenarios) - seen)
    if missing:
        errors.append(f"Runbook 누락: {missing[:10]} 총 {len(missing)}건")
    if errors:
        raise PolicyError("; ".join(errors))
