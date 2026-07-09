"""AI 레드팀 결정론 회귀 게이트 — 인젝션 가드 상시 검증(BAS 의 AI 버전).

방금 구현한 프롬프트 인젝션 가드(core/prompt_guard.py)가 **실제 공격을 표식하고
정상 문구를 무탐(FP 없음)** 하는지 결정론 시나리오로 상시 검증한다. BAS(core/bas.py,
방어 상시 검증)를 AI 위협(ATLAS AML.T0051)으로 확장 — 가드가 회귀(패턴 약화/FP 증가)
하면 이 게이트가 실패해 CI 에서 잡는다.

expect 판정(가드 scan 결과 대조):
  - high    : high_confidence 여야 통과(우리 시스템 직접 조작 active 공격).
  - detected: detected 여야 통과(인젝션 표식).
  - benign  : detected=False 여야 통과(정상 SOC 문구 — FP 회귀 가드).

Spec: docs/superpowers/specs/2026-07-09-ai-redteam-gate-design.md
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from core.exceptions import PolicyError
from core.policy_loader import load_policy_mapping, require_list, validate_models
from core.prompt_guard import PromptInjectionGuard, load_default_guard

_POLICY = Path(__file__).resolve().parent / "policy" / "ai-redteam-scenarios.yaml"
_VALID_EXPECT = frozenset({"high", "detected", "benign"})


class AiRedTeamCase(BaseModel):
    """AI 레드팀 공격/정상 케이스 한 건.

    Attributes:
        id: 케이스 식별자.
        name: 사람이 읽을 이름.
        payload: 가드에 넣을 텍스트(공격 페이로드 또는 정상 문구).
        expect: 기대 결과("high"|"detected"|"benign").
        atlas: MITRE ATLAS technique id(공격 케이스만).
    """

    id: str
    name: str = ""
    payload: str = ""
    expect: str = "detected"
    atlas: str = ""


class AiRedTeamReport(BaseModel):
    """AI 레드팀 회귀 검증 결과 — 통과/실패 + ATLAS 별 집계.

    Attributes:
        total: 전체 케이스 수.
        passed: 기대와 일치한 수.
        failures: 실패 케이스 상세(가드 회귀/FP).
        by_expect: expect 유형별 (passed, total).
    """

    total: int = 0
    passed: int = 0
    failures: list[str] = Field(default_factory=list)
    by_expect: dict[str, list[int]] = Field(default_factory=dict)

    @property
    def pass_ratio(self) -> float:
        """통과 비율(total 0 이면 0.0)."""
        return round(self.passed / self.total, 3) if self.total else 0.0


class AiRedTeamRunner:
    """인젝션 가드 회귀 검증 실행기(결정론·읽기전용).

    Args:
        cases: 검증할 레드팀 케이스.
        guard: 검증 대상 가드(미주입 시 기본 정책 로드).
    """

    def __init__(
        self, cases: list[AiRedTeamCase], guard: PromptInjectionGuard | None = None
    ) -> None:
        self._cases = cases
        self._guard = guard or load_default_guard()

    @classmethod
    def from_yaml(
        cls, path: str | Path | None = None, guard: PromptInjectionGuard | None = None
    ) -> AiRedTeamRunner:
        """ai-redteam-scenarios.yaml 을 적재한다(공유 로더로 graceful).

        Args:
            path: 정책 경로. 생략 시 기본 시나리오.
            guard: 검증 대상 가드(미주입 시 기본).

        Returns:
            로드된 AiRedTeamRunner.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치/빈 시나리오 시.
        """
        raw = load_policy_mapping(path, _POLICY, label="AI 레드팀 시나리오")
        cases = validate_models(
            require_list(raw.get("scenarios"), label="AI 레드팀 scenarios"),
            AiRedTeamCase,
            label="AI 레드팀 시나리오",
        )
        if not cases:
            raise PolicyError("AI 레드팀 시나리오가 비어있음.")
        return cls(cases, guard)

    def _case_passes(self, case: AiRedTeamCase) -> bool:
        """단일 케이스 — 가드 scan 결과가 expect 와 일치하는지."""
        v = self._guard.scan(case.payload)
        if case.expect == "high":
            return v.high_confidence
        if case.expect == "detected":
            return v.detected
        # benign — 무탐이어야 통과(FP 회귀 가드).
        return not v.detected

    def run(self) -> AiRedTeamReport:
        """레드팀 케이스를 가드에 통과시켜 회귀 검증 리포트를 산출한다.

        Returns:
            통과/실패 + expect 유형별 집계.
        """
        report = AiRedTeamReport(total=len(self._cases))
        for case in self._cases:
            ok = self._case_passes(case)
            bucket = report.by_expect.setdefault(case.expect, [0, 0])
            bucket[1] += 1
            if ok:
                report.passed += 1
                bucket[0] += 1
            else:
                report.failures.append(f"{case.id}(expect={case.expect})")
        return report
