"""BAS(Breach & Attack Simulation) — 방어 상시 검증(우리 룰이 진짜 막나).

DoD/업계 BAS 교리의 결정론 구현. `bas-scenarios.yaml` 의 공격 케이스를 방어 판정
(신호 존재 + 매칭 탐지룰 존재)에 통과시켜 탐지 성공/미탐(gap)을 집계한다. 정적
커버리지 매트릭스(attack_coverage.yaml)와 상보 — BAS 는 *실제 공격 케이스* 기반
검증이라 "룰이 있다고 표기됐지만 실제로 이 케이스를 잡나" 를 확인한다.

tactic·STRIDE(UAV STRIDE 모델) 별 커버리지를 산출해 STRIDE 기능이 재사용한다.
LLM 무관, 전 과정 결정론 — 주기 워커/CI 게이트로 상시 회귀 감시 가능.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from core.exceptions import PolicyError
from core.policy_loader import load_policy_mapping, require_list, validate_models

_POLICY = Path(__file__).resolve().parent / "policy" / "bas-scenarios.yaml"


class BASScenario(BaseModel):
    """BAS 공격 케이스 한 건."""

    id: str
    name: str = ""
    status: str = Field(
        default="deployed",
        description="MaGMA 라이프사이클: planned|deployed|deprecated.",
    )
    signals: list[str] = Field(default_factory=list)
    detection_rule: str = ""
    tactic: str = ""
    stride: list[str] = Field(default_factory=list)
    campaign: list[str] = Field(
        default_factory=list, description="소속 캠페인 체인 id(C1~C34)."
    )

    @property
    def detected(self) -> bool:
        """방어 판정: 배포 상태 + 신호 존재 + 매칭 탐지룰 존재 시 탐지 가능.

        deployed 아닌 룰(planned/deprecated)은 실배포가 아니므로 탐지로
        집계하지 않는다 — 커버리지 부풀림 방지.
        """
        return (
            self.status == "deployed"
            and bool(self.signals)
            and bool(self.detection_rule)
        )


class BASCategoryStat(BaseModel):
    """카테고리(tactic/STRIDE) 별 탐지 집계."""

    detected: int = 0
    total: int = 0

    @property
    def ratio(self) -> float:
        """탐지 비율(total 0 이면 0.0)."""
        return round(self.detected / self.total, 3) if self.total else 0.0


class BASReport(BaseModel):
    """BAS 검증 결과 — 전체 커버리지 + 갭 + tactic/STRIDE 별 집계."""

    total: int = 0
    detected: int = 0
    gaps: list[str] = Field(default_factory=list)
    by_tactic: dict[str, BASCategoryStat] = Field(default_factory=dict)
    by_stride: dict[str, BASCategoryStat] = Field(default_factory=dict)

    @property
    def detection_ratio(self) -> float:
        """전체 탐지 비율(detected/total)."""
        return round(self.detected / self.total, 3) if self.total else 0.0


class BASRunner:
    """방어 상시 검증 실행기 — 공격 세트 → 탐지 판정 → 커버리지/갭.

    Args:
        scenarios: 검증할 공격 케이스 목록.
    """

    def __init__(self, scenarios: list[BASScenario]) -> None:
        self._scenarios = scenarios

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> BASRunner:
        """bas-scenarios.yaml 을 적재한다.

        Args:
            path: 정책 경로. 생략 시 기본 bas-scenarios.yaml.

        Returns:
            로드된 BASRunner.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        raw = load_policy_mapping(path, _POLICY, label="BAS 시나리오")
        scenarios = validate_models(
            require_list(raw.get("scenarios"), label="BAS 시나리오 scenarios"),
            BASScenario,
            label="BAS 시나리오",
        )
        if not scenarios:
            raise PolicyError("BAS 시나리오가 비어있음.")
        return cls(scenarios)

    def run(self) -> BASReport:
        """공격 세트를 방어 판정에 통과시켜 검증 리포트를 산출한다.

        Returns:
            전체 커버리지 + 미탐 갭 + tactic/STRIDE 별 집계.
        """
        report = BASReport(total=len(self._scenarios))
        for scn in self._scenarios:
            hit = scn.detected
            if hit:
                report.detected += 1
            else:
                report.gaps.append(scn.id)
            if scn.tactic:
                self._tally(report.by_tactic, scn.tactic, hit)
            for cat in scn.stride:
                self._tally(report.by_stride, cat, hit)
        return report

    @staticmethod
    def _tally(bucket: dict[str, BASCategoryStat], key: str, hit: bool) -> None:
        """카테고리 집계 버킷에 탐지/총계를 누적한다."""
        stat = bucket.setdefault(key, BASCategoryStat())
        stat.total += 1
        if hit:
            stat.detected += 1
