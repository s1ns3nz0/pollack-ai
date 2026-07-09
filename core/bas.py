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
from typing import Literal

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
    instrumentation_status: Literal[
        "native", "proxy", "reconstructed", "design_blind", "proposed_schema"
    ] = Field(
        default="native",
        description=(
            "탐지 근거 품질: "
            "native|proxy|reconstructed|design_blind|proposed_schema."
        ),
    )
    tactic: str = ""
    stride: list[str] = Field(default_factory=list)
    campaign: list[str] = Field(
        default_factory=list, description="소속 캠페인 체인 id(C1~C34)."
    )

    @property
    def detected(self) -> bool:
        """룰 존재 판정: 배포 상태 + 신호 존재 + 매칭 탐지룰 존재 시 True.

        deployed 아닌 룰(planned/deprecated)은 실배포가 아니므로 탐지로
        집계하지 않는다. 단, proxy/design_blind 도 True 일 수 있으므로 이 값은
        native readiness 와 동일하지 않다.
        """
        return (
            self.status == "deployed"
            and bool(self.signals)
            and bool(self.detection_rule)
        )

    @property
    def native_ready(self) -> bool:
        """실측 native 계측으로 탐지 가능한지 반환한다."""
        return self.detected and self.instrumentation_status == "native"


class BASCategoryStat(BaseModel):
    """카테고리(tactic/STRIDE) 별 탐지 집계."""

    detected: int = 0
    total: int = 0

    @property
    def ratio(self) -> float:
        """탐지 비율(total 0 이면 0.0)."""
        return round(self.detected / self.total, 3) if self.total else 0.0


class BASRemediationBacklogItem(BaseModel):
    """비-native BAS 탐지를 native readiness 로 올리기 위한 계측 백로그."""

    status: str
    scenario_count: int
    scenarios: list[str] = Field(default_factory=list)
    remediation: str = ""


_REMEDIATION_BY_STATUS = {
    "proxy": "전용 로그원/컬럼을 추가해 관례값·근사 조건을 native signal 로 전환",
    "reconstructed": "mission/opmode 원천 이벤트를 보강해 재구성 추론 의존도를 제거",
    "design_blind": "수동·passive 행위 한계를 명시하고 예방통제/외부센서로 별도 커버",
    "proposed_schema": "제안 스키마를 DCR/테이블/룰 배포까지 승격",
}


class BASReport(BaseModel):
    """BAS 검증 결과 — 전체 커버리지 + 갭 + tactic/STRIDE 별 집계."""

    total: int = 0
    detected: int = 0
    native_detected: int = 0
    proxy_detected: int = 0
    reconstructed_detected: int = 0
    design_blind_detected: int = 0
    proposed_schema_detected: int = 0
    gaps: list[str] = Field(default_factory=list)
    quality_gaps: dict[str, list[str]] = Field(default_factory=dict)
    remediation_backlog: list[BASRemediationBacklogItem] = Field(default_factory=list)
    by_tactic: dict[str, BASCategoryStat] = Field(default_factory=dict)
    by_stride: dict[str, BASCategoryStat] = Field(default_factory=dict)

    @property
    def detection_ratio(self) -> float:
        """전체 룰 존재 비율(detected/total)."""
        return round(self.detected / self.total, 3) if self.total else 0.0

    @property
    def readiness_ratio(self) -> float:
        """실측 native 탐지 준비도(native_detected/total)."""
        return round(self.native_detected / self.total, 3) if self.total else 0.0


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
                self._tally_quality(report, scn)
            else:
                report.gaps.append(scn.id)
            if scn.tactic:
                self._tally(report.by_tactic, scn.tactic, hit)
            for cat in scn.stride:
                self._tally(report.by_stride, cat, hit)
        report.remediation_backlog = self._remediation_backlog(report.quality_gaps)
        return report

    @staticmethod
    def _tally(bucket: dict[str, BASCategoryStat], key: str, hit: bool) -> None:
        """카테고리 집계 버킷에 탐지/총계를 누적한다."""
        stat = bucket.setdefault(key, BASCategoryStat())
        stat.total += 1
        if hit:
            stat.detected += 1

    @staticmethod
    def _tally_quality(report: BASReport, scenario: BASScenario) -> None:
        """계측 품질별 탐지 수와 품질 갭 목록을 누적한다."""
        if scenario.instrumentation_status == "native":
            report.native_detected += 1
            return
        if scenario.instrumentation_status == "proxy":
            report.proxy_detected += 1
        elif scenario.instrumentation_status == "reconstructed":
            report.reconstructed_detected += 1
        elif scenario.instrumentation_status == "design_blind":
            report.design_blind_detected += 1
        elif scenario.instrumentation_status == "proposed_schema":
            report.proposed_schema_detected += 1
        report.quality_gaps.setdefault(scenario.instrumentation_status, []).append(
            scenario.id
        )

    @staticmethod
    def _remediation_backlog(
        quality_gaps: dict[str, list[str]],
    ) -> list[BASRemediationBacklogItem]:
        """품질 갭을 계측 보완 백로그로 변환한다."""
        items = [
            BASRemediationBacklogItem(
                status=status,
                scenario_count=len(scenarios),
                scenarios=sorted(scenarios),
                remediation=_REMEDIATION_BY_STATUS.get(status, "계측 상태를 재분류"),
            )
            for status, scenarios in quality_gaps.items()
        ]
        return sorted(items, key=lambda item: (-item.scenario_count, item.status))
