"""Continuous monitoring — SLO 규칙 기반 상시 방어 지표 위반 감지.

지금까지의 방어 지표(BAS 탐지율·ATT&CK 커버리지·예측 적중·축출 실패·임무 중단·
경보 처리량)를 `slo-rules.yaml` 임계와 대조해 상시 위반을 감지한다. /metrics 는
값을 노출하고, 이 모듈은 "언제 경보인가" 를 정책으로 판정한다(SloBreach 목록).

방어 스택 전체를 하나의 상시 감시 레이어로 묶는다 — 예측·재심·kill chain·COA·
recovery·degradation·BAS 어느 지표가 회귀해도 즉시 위반으로 표면화. LLM 무관,
결정론 — 주기 워커가 평가해 알람 룰/대시보드로 승격한다.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel
import yaml

from core.exceptions import PolicyError
from utils.logging import get_logger

_logger = get_logger("monitoring")
_POLICY = Path(__file__).resolve().parent / "policy" / "slo-rules.yaml"


def collect_snapshot() -> dict[str, float]:
    """현재 방어 지표를 SLO 평가용 스냅샷으로 수집한다.

    런타임 카운터(metrics)와 정책 파일 기반 상시 지표(coverage/BAS)를 하나의
    dict 로 통합한다. 조회 실패한 지표는 스냅샷에서 생략(graceful) — SLOMonitor
    가 없는 지표를 평가 생략하므로 안전하다.

    Returns:
        metric 이름 → 현재값 스냅샷.
    """
    from app.metrics import metrics

    c = metrics()
    snap: dict[str, float] = {
        "alerts_total": float(c.alerts_total),
        "eviction_failed_total": float(c.eviction_failed_total),
        "mission_abort_total": float(c.mission_abort_total),
        "killchain_advanced_total": float(c.killchain_advanced_total),
    }
    pred = c.prediction_stats()
    if pred:
        snap["prediction_hit_ratio"] = pred["hit_ratio"]
    try:
        from core.bas import BASRunner

        snap["bas_detection_ratio"] = BASRunner.from_yaml().run().detection_ratio
    except Exception as exc:  # noqa: BLE001 - 지표 수집 실패는 해당 지표만 생략
        _logger.debug("bas 지표 수집 생략: %s", exc)
    try:
        from tools.coverage import CoverageMatrix

        snap["attack_coverage_ratio"] = CoverageMatrix.from_yaml().report().coverage_pct
    except Exception as exc:  # noqa: BLE001 - 지표 수집 실패는 해당 지표만 생략
        _logger.debug("coverage 지표 수집 생략: %s", exc)
    return snap


class SloRule(BaseModel):
    """SLO 규칙 한 건 — 지표 임계 + 방향 + 경보 메타."""

    metric: str
    operator: str  # "lt"(미만이면 위반) | "gt"(초과면 위반)
    threshold: float
    severity: str = "warning"
    message: str = ""


class SloBreach(BaseModel):
    """SLO 위반 한 건."""

    metric: str
    actual: float
    threshold: float
    severity: str
    message: str


class SLOMonitor:
    """SLO 규칙 평가기 — 지표 스냅샷 → 위반 목록(continuous monitoring).

    Args:
        rules: 평가할 SLO 규칙 목록.
    """

    def __init__(self, rules: list[SloRule]) -> None:
        self._rules = rules

    @property
    def rule_count(self) -> int:
        """로드된 규칙 수."""
        return len(self._rules)

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> SLOMonitor:
        """slo-rules.yaml 을 적재한다.

        Args:
            path: 정책 경로. 생략 시 기본 slo-rules.yaml.

        Returns:
            로드된 SLOMonitor.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        p = Path(path) if path is not None else _POLICY
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"SLO 규칙 적재 실패: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError("SLO 규칙 구조 오류(최상위 dict 아님).")
        rules: list[SloRule] = []
        for item in raw.get("rules", []) or []:
            if isinstance(item, dict):
                rules.append(SloRule.model_validate(item))
        if not rules:
            raise PolicyError("SLO 규칙이 비어있음.")
        return cls(rules)

    def evaluate(self, values: dict[str, float]) -> list[SloBreach]:
        """지표 스냅샷을 규칙과 대조해 위반 목록을 반환한다.

        Args:
            values: metric 이름 → 현재값 스냅샷. 없는 지표는 평가 생략.

        Returns:
            위반 SloBreach 목록(위반 없으면 빈 리스트).
        """
        breaches: list[SloBreach] = []
        for rule in self._rules:
            if rule.metric not in values:
                continue
            actual = values[rule.metric]
            if self._violates(actual, rule):
                breaches.append(
                    SloBreach(
                        metric=rule.metric,
                        actual=actual,
                        threshold=rule.threshold,
                        severity=rule.severity,
                        message=rule.message,
                    )
                )
        return breaches

    @staticmethod
    def _violates(actual: float, rule: SloRule) -> bool:
        """규칙 방향에 따라 위반 여부를 판정한다."""
        if rule.operator == "lt":
            return actual < rule.threshold
        if rule.operator == "gt":
            return actual > rule.threshold
        return False
