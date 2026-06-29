"""[3] Validation Agent — 오탐/정탐 판단 + 라우팅.

판정기(Judge)는 주입 가능. 기본 Judge 는 신호-탐지로직 정합성 + ground_truth 로
결정론적으로 동작(MVP). 실연동 시 LLM-as-Judge 루브릭으로 교체.
"""

from __future__ import annotations

from collections.abc import Callable

from agents.base import BaseSOCAgent
from core.models import SOCState, Verdict
from core.settings import Settings

Judge = Callable[[SOCState], Verdict]


def default_judge(state: SOCState) -> Verdict:
    """신호+룰 매핑 시 정탐 후보, 최종은 ground_truth 로 확정(MVP).

    라우팅/파이프라인 검증용 — ground_truth 를 따르므로 FPR/FNR 측정엔
    `signal_judge`(근거 기반)를 쓴다.
    """
    alert = state["alert"]
    has_signal = bool(alert.signals)
    has_rule = bool(alert.expected_detection.get("sigma_rule"))
    candidate = (
        Verdict.TRUE_POSITIVE if (has_signal and has_rule) else Verdict.FALSE_POSITIVE
    )
    return alert.ground_truth or candidate


def signal_judge(state: SOCState) -> Verdict:
    """근거 기반 정탐/오탐 판정(ground_truth 비참조 — FPR/FNR 측정용 실판정).

    탐지 신호 + 매칭 탐지룰 + 조사 근거(신뢰 유사사례 또는 신뢰도≥0.5)가 동시
    충족될 때만 정탐. 어느 하나라도 빠지면(예: 매칭 룰 없는 양성 노이즈, RAG 근거
    부재) 오탐으로 본다. 라벨을 참조하지 않으므로 라벨 대비 FPR/FNR 이 의미를 갖는다.

    Args:
        state: investigation 까지 완료된 상태.

    Returns:
        근거 기반 판정 Verdict.
    """
    alert = state["alert"]
    inv = state.get("investigation")
    has_signal = bool(alert.signals)
    has_rule = bool(
        alert.expected_detection.get("sigma_rule")
        or alert.expected_detection.get("sentinel_rule")
    )
    corroborated = inv is not None and (
        bool(inv.similar_cases)
        or inv.confidence >= 0.5
        or inv.experience_corroboration > 0  # exp/ 과거 정탐 자문(하한 불변)
        # spec #1: 외부 GNSS/Airspace 컨텍스트도 corroborated 기여.
        or any(f.level >= 2 for f in inv.gnss_jam_findings)
        or any(f.hostile and f.distance_km <= 10.0 for f in inv.airspace_findings)
    )
    verdict = (
        Verdict.TRUE_POSITIVE
        if (has_signal and has_rule and corroborated)
        else Verdict.FALSE_POSITIVE
    )
    # 맥락 FP 억제(위험 방향): 신뢰 출처·동일 신호패턴 과거 오탐이 있을 때만 TP→FP.
    # Investigation 이 ReadGate(신뢰 출처 한정) + 부분집합 매칭으로 좁게 산정하므로
    # 진짜 공격(다른 신호)이나 미신뢰 출처로는 억제되지 않는다.
    if (
        verdict == Verdict.TRUE_POSITIVE
        and inv is not None
        and inv.suppression_corroboration > 0
    ):
        return Verdict.FALSE_POSITIVE
    return verdict


def route_after_validation(state: SOCState) -> str:
    """Validation 이후 분기 키를 반환한다(정탐→response, 오탐→rule_update)."""
    return (
        "false_positive"
        if state["verdict"] == Verdict.FALSE_POSITIVE
        else "true_positive"
    )


class ValidationAgent(BaseSOCAgent):
    """오탐/정탐 판정 Agent."""

    def __init__(self, settings: Settings, judge: Judge = default_judge) -> None:
        super().__init__(settings)
        self._judge = judge

    async def run(self, state: SOCState) -> SOCState:
        """판정 실행.

        Args:
            state: investigation 까지 완료된 상태.

        Returns:
            verdict 가 담긴 부분 상태.
        """
        verdict = self._judge(state)
        self._logger.info("validation: alert=%s verdict=%s", state["alert"].id, verdict)
        return {"verdict": verdict, "trace": ["validation"]}
