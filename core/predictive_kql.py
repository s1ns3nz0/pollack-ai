"""예측 gap → AutoKql 연결 — 미커버 예측 TTP 를 KQL draft PR 로(선제 방어).

예측 폐루프(SequencePredictor)가 내놓은 다음 공격 TTP 중 **아직 탐지룰이 없는
것(gap)** 을 골라 AutoKqlRuleAgent 에 넘긴다. "공격자가 다음에 T1573 을 쓸 텐데
우리는 그 탐지룰이 없다 → 지금 KQL 초안을 만들어 두자". 자동 머지 없음 — 항상
운영자 검토(AutoKqlRuleAgent 의 RulePublisher 는 proposed PR 만).

핫패스 SLO 보존: LLM 을 부르므로 핫패스가 아니라 주기 워커(app.learning)에서
호출하는 것을 전제로 한다. staged/accelerate(이미 룰 있음/계획됨)는 대상 아님 —
gap 만 신규 KQL 이 필요하다.
"""

from __future__ import annotations

from agents.auto_kql_rule_agent import AutoKqlRuleAgent
from core.models import AttackPrediction, WorkerReport
from core.staging import DefenseStager


def gap_techniques(
    predictions: list[AttackPrediction], stager: DefenseStager
) -> list[str]:
    """예측 중 coverage gap(미커버) technique 목록을 순서 유지로 추출한다.

    Args:
        predictions: SequencePredictor 가 발행한 다음 TTP 후보.
        stager: coverage 매트릭스 조회 스테이저.

    Returns:
        status 가 "gap" 인 예측 technique 목록(중복 제거, 발견 순서).
    """
    out: list[str] = []
    seen: set[str] = set()
    for staged in stager.stage(predictions):
        if staged.status != "gap" or staged.technique in seen:
            continue
        seen.add(staged.technique)
        out.append(staged.technique)
    return out


async def run_kql_for_predictions(
    predictions: list[AttackPrediction],
    stager: DefenseStager,
    agent: AutoKqlRuleAgent,
) -> WorkerReport:
    """예측 gap technique 에 대해 KQL draft PR 생성을 위임한다.

    Args:
        predictions: 예측 TTP 후보.
        stager: coverage gap 판정 스테이저.
        agent: KQL draft 생성 에이전트(LLM 필요).

    Returns:
        AutoKqlRuleAgent 처리 결과. gap 없으면 빈 사이클 리포트.
    """
    gaps = gap_techniques(predictions, stager)
    return await agent.run_for(gaps)
