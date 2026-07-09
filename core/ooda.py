"""OODA / Decision Advantage — 결심 여유 템포(결정론·읽기전용·자문).

전(全)-OODA vs 적-OODA 를 비교하지 않는다(적 결심주기 미관측). 정직한 프록시:
**SOC 브리핑 생성 지연 vs 관측된 적 진행 cadence** — "적의 다음 확정 진행 전에
지휘관 결심 브리핑을 낼 여유(margin)가 있는가". Boyd 본질(적 행동 주기 안에서
결심)의 관측가능 근사. verdict/severity/CAT 을 바꾸지 않는다.

cadence 는 신뢰 actor 프로필(서명·포이즈닝 면역 write gate, 서버시각 ts)의
kill_chain 에서만 — untrusted alert 필드 미사용. 소비자는 ActorReadGate 검증
프로필만 넘긴다(raw store 금지).

Spec: docs/superpowers/specs/2026-07-09-decision-advantage-design.md
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from statistics import median
from typing import Literal

from core.models import ActorKillChainStep, DecisionAdvantage

# O/O/D/A 단계별 기여 산출물(정적 교리 맵) — 브리핑 구조 정렬용.
OODA_SOURCES: dict[str, list[str]] = {
    "observe": ["signals", "telemetry", "mitre"],
    "orient": ["diamond", "actor_profile", "campaign_matches", "causal_summary"],
    "decide": [
        "coa_options",
        "intent_assessment",
        "incident_directive",
        "recovery_plan",
    ],
    "act": ["recommended_action"],
}


def ooda_alignment(present: dict[str, bool]) -> dict[str, list[str]]:
    """산출물 존재 플래그를 O/O/D/A 단계별 라벨로 정렬한다(브리핑 구조).

    Args:
        present: 산출물명→존재여부(예: {"diamond": True, "coa_options": False}).

    Returns:
        O/O/D/A 단계별 존재하는 기여 산출물 라벨 목록.
    """
    return {
        phase: [s for s in srcs if present.get(s, False)]
        for phase, srcs in OODA_SOURCES.items()
    }


def _parse_ts(value: str) -> datetime | None:
    """ISO8601 → tz-aware datetime. 실패/naive 는 None(제외).

    naive(오프셋 없는) ts 는 거부한다 — aware 와 혼합 subtract 가 TypeError 를
    내 report 생성을 깨뜨리기 때문(Codex Medium). 실 kill_chain ts 는 항상 'Z'.
    """
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return dt if dt.tzinfo is not None else None


class DecisionAdvantageAssessor:
    """결심 여유 판정기(결정론·읽기전용·자문)."""

    def assess(
        self,
        soc_latency_ms: float,
        kill_chain: Sequence[ActorKillChainStep],
        ooda: dict[str, list[str]] | None = None,
    ) -> DecisionAdvantage:
        """SOC 지연 vs 적 진행 cadence 로 결심 여유를 판정한다.

        Args:
            soc_latency_ms: 브리핑 생성 지연(detect→brief, report 노드 제외 하한).
            kill_chain: 신뢰 actor 프로필의 시간순 단계(서버시각 ts).
            ooda: O/O/D/A 단계별 기여 산출물 라벨(브리핑 구조). 없으면 빈 맵.

        Returns:
            결심 여유 판정. cadence 측정 불가 시 verdict="unknown"(과장 금지).
        """
        basis: list[str] = [
            "SOC 브리핑 지연(하한) vs 관측 적 진행 cadence — 적-OODA 직접비교 아님"
        ]
        # **원본 인접 step 쌍**을 순회 — 둘 다 파싱되고 양(+)의 델타일 때만 유효.
        # 중간 unparseable step 을 건너뛰어 비인접 쌍으로 잇는 오류 방지(Codex Medium).
        # 0/음수/중복 ts(한 alert 다기법=동일 now)도 제외.
        deltas: list[float] = []
        for a, b in zip(kill_chain, kill_chain[1:], strict=False):
            ta, tb = _parse_ts(a.ts), _parse_ts(b.ts)
            if ta is None or tb is None:
                continue
            d = (tb - ta).total_seconds() * 1000.0
            if d > 0.0:
                deltas.append(d)
        cadence: float | None
        verdict: Literal["margin", "contested", "unknown"]
        if not deltas:
            cadence = None
            verdict = "unknown"
            basis.append("적 진행 cadence 측정 불가(연속 step 양의 델타 없음)")
        else:
            cadence = float(median(deltas))
            if soc_latency_ms < cadence:
                verdict = "margin"
                basis.append(f"브리핑 {soc_latency_ms:.0f}ms < cadence {cadence:.0f}ms")
            else:
                verdict = "contested"
                basis.append(f"브리핑 {soc_latency_ms:.0f}ms ≥ cadence {cadence:.0f}ms")
        return DecisionAdvantage(
            soc_latency_ms=round(soc_latency_ms, 2),
            soc_latency_partial=True,
            adversary_cadence_ms=None if cadence is None else round(cadence, 2),
            advance_count=len(kill_chain),
            verdict=verdict,
            ooda=ooda or {},
            basis=basis,
        )
