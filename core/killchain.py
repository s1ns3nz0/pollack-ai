"""Kill chain 진행도 산정 — actor 누적 도달 단계 → 후반단계 격상(읽기 전용).

공격자의 관측 TTP 를 coverage.yaml 의 tactic order(도메인 특화 kill chain 15단계)
에 매핑해 **이 공격자가 지금 어디까지 왔나** 를 잰다. actor 누적 이력 + 현 alert 의
tactic 을 합쳐 최고 order 를 구하고, 임계(후반 단계, 기본 order≥11=C2 확립 이후)
이상이면 `Alert.kill_chain_advanced` 를 세워 정책 dynamics 격상 입력으로 넘긴다.

"이 알람은 고립 이벤트가 아니라 이미 통제·영향 단계에 이른 캠페인의 일부다".
PredictionMatcher 와 동형 — 읽기 전용(프로필 변이 없음), 격상 판정권은 정책 엔진.
"""

from __future__ import annotations

from core.actor_fingerprint import is_empty_fingerprint, resolve_actor_id
from core.actors import ActorReadGate
from core.models import Alert
from tools.coverage import CoverageMatrix

# 후반 단계 기본 임계(coverage.yaml order): 11=CommandAndControl 이후.
# C2 확립 = 공격자 지속 통제 → 임무 위협 실질화. policy 로 튜닝 가능.
_DEFAULT_ADVANCED_ORDER = 11


def _alert_tactics(alert: Alert) -> list[str]:
    """alert.mitre 에서 tactic 목록을 안전 추출한다."""
    raw = alert.mitre.get("tactics", [])
    return [str(t) for t in raw] if isinstance(raw, list) else []


class KillChainProgressor:
    """actor 누적 kill-chain 진행도 → 후반단계 격상 플래그 enrich(읽기 전용).

    Args:
        read_gate: actor 프로필 회상 게이트(서명 검증 통과분만).
        matrix: tactic→order 매핑 커버리지 매트릭스.
        advanced_order: 후반 단계 판정 임계(기본 11=C2 이후).
    """

    def __init__(
        self,
        read_gate: ActorReadGate,
        matrix: CoverageMatrix | None = None,
        advanced_order: int = _DEFAULT_ADVANCED_ORDER,
    ) -> None:
        self._read_gate = read_gate
        self._matrix = matrix or CoverageMatrix.from_yaml()
        self._advanced_order = advanced_order

    async def enrich(self, alert: Alert) -> Alert:
        """actor 누적 + 현 alert tactic 최고 order 가 임계 이상이면 플래그 세팅.

        Args:
            alert: 파이프라인 진입 알람.

        Returns:
            후반 단계 도달 시 `kill_chain_advanced=True` 복사본, 아니면 원본.
        """
        tactics = list(_alert_tactics(alert))
        actor_id, is_explicit = resolve_actor_id(alert)
        if is_explicit or not is_empty_fingerprint(actor_id):
            profile = await self._read_gate.recall(actor_id)
            if profile is not None:
                tactics.extend(s.tactic for s in profile.ttp_stats)
        max_order = self._matrix.max_tactic_order(tactics)
        if max_order >= self._advanced_order:
            return alert.model_copy(update={"kill_chain_advanced": True})
        return alert
