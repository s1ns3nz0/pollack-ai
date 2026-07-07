"""공격 시퀀스 예측 — ActorProfile.kill_chain n-gram(spec C1) + 폐루프 대조.

결정론 n=2 마르코프 — (prev, curr) → next 조건부 빈도. support/probability 가드로
잡음 후보 제거. 미달 시 빈 결과 (graceful).

PredictionMatcher: 새 알람을 actor 의 pending 예측과 읽기 전용 대조 —
일치 시 `Alert.prediction_match` 세팅(정책 dynamics 격상 입력). 프로필 변이는
ActorWriteGate 만 한다(포이즈닝 면역).

Spec: docs/superpowers/specs/2026-06-30-attack-sequence-prediction-design.md
"""

from __future__ import annotations

from core.actor_fingerprint import is_empty_fingerprint, resolve_actor_id
from core.actors import ActorReadGate
from core.models import ActorProfile, Alert, AttackPrediction


class SequencePredictor:
    """결정론 n=2 마르코프 시퀀스 예측기.

    Args:
        min_support: 채택 최소 빈도(기본 3).
        min_probability: 채택 최소 조건부 확률(기본 0.5).
        top_k: 반환 상위 K.
    """

    def __init__(
        self,
        min_support: int = 3,
        min_probability: float = 0.5,
        top_k: int = 3,
    ) -> None:
        self._min_support = min_support
        self._min_prob = min_probability
        self._top_k = top_k

    def predict(self, profile: ActorProfile, current: str) -> list[AttackPrediction]:
        """profile.kill_chain n=2 빈도 → 현재 (prev,curr) → next 예측."""
        chain = profile.kill_chain
        if len(chain) < 3 or not current:
            return []
        # n-gram 빈도: { (prev, curr): { next: count } }
        ngram: dict[tuple[str, str], dict[str, int]] = {}
        for i in range(len(chain) - 2):
            prev = chain[i].technique
            curr = chain[i + 1].technique
            nxt = chain[i + 2].technique
            ngram.setdefault((prev, curr), {})
            ngram[(prev, curr)][nxt] = ngram[(prev, curr)].get(nxt, 0) + 1
        prev_tech = chain[-1].technique
        next_counts = ngram.get((prev_tech, current), {})
        if not next_counts:
            return []
        total = sum(next_counts.values())
        out: list[AttackPrediction] = []
        for nxt, count in next_counts.items():
            prob = count / total
            if count >= self._min_support and prob >= self._min_prob:
                out.append(
                    AttackPrediction(
                        next_technique=nxt,
                        probability=round(prob, 3),
                        support_count=count,
                        basis_actor_id=profile.actor_id,
                    )
                )
        return sorted(out, key=lambda p: -p.probability)[: self._top_k]


class PredictionMatcher:
    """pending 예측 ↔ 신규 알람 읽기 전용 대조기(예측 폐루프 절반).

    hit/miss *판정·적립* 은 TP 확정 시 ActorWriteGate 가 한다. 여기는
    미검증 알람에 대한 사전 신호만 세팅 — 저장소를 절대 변이하지 않는다.
    """

    def __init__(self, read_gate: ActorReadGate) -> None:
        self._read_gate = read_gate

    async def enrich(self, alert: Alert) -> Alert:
        """alert technique 이 actor 의 pending 예측과 일치하면 플래그 세팅.

        Args:
            alert: 파이프라인 진입 알람.

        Returns:
            일치 시 `prediction_match=True` 인 복사본, 아니면 원본 그대로.
        """
        actor_id, is_explicit = resolve_actor_id(alert)
        if not is_explicit and is_empty_fingerprint(actor_id):
            return alert
        profile = await self._read_gate.recall(actor_id)
        if profile is None or not profile.pending_predictions:
            return alert
        techs_raw = alert.mitre.get("techniques", [])
        techs = {str(t) for t in techs_raw} if isinstance(techs_raw, list) else set()
        if any(p.technique in techs for p in profile.pending_predictions):
            return alert.model_copy(update={"prediction_match": True})
        return alert
