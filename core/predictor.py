"""공격 시퀀스 예측 — ActorProfile.kill_chain n-gram(spec C1).

결정론 n=2 마르코프 — (prev, curr) → next 조건부 빈도. support/probability 가드로
잡음 후보 제거. 미달 시 빈 결과 (graceful).

Spec: docs/superpowers/specs/2026-06-30-attack-sequence-prediction-design.md
"""

from __future__ import annotations

from core.models import ActorProfile, AttackPrediction


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
