"""Diamond Model of Intrusion Analysis — 4 정점 정형화 + 정점 피벗(결정론).

actor_fingerprint([[attacker-profile-store]])를 침입분석 다이아몬드(교리)로 정형화한다.
한 사건을 Adversary·Capability·Infrastructure·Victim 4 정점으로 사상하고, 여러 사건
사이의 **정점 피벗**(같은 인프라/능력/피해자를 쓰는 서로 다른 공격자 상관)을 산출한다.
campaign 상관(시나리오 시퀀스)·predictor(technique n-gram)와 상보 — 이건 *정점 공유* 축.

전 과정 결정론. LLM 무관. build 는 신뢰 프로필(선택)로 정점을 보강하되, alert 자체
값만으로도 사상 가능.

Spec: docs/superpowers/specs/2026-07-08-diamond-model-design.md
"""

from __future__ import annotations

from core.models import ActorProfile, Alert, DiamondEvent, DiamondPivot

# 피벗 대상 정점 — adversary 는 정의상 사건별 고유라 상관축에서 제외.
_PIVOT_VERTICES = ("capability", "infrastructure", "victim")
# 상관 확정 최소 공유 사건 수(1개는 상관 아님).
_MIN_SHARED = 2


def _alert_techniques(alert: Alert) -> list[str]:
    # mitre 가 post-validation 으로 None 이 돼도 방어(Codex 견고성 caveat).
    raw = (alert.mitre or {}).get("techniques", [])
    return [str(t) for t in raw] if isinstance(raw, list) else []


class DiamondAnalyzer:
    """alert(+프로필) → DiamondEvent 사상 + 사건 집합 정점 피벗(결정론)."""

    def build(
        self, alert: Alert, profile: ActorProfile | None = None, adversary: str = ""
    ) -> DiamondEvent:
        """한 alert 을 4 정점 DiamondEvent 로 사상한다.

        Args:
            alert: 대상 알람.
            profile: 신뢰 actor 프로필(선택) — 누적 TTP/IOC 로 정점 보강.
            adversary: 공격자 식별. 빈값이면 alert.actor_id 또는 profile.actor_id.

        Returns:
            4 정점이 채워진 DiamondEvent.
        """
        adv = (
            adversary or (alert.actor_id or "") or (profile.actor_id if profile else "")
        )
        caps = set(_alert_techniques(alert))
        infra = {str(i) for i in (alert.iocs or []) if i}
        if profile is not None:
            caps.update(s.technique for s in profile.ttp_stats if s.technique)
            infra.update(p.value for p in profile.ioc_patterns if p.value)
        return DiamondEvent(
            adversary=adv.strip(),
            capabilities=sorted(caps),
            infrastructure=sorted(infra),
            victim=alert.asset_id,
            victim_tier=alert.asset_tier,
            mission_phase=alert.mission_phase,
        )

    def pivot(self, events: list[DiamondEvent]) -> list[DiamondPivot]:
        """사건 집합에서 정점 공유 상관(피벗)을 산출한다.

        capability/infrastructure/victim 정점값을 **서로 다른 공격자 2+** 가 공유하면
        상관으로 본다(동일 공격자 반복은 상관 아님). adversary 정점은 고유라 제외.

        Args:
            events: DiamondEvent 목록.

        Returns:
            공유 공격자 수 내림차순 DiamondPivot 목록. 상관 없으면 빈 리스트.
        """
        # (vertex, value) → 공격자 집합
        index: dict[tuple[str, str], set[str]] = {}
        for ev in events:
            if not ev.adversary:
                continue
            for vertex, values in (
                ("capability", ev.capabilities),
                ("infrastructure", ev.infrastructure),
                ("victim", [ev.victim] if ev.victim else []),
            ):
                for value in values:
                    index.setdefault((vertex, value), set()).add(ev.adversary)

        pivots: list[DiamondPivot] = []
        for (vertex, value), advs in index.items():
            if len(advs) >= _MIN_SHARED and vertex in _PIVOT_VERTICES:
                pivots.append(
                    DiamondPivot(
                        vertex=vertex,
                        value=value,
                        adversaries=sorted(advs),
                        count=len(advs),
                    )
                )
        pivots.sort(key=lambda p: (-p.count, p.vertex, p.value))
        return pivots
