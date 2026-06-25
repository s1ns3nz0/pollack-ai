"""경보 dynamics 신호 추적기.

`SeverityEngine` 이 소비하는 런타임 신호를 관측된 경보 이력에서 채운다.
탐지 파이프라인이 정적 산정 외에 동적 조정을 실제로 발동하도록 하는 연결고리다.

- `dwelling_min`      : 동일 위협(자산·시나리오)의 최초 관측 이후 경과 분(체류시간).
- `lateral_correlation`: 상위자산(GCS/C2 등) 침해가 활성인 동안 의존 기체 경보를 상관.

`no_effect_sustained`(무영향 지속 → 하향)는 '효과 관측'이 필요해 시간만으로 자동
도출하지 않는다(명시 입력 유지). 잘못된 자동 하향으로 정탐을 묻지 않기 위함.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from core.models import Alert

# 다수 기체를 통제하는 상위자산 식별 토큰(asset_id/tier 에 포함되면 상위자산으로 본다).
_UPSTREAM_MARKERS = ("GCS", "C2")


class DynamicsTracker:
    """경보 스트림에서 dynamics 신호(체류시간·횡적상관)를 산정한다.

    인스턴스가 이력을 보유하므로 경보 시퀀스를 순차로 `enrich` 하면 누적된다.

    Args:
        upstream_markers: 상위자산 식별 토큰(대소문자 무시).
        upstream_active_min: 상위자산 침해를 '활성'으로 보는 시간창(분).
    """

    def __init__(
        self,
        upstream_markers: tuple[str, ...] = _UPSTREAM_MARKERS,
        upstream_active_min: int = 60,
    ) -> None:
        self._upstream_markers = tuple(m.upper() for m in upstream_markers)
        self._upstream_window = timedelta(minutes=upstream_active_min)
        self._first_seen: dict[tuple[str, str], datetime] = {}
        self._upstream_seen: dict[str, datetime] = {}

    def _is_upstream(self, alert: Alert) -> bool:
        token = f"{alert.asset_id} {alert.asset_tier}".upper()
        return any(m in token for m in self._upstream_markers)

    def enrich(self, alert: Alert, now: datetime) -> Alert:
        """경보를 이력에 반영하고 dynamics 신호를 채운 복사본을 반환한다.

        Args:
            alert: 입력 경보.
            now: 관측 시각(테스트 주입 가능; 라이브는 텔레메트리 타임스탬프).

        Returns:
            `dwelling_min`·`lateral_correlation` 이 채워진 경보 복사본(기존 값과
            병합 — 더 큰 dwell / 참인 lateral 을 유지).
        """
        key = (alert.asset_id, alert.scenario_id)
        first = self._first_seen.setdefault(key, now)
        dwell = max(0, int((now - first).total_seconds() // 60))

        is_upstream = self._is_upstream(alert)
        if is_upstream:
            self._upstream_seen[alert.asset_id] = now
        upstream_active = any(
            now - seen <= self._upstream_window for seen in self._upstream_seen.values()
        )
        lateral = (not is_upstream) and upstream_active

        return alert.model_copy(
            update={
                "dwelling_min": max(dwell, alert.dwelling_min),
                "lateral_correlation": alert.lateral_correlation or lateral,
            }
        )

    def reset(self) -> None:
        """이력 초기화(사건 세트 종료 후 재사용)."""
        self._first_seen.clear()
        self._upstream_seen.clear()
