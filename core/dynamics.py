"""경보 dynamics 신호 추적기.

`SeverityEngine` 이 소비하는 런타임 신호를 관측된 경보 이력에서 채운다.
탐지 파이프라인이 정적 산정 외에 동적 조정을 실제로 발동하도록 하는 연결고리다.

- `dwelling_min`      : 동일 위협(자산·시나리오)의 최초 관측 이후 경과 분(체류시간).
- `lateral_correlation`: 상위자산(GCS/C2 등) 침해가 활성인 동안 의존 기체 경보를 상관.

`no_effect_sustained`(무영향 지속 → 하향)는 '효과 관측'이 필요해 시간만으로 자동
도출하지 않는다(명시 입력 유지). 잘못된 자동 하향으로 정탐을 묻지 않기 위함.

이력은 **비활성(last_seen) 기준 TTL** + **cardinality 상한**으로 bounded(장기 hotpath
메모리 고갈·위조 asset_id 키 폭증 방지). 활성 인시던트는 first_seen 을 보존해 dwell 이
리셋되지 않는다(escalate-only). upstream 판정은 substring(레거시) 또는 레지스트리
(`upstream_assets`, hotpath 배선)로 — 임의 문자열 사칭 차단.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from core.models import Alert

# 다수 기체를 통제하는 상위자산 식별 토큰(asset_id/tier 에 포함되면 상위자산으로 본다).
# 레거시(substring) 판정용 — 레지스트리(upstream_assets) 미주입 시 fallback.
_UPSTREAM_MARKERS = ("GCS", "C2")


def _default_clock() -> datetime:
    """기본 클록(UTC 수신시각)."""
    return datetime.now(UTC)


class DynamicsTracker:
    """경보 스트림에서 dynamics 신호(체류시간·횡적상관)를 산정한다.

    인스턴스가 이력을 보유하므로 경보 시퀀스를 순차로 `enrich` 하면 누적된다.

    Args:
        upstream_markers: 상위자산 식별 토큰(레거시 substring 판정, 대소문자 무시).
        upstream_active_min: 상위자산 침해를 '활성'으로 보는 시간창(분).
        upstream_assets: 레지스트리 upstream 집합(등록 자산만 upstream — substring
            대체). None 이면 레거시 substring 판정. hotpath 는 asset-tiers 에서 도출한
            'dependents 보유' 자산을 주입한다.
        retention_min: 비활성 이력 eviction 창(분). 이 시간 무관측 항목만 드롭.
        max_entries: 이력 dict cardinality 상한(위조 키 폭증 방지).
        clock: 현재시각 콜백(테스트 주입). 미지정 시 UTC now.
    """

    def __init__(
        self,
        upstream_markers: tuple[str, ...] = _UPSTREAM_MARKERS,
        upstream_active_min: int = 60,
        *,
        upstream_assets: frozenset[str] | None = None,
        retention_min: int = 180,
        max_entries: int = 4096,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._upstream_markers = tuple(m.upper() for m in upstream_markers)
        self._upstream_assets = upstream_assets
        self._upstream_window = timedelta(minutes=upstream_active_min)
        self._retention = timedelta(minutes=retention_min)
        self._max_entries = max_entries
        self._clock = clock or _default_clock
        self._first_seen: dict[tuple[str, str], datetime] = {}
        self._last_seen: dict[tuple[str, str], datetime] = {}
        self._upstream_seen: dict[str, datetime] = {}

    def _is_upstream(self, alert: Alert) -> bool:
        """상위자산 여부 — 레지스트리 주입 시 멤버십, 아니면 레거시 substring."""
        if self._upstream_assets is not None:
            return alert.asset_id in self._upstream_assets
        token = f"{alert.asset_id} {alert.asset_tier}".upper()
        return any(m in token for m in self._upstream_markers)

    def _evict(self, now: datetime) -> None:
        """비활성(last_seen 무관측 retention 초과) 이력을 드롭한다.

        first_seen 나이가 아니라 **무활동** 기준 — 활성 인시던트의 dwell 을 보존해
        다음 경보가 dwell=0 으로 리셋돼 격상이 사라지는 버그를 막는다.
        """
        stale = [
            k for k, seen in self._last_seen.items() if now - seen > self._retention
        ]
        for k in stale:
            self._first_seen.pop(k, None)
            self._last_seen.pop(k, None)
        stale_up = [
            a
            for a, seen in self._upstream_seen.items()
            if now - seen > self._upstream_window
        ]
        for a in stale_up:
            self._upstream_seen.pop(a, None)

    def _enforce_cap(self) -> None:
        """이력 개수가 상한을 넘으면 가장 오래된 항목부터 축출한다.

        `_first_seen`/`_last_seen` 뿐 아니라 `_upstream_seen` 도 상한을 건다 — 레거시
        substring 모드에서 위조 'GCS-*'/'C2-*' 스트림이 active 창 만료 전까지 upstream
        dict 를 부풀리는 벡터 차단(Codex diff M).
        """
        while len(self._first_seen) > self._max_entries:
            oldest = min(self._last_seen, key=lambda k: self._last_seen[k])
            self._first_seen.pop(oldest, None)
            self._last_seen.pop(oldest, None)
        while len(self._upstream_seen) > self._max_entries:
            oldest_up = min(self._upstream_seen, key=lambda a: self._upstream_seen[a])
            self._upstream_seen.pop(oldest_up, None)

    def enrich(self, alert: Alert, now: datetime | None = None) -> Alert:
        """경보를 이력에 반영하고 dynamics 신호를 채운 복사본을 반환한다.

        Args:
            alert: 입력 경보.
            now: 관측 시각(테스트 주입 가능). 미지정 시 내부 clock(라이브는 수신시각).

        Returns:
            `dwelling_min`·`lateral_correlation` 이 채워진 경보 복사본(기존 값과
            병합 — 더 큰 dwell / 참인 lateral 을 유지, escalate-only).
        """
        if now is None:
            now = self._clock()
        self._evict(now)

        key = (alert.asset_id, alert.scenario_id)
        first = self._first_seen.setdefault(key, now)
        self._last_seen[key] = now
        dwell = max(0, int((now - first).total_seconds() // 60))

        is_upstream = self._is_upstream(alert)
        if is_upstream:
            self._upstream_seen[alert.asset_id] = now
        upstream_active = any(
            now - seen <= self._upstream_window for seen in self._upstream_seen.values()
        )
        lateral = (not is_upstream) and upstream_active

        self._enforce_cap()
        return alert.model_copy(
            update={
                "dwelling_min": max(dwell, alert.dwelling_min),
                "lateral_correlation": alert.lateral_correlation or lateral,
            }
        )

    def reset(self) -> None:
        """이력 초기화(사건 세트 종료 후 재사용)."""
        self._first_seen.clear()
        self._last_seen.clear()
        self._upstream_seen.clear()
