"""다중경보 상관·집약 (S9 군집 포화 / SOC 과부하 대응).

개별 경보 N건을 슬라이딩 윈도우에 모아 **경보 폭주(alert storm)** · **다축 동시침해
(multi-axis)** · **의미적 상관 클러스터(correlated_cluster)** 를 탐지해 하나의 집약
인시던트로 묶는다. 운용자·탐지 과부하 완화(집약) + 상관 시 등급 상향.

의미적 상관(correlated_cluster): 볼륨/자산개수만이 아니라 **공유 IOC**(해시/IP)·**자산
의존 엣지**(depends_on)로 연결된 연결요소를 실제 상관 인시던트로 묶는다. depends_on 은
정책그래프(asset-tiers)라 위조 저항, 공유 IOC 는 shape 산열 + cluster_min 으로 제한.

`SOC_Alert_Stream_CL`(S1~S11 개별 룰 출력의 통합 스트림)의 런타임 구현부에 해당하며,
집약 결과를 `to_aggregate_alert()` 로 S9 경보(`UAV-SWARM-SATURATION-009`)로 변환해
기존 6-에이전트 파이프라인에 그대로 투입할 수 있다. (S9 id 는 correlation.py 선재 상수 —
bas-scenarios 카탈로그와 미정렬이나 합성 내부 산출물이라 계약 미저촉.)
"""

from __future__ import annotations

from collections import deque
from datetime import datetime

from pydantic import BaseModel, Field

from core.egress import IocEgressFilter
from core.models import Alert, Severity, Verdict
from core.terrain import KeyTerrainMap

_S9_SCENARIO = "UAV-SWARM-SATURATION-009"
_IOC_SHAPE_CAP = 64  # alert당 IOC shape 산열 상한(엣지 구성용, 과다 IOC 방어)
_PATTERN_ORDER = ("correlated_cluster", "multi_axis", "alert_storm")
_S9_PLAYBOOK: dict[str, object] = {
    "id": "PB-SWARM-AGGREGATE-09",
    "actions": [
        "경보 집약 — 다축/의미상관 클러스터를 단일 인시던트로 승급",
        "상위자산 lateral 에스컬레이션",
        "탐지 게이트 완화(과부하 시 우선순위 큐 운영)",
    ],
    "failover": "운용자 과부하 시 자동대응 우선순위 큐로 분산",
}


class CorrelatedIncident(BaseModel):
    """다수 경보를 집약한 상관 인시던트."""

    id: str
    pattern: str  # "alert_storm" | "multi_axis" | "correlated_cluster"
    count: int
    distinct_assets: int
    distinct_scenarios: int
    window_sec: float
    member_alert_ids: list[str] = Field(default_factory=list)
    member_scenarios: list[str] = Field(default_factory=list)
    edge_kinds: list[str] = Field(default_factory=list)  # ["shared_ioc","dependency"]


class AlertCorrelator:
    """경보 스트림을 슬라이딩 윈도우로 상관·집약한다.

    Args:
        window_sec: 상관 윈도우(초). 이 안의 경보를 한 묶음으로 본다.
        storm_count: 윈도우 내 경보 수가 이 값 이상이면 경보 폭주.
        multi_axis_assets: 윈도우 내 서로 다른 자산 수가 이 값 이상이면 다축 동시침해.
        terrain: 자산 의존 그래프(depends_on 엣지용). None 이면 공유-IOC 엣지만 사용.
        cluster_min: 의미 연결요소가 이 크기 이상이면 correlated_cluster 후보.
        max_alerts: 윈도우 하드 상한(위조 고속 스트림 DoS 방지 — compute/메모리 bound).
    """

    def __init__(
        self,
        window_sec: float = 300.0,
        storm_count: int = 5,
        multi_axis_assets: int = 3,
        *,
        terrain: KeyTerrainMap | None = None,
        cluster_min: int = 3,
        max_alerts: int = 512,
    ) -> None:
        self._window_sec = window_sec
        self._storm_count = storm_count
        self._multi_axis_assets = multi_axis_assets
        self._terrain = terrain
        self._cluster_min = cluster_min
        self._max_alerts = max_alerts
        self._ioc_filter = IocEgressFilter()
        self._window: deque[tuple[datetime, Alert]] = deque()
        # 패턴별 arm/disarm — 발화된 상위 패턴이 하위 패턴을 굶기지 않게.
        self._fired: dict[str, bool] = {}

    def observe(self, alert: Alert, now: datetime) -> CorrelatedIncident | None:
        """경보 한 건을 윈도우에 넣고, 상관 패턴이 새로 확정되면 인시던트 반환.

        Args:
            alert: 입력 경보.
            now: 관측 시각.

        Returns:
            우선순위(correlated_cluster > multi_axis > alert_storm) 상 **탐지됐고 아직
            미발화**인 최고 패턴 1건. 없으면 None. 각 패턴은 조건이 풀리면 재무장한다.
        """
        self._window.append((now, alert))
        # age eviction
        while (
            self._window
            and (now - self._window[0][0]).total_seconds() > self._window_sec
        ):
            self._window.popleft()
        # 하드 상한 eviction(DoS — Codex High)
        while len(self._window) > self._max_alerts:
            self._window.popleft()

        members = [a for _, a in self._window]
        assets = {a.asset_id for a in members}
        scenarios = {a.scenario_id for a in members}
        cluster = self._detect_cluster(members)
        detections = {
            "correlated_cluster": cluster is not None,
            "multi_axis": len(assets) >= self._multi_axis_assets,
            "alert_storm": len(members) >= self._storm_count,
        }

        for pattern in _PATTERN_ORDER:
            if not detections[pattern]:
                self._fired[pattern] = False  # 조건 해제 → 재무장
                continue
            if self._fired.get(pattern):
                continue  # 이미 발화 → 하위 패턴으로
            self._fired[pattern] = True
            return self._build_incident(pattern, members, assets, scenarios, cluster)
        return None

    def _dep_linked(self, a: str, b: str) -> bool:
        """두 자산이 의존 엣지로 연결(한쪽이 다른쪽을 depends_on)인지 — 등록 자산만."""
        if self._terrain is None or not a or not b or a == b:
            return False
        return a in self._terrain.dependents(b) or b in self._terrain.dependents(a)

    def _detect_cluster(
        self, members: list[Alert]
    ) -> tuple[list[Alert], list[str]] | None:
        """공유 IOC·의존 엣지로 union-find → 최대 적격 연결요소와 엣지 종류 반환.

        적격 요소: 크기 ≥ cluster_min **이고** 서로 다른 자산 ≥ 2(단일자산 반복 배제).
        공유-IOC 는 역색인(O(N·k)), 의존은 등록 자산 페어(O(A²), A 소수)로 구성.
        """
        n = len(members)
        if n < self._cluster_min:
            return None

        parent = list(range(n))

        def find(x: int) -> int:
            root = x
            while parent[root] != root:
                root = parent[root]
            while parent[x] != root:
                parent[x], x = root, parent[x]
            return root

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        edges: list[tuple[int, int, str]] = []
        # 공유-IOC 엣지: IOC 역색인(shape 산열된 공개 지표만)
        ioc_index: dict[str, list[int]] = {}
        for i, a in enumerate(members):
            clean, _ = self._ioc_filter.sanitize(list(a.iocs), cap=_IOC_SHAPE_CAP)
            for ioc in set(clean):
                ioc_index.setdefault(ioc, []).append(i)
        for idxs in ioc_index.values():
            for j in idxs[1:]:
                edges.append((idxs[0], j, "shared_ioc"))

        # 의존 엣지: 등록 자산 페어만(위조 asset_id 는 엣지 0)
        if self._terrain is not None:
            by_asset: dict[str, list[int]] = {}
            for i, a in enumerate(members):
                if a.asset_id:
                    by_asset.setdefault(a.asset_id, []).append(i)
            asset_ids = list(by_asset)
            dep_assets: set[str] = set()
            for x in range(len(asset_ids)):
                for y in range(x + 1, len(asset_ids)):
                    ax, ay = asset_ids[x], asset_ids[y]
                    if self._dep_linked(ax, ay):
                        edges.append((by_asset[ax][0], by_asset[ay][0], "dependency"))
                        dep_assets.add(ax)
                        dep_assets.add(ay)
            # 의존 엣지에 참여한 자산만 자기 그룹 내 union(전 멤버 클러스터 편입)
            for asset in dep_assets:
                idxs = by_asset[asset]
                for j in idxs[1:]:
                    edges.append((idxs[0], j, "dependency"))

        for i, j, _kind in edges:
            union(i, j)

        comps: dict[int, list[int]] = {}
        for i in range(n):
            comps.setdefault(find(i), []).append(i)

        best: list[int] | None = None
        for idxs in comps.values():
            comp_assets = {members[i].asset_id for i in idxs}
            if len(idxs) >= self._cluster_min and len(comp_assets) >= 2:
                if best is None or len(idxs) > len(best):
                    best = idxs
        if best is None:
            return None

        best_set = set(best)
        kinds = sorted({k for i, j, k in edges if i in best_set and j in best_set})
        return [members[i] for i in best], kinds

    def _build_incident(
        self,
        pattern: str,
        members: list[Alert],
        assets: set[str],
        scenarios: set[str],
        cluster: tuple[list[Alert], list[str]] | None,
    ) -> CorrelatedIncident:
        """확정된 패턴으로 CorrelatedIncident 를 구성한다."""
        if pattern == "correlated_cluster" and cluster is not None:
            comp, kinds = cluster
            comp_assets = {a.asset_id for a in comp}
            comp_scen = {a.scenario_id for a in comp}
            return CorrelatedIncident(
                id=f"CORR-{_S9_SCENARIO}-cluster-{len(comp)}",
                pattern="correlated_cluster",
                count=len(comp),
                distinct_assets=len(comp_assets),
                distinct_scenarios=len(comp_scen),
                window_sec=self._window_sec,
                member_alert_ids=[a.id for a in comp],
                member_scenarios=sorted(comp_scen),
                edge_kinds=kinds,
            )
        return CorrelatedIncident(
            id=f"CORR-{_S9_SCENARIO}-{len(members)}",
            pattern=pattern,
            count=len(members),
            distinct_assets=len(assets),
            distinct_scenarios=len(scenarios),
            window_sec=self._window_sec,
            member_alert_ids=[a.id for a in members],
            member_scenarios=sorted(scenarios),
        )

    def to_aggregate_alert(self, incident: CorrelatedIncident) -> Alert:
        """집약 인시던트를 S9 경보로 변환(파이프라인 투입용).

        조율/의미상관 침해는 baseline h + lateral_correlation 으로 등급 상향을 유도한다.

        Args:
            incident: 집약 인시던트.

        Returns:
            S9(`UAV-SWARM-SATURATION-009`) 경보.
        """
        if incident.pattern == "correlated_cluster":
            kinds = "/".join(incident.edge_kinds) or "semantic"
            title = "의미 상관 클러스터 — 공유지표/의존전파 상관(집약)"
            signals = [
                f"의미상관({kinds}): {incident.distinct_assets}자산 "
                f"{incident.count}경보 연결",
                f"시나리오 {', '.join(incident.member_scenarios)}",
            ]
        else:
            title = "군집 포화 — 다축 동시침해 및 SOC 과부하(집약)"
            signals = [
                f"경보 {incident.count}건 {incident.window_sec:.0f}초 내 집약",
                f"다축 {incident.distinct_assets}자산 동시침해",
                f"시나리오 {', '.join(incident.member_scenarios)}",
            ]
        return Alert(
            id=incident.id,
            scenario_id=_S9_SCENARIO,
            title=title,
            asset_id="AI_SOC",
            asset_tier="T0-AISOC",
            mission_phase="on-station",
            severity_baseline=Severity.HIGH,
            signals=signals,
            mitre={"attack_ics": ["T0814", "T0855"]},
            expected_detection={"sigma_rule": "swarm_saturation_alertstorm.yml"},
            defense_playbook=_S9_PLAYBOOK,
            ground_truth=Verdict.TRUE_POSITIVE,
            lateral_correlation=incident.pattern
            in ("multi_axis", "correlated_cluster"),
        )

    def reset(self) -> None:
        """윈도우·발화 상태 초기화."""
        self._window.clear()
        self._fired.clear()
