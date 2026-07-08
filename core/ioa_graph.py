"""IoA(Indicators of Attack) 그래프 빌더 — 시각화용 그래프 JSON 생성(spec E-4).

IoC = 사후 침해 지표(hash/IP/도메인 평판). IoA = 사전 공격 행위 지표(행위 시퀀스,
kill_chain, causal 체인, actor 프로파일). 본 모듈은 우리 시스템의 IoA 데이터
(ActorProfile.kill_chain / ttp_stats + AttackPrediction + CausalChain)를 그래프
JSON 으로 변환한다. Cytoscape.js 표준 형식 호환 — 프론트엔드 렌더는 별도 스킬.

Spec: E-4 공격 그래프 시각화 (IoA 통합)
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from core.models import (
    ActorProfile,
    AttackPrediction,
    CausalChain,
    InvestigationResult,
)


class IoANode(BaseModel):
    """Cytoscape 노드 한 개.

    Attributes:
        id: 그래프 내 고유 식별자.
        label: 표시 라벨.
        type: 노드 유형 — technique / tactic / actor / effect / prediction.
        attrs: 부가 속성 (tactic, count, source 등).
    """

    id: str
    label: str
    type: str
    attrs: dict[str, object] = Field(default_factory=dict)


class IoAEdge(BaseModel):
    """Cytoscape 엣지 한 개.

    Attributes:
        source: 출발 노드 id.
        target: 도착 노드 id.
        type: 엣지 유형 — sequence / causal / belongs_to / used_by / predicts.
        attrs: 부가 속성 (weight, order 등).
    """

    source: str
    target: str
    type: str
    attrs: dict[str, object] = Field(default_factory=dict)


class IoAGraph(BaseModel):
    """IoA 그래프 (노드 + 엣지 목록).

    `to_cytoscape()` 로 Cytoscape.js 표준 elements JSON 을 얻는다.
    """

    nodes: list[IoANode] = Field(default_factory=list)
    edges: list[IoAEdge] = Field(default_factory=list)

    def to_cytoscape(self) -> dict[str, list[dict[str, object]]]:
        """Cytoscape.js elements 배열 형식으로 직렬화."""
        return {
            "nodes": [
                {
                    "data": {
                        "id": n.id,
                        "label": n.label,
                        "type": n.type,
                        **n.attrs,
                    }
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "data": {
                        "id": f"{e.source}->{e.target}:{e.type}",
                        "source": e.source,
                        "target": e.target,
                        "type": e.type,
                        **e.attrs,
                    }
                }
                for e in self.edges
            ],
        }


def _tactic_node_id(tactic: str) -> str:
    return f"tactic:{tactic}"


def _technique_node_id(tech: str) -> str:
    return f"technique:{tech}"


def _actor_node_id(actor_id: str) -> str:
    return f"actor:{actor_id}"


def _effect_node_id(effect: str) -> str:
    return f"effect:{effect}"


def _pred_node_id(tech: str, actor_id: str) -> str:
    return f"pred:{actor_id}:{tech}"


class IoAGraphBuilder:
    """IoA 그래프 빌더 — actor / investigation → IoAGraph 통합."""

    def __init__(self) -> None:
        self._nodes: dict[str, IoANode] = {}
        self._edges: list[IoAEdge] = []
        self._edge_keys: set[tuple[str, str, str]] = set()

    def _add_node(self, node: IoANode) -> None:
        existing = self._nodes.get(node.id)
        if existing is None:
            self._nodes[node.id] = node
            return
        # merge attrs (count 등 누적, 나머지 새 값 우선).
        merged: dict[str, object] = {**existing.attrs}
        for k, v in node.attrs.items():
            existing_v = merged.get(k)
            if k == "count" and isinstance(v, int) and isinstance(existing_v, int):
                merged[k] = existing_v + v
            else:
                merged[k] = v
        self._nodes[node.id] = existing.model_copy(update={"attrs": merged})

    def _add_edge(self, edge: IoAEdge) -> None:
        key = (edge.source, edge.target, edge.type)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self._edges.append(edge)

    def build_from_actor(self, profile: ActorProfile) -> IoAGraph:
        """단일 actor 프로필 → 그래프.

        노드: actor, technique(top N), tactic, prediction 없음(투입 X).
        엣지: actor → technique (used_by), technique → tactic (belongs_to),
              kill_chain 시간순 sequence.
        """
        self._add_actor(profile)
        self._add_techniques_and_tactics(profile)
        self._add_kill_chain_sequence(profile)
        return self._materialize()

    def build_from_state(
        self,
        profile: ActorProfile | None,
        investigation: InvestigationResult | None,
        causal: CausalChain | None = None,
    ) -> IoAGraph:
        """상태 통합 그래프 (actor + predictions + causal)."""
        if profile is not None:
            self._add_actor(profile)
            self._add_techniques_and_tactics(profile)
            self._add_kill_chain_sequence(profile)
        if investigation is not None:
            self._add_predictions(investigation.predictions, profile)
        if causal is not None:
            self._add_causal_chain(causal)
        return self._materialize()

    def _add_actor(self, profile: ActorProfile) -> None:
        self._add_node(
            IoANode(
                id=_actor_node_id(profile.actor_id),
                label=profile.actor_id,
                type="actor",
                attrs={
                    "is_explicit": profile.is_explicit,
                    "alert_count": profile.alert_count,
                },
            )
        )

    def _add_techniques_and_tactics(self, profile: ActorProfile) -> None:
        for stat in profile.ttp_stats:
            tech_id = _technique_node_id(stat.technique)
            self._add_node(
                IoANode(
                    id=tech_id,
                    label=stat.technique,
                    type="technique",
                    attrs={
                        "tactic": stat.tactic,
                        "count": stat.count,
                        "last_seen": stat.last_seen,
                    },
                )
            )
            if stat.tactic:
                tactic_id = _tactic_node_id(stat.tactic)
                self._add_node(
                    IoANode(
                        id=tactic_id,
                        label=stat.tactic,
                        type="tactic",
                        attrs={"technique_count": 1},
                    )
                )
                self._add_edge(
                    IoAEdge(source=tech_id, target=tactic_id, type="belongs_to")
                )
            # actor → technique (used_by)
            self._add_edge(
                IoAEdge(
                    source=_actor_node_id(profile.actor_id),
                    target=tech_id,
                    type="used_by",
                    attrs={"count": stat.count},
                )
            )

    def _add_kill_chain_sequence(self, profile: ActorProfile) -> None:
        chain = profile.kill_chain
        for i in range(len(chain) - 1):
            a_id = _technique_node_id(chain[i].technique)
            b_id = _technique_node_id(chain[i + 1].technique)
            # 노드 미리 등록(ttp_stats 에 없을 수도 있는 경우 대비).
            if a_id not in self._nodes:
                self._add_node(
                    IoANode(
                        id=a_id,
                        label=chain[i].technique,
                        type="technique",
                        attrs={"count": 1, "source": "kill_chain"},
                    )
                )
            if b_id not in self._nodes:
                self._add_node(
                    IoANode(
                        id=b_id,
                        label=chain[i + 1].technique,
                        type="technique",
                        attrs={"count": 1, "source": "kill_chain"},
                    )
                )
            self._add_edge(
                IoAEdge(
                    source=a_id,
                    target=b_id,
                    type="sequence",
                    attrs={"order": i},
                )
            )

    def _add_predictions(
        self,
        predictions: list[AttackPrediction],
        profile: ActorProfile | None,
    ) -> None:
        actor_id = profile.actor_id if profile is not None else ""
        # 시퀀스 anchor: kill_chain 마지막 technique (있으면).
        last_tech: str | None = None
        if profile is not None and profile.kill_chain:
            last_tech = profile.kill_chain[-1].technique
        for pred in predictions:
            pred_id = _pred_node_id(pred.next_technique, actor_id or "unknown")
            self._add_node(
                IoANode(
                    id=pred_id,
                    label=pred.next_technique,
                    type="prediction",
                    attrs={
                        "probability": pred.probability,
                        "support_count": pred.support_count,
                        "basis_actor_id": pred.basis_actor_id,
                    },
                )
            )
            if last_tech:
                self._add_edge(
                    IoAEdge(
                        source=_technique_node_id(last_tech),
                        target=pred_id,
                        type="predicts",
                        attrs={"probability": pred.probability},
                    )
                )
            elif actor_id:
                self._add_edge(
                    IoAEdge(
                        source=_actor_node_id(actor_id),
                        target=pred_id,
                        type="predicts",
                        attrs={"probability": pred.probability},
                    )
                )

    def _add_causal_chain(self, causal: CausalChain) -> None:
        for i, step in enumerate(causal.steps):
            effect_id = _effect_node_id(step.effect)
            self._add_node(
                IoANode(
                    id=effect_id,
                    label=step.effect,
                    type="effect",
                    attrs={
                        "mitre_technique": step.mitre_technique,
                        "explanation": step.explanation,
                    },
                )
            )
            # 매핑 technique → effect (causal).
            if step.mitre_technique:
                tech_id = _technique_node_id(step.mitre_technique)
                # technique 노드 없으면 신규(causal 근거만).
                if tech_id not in self._nodes:
                    self._add_node(
                        IoANode(
                            id=tech_id,
                            label=step.mitre_technique,
                            type="technique",
                            attrs={"source": "causal", "count": 0},
                        )
                    )
                self._add_edge(
                    IoAEdge(
                        source=tech_id,
                        target=effect_id,
                        type="causal",
                        attrs={"order": i},
                    )
                )
            # 다음 스텝 effect 로 이어지는 sequence.
            if i + 1 < len(causal.steps):
                next_effect_id = _effect_node_id(causal.steps[i + 1].effect)
                self._add_edge(
                    IoAEdge(
                        source=effect_id,
                        target=next_effect_id,
                        type="causal",
                        attrs={"order": i + 1},
                    )
                )

    def _materialize(self) -> IoAGraph:
        return IoAGraph(nodes=list(self._nodes.values()), edges=list(self._edges))
