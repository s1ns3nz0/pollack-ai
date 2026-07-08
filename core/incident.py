"""Incident Case 생명주기 — alert-driven → case-driven(DoD SOC 정렬, MVP).

DoD CSSP tiered SOC / NIST 800-61 인시던트 생명주기 / CJCSM 6510 CAT 분류의 결정론
구현. 흩어진 alert 을 actor 단위 **Incident Case** 로 봉합해 상태(NEW→…→CLOSED)로
진행시킨다.

트러스트(Codex 설계검증 반영):
- report 노드는 **PROVISIONAL 상태만**(NEW→ANALYSIS)+잠정 CAT. in-pipeline verdict 는
  default_judge 가 ground_truth(기본 TP) 반환 → 자기확증 가능. 그래서 CONTAINMENT·권위
  CAT(1/2/7)은 report 도달 불가(edge 없음). 확증(CONFIRMED_TP)은 OutcomeProbe 후속.
- 봉합은 `resolve_actor_id`(빈 fp 미개설). fingerprint 변조 DoS 는 store 캡+LRU.
- store 는 모듈 싱글톤(build_soc_graph 매요청 재생성 무관).

Spec: docs/superpowers/specs/2026-07-08-incident-case-lifecycle-design.md
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from core.actor_fingerprint import is_empty_fingerprint, resolve_actor_id
from core.models import Alert, IncidentCase, IncidentState, Severity
from tools.coverage import CoverageMatrix

# open case 하드캡(H3 DoS 봉인) — 초과 시 LRU eviction.
_CASE_CAP = 1000
_RECON_MAX_ORDER = 2  # 정찰 단계 상한(잠정 CAT6 판정).


# 상태 서열(단조 전진용) — 뒤일수록 진행.
_STATE_ORDER: dict[IncidentState, int] = {
    IncidentState.NEW: 0,
    IncidentState.ANALYSIS: 1,
    IncidentState.CONTAINMENT: 2,
    IncidentState.ERADICATION: 3,
    IncidentState.RECOVERY: 4,
    IncidentState.CLOSED: 5,
}
# 허용 전이 edge — report 노드는 NEW/ANALYSIS 만(CONTAINMENT edge 없음).
_REPORT_EDGES: dict[IncidentState, IncidentState] = {
    IncidentState.NEW: IncidentState.ANALYSIS,
}


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@runtime_checkable
class IncidentStore(Protocol):
    """Incident Case 저장소 계약."""

    def load(self, case_id: str) -> IncidentCase | None:
        """case_id 로 case 를 가져온다(없으면 None)."""
        ...

    def save(self, case: IncidentCase) -> None:
        """case 를 저장한다(캡 초과 시 LRU eviction)."""
        ...

    def open_count(self) -> int:
        """현재 저장된 case 수."""
        ...


class InMemoryIncidentStore:
    """프로세스 내 Incident Case 저장소 — 하드캡 + LRU eviction(DoS 봉인).

    Args:
        cap: open case 상한. 초과 시 최오래(LRU) case 축출.
    """

    def __init__(self, cap: int = _CASE_CAP) -> None:
        self._by_id: OrderedDict[str, IncidentCase] = OrderedDict()
        self._cap = cap

    def load(self, case_id: str) -> IncidentCase | None:
        case = self._by_id.get(case_id)
        if case is not None:
            self._by_id.move_to_end(case_id)  # LRU 갱신
        return case

    def save(self, case: IncidentCase) -> None:
        self._by_id[case.case_id] = case
        self._by_id.move_to_end(case.case_id)
        while len(self._by_id) > self._cap:
            self._by_id.popitem(last=False)  # 최오래 축출

    def open_count(self) -> int:
        return len(self._by_id)


# 모듈 싱글톤 — build_soc_graph 가 매 /alert 요청마다 호출되므로 store 는 그래프가
# 아니라 여기서 보유해 case 누적이 요청 간 유지된다(Codex H4).
_STORE = InMemoryIncidentStore()


def incident_store() -> IncidentStore:
    """전역 Incident Case 저장소(싱글톤)."""
    return _STORE


def _provisional_cat(kill_chain_stage: int) -> str:
    """잠정 CAT(순서 결정표, 첫 매치) — 권위 CAT1/2/7 은 신뢰확증 후속에서만."""
    if 0 < kill_chain_stage <= _RECON_MAX_ORDER:
        return "CAT6"  # Reconnaissance
    return "CAT8"  # Investigating


class CaseManager:
    """alert → Incident Case 봉합·PROVISIONAL 상태 진행(결정론, report 노드용).

    Args:
        store: Incident Case 저장소(기본 싱글톤).
    """

    def __init__(
        self,
        store: IncidentStore | None = None,
        coverage: CoverageMatrix | None = None,
    ) -> None:
        self._store = store or incident_store()
        # kill-chain stage 산정용(잠정 CAT6/CAT8 구분). 미주입 시 지연 로드 시도.
        self._coverage = coverage

    def observe_alert(self, alert: Alert, severity: Severity) -> IncidentCase | None:
        """alert 을 actor case 에 봉합하고 PROVISIONAL 상태를 전진시킨다.

        report 노드(hotpath)용 — NEW→ANALYSIS 까지만. CONTAINMENT·권위 CAT 은
        전이표에 없어 도달 불가(신뢰확증 후속 전담).

        Args:
            alert: 대상 알람.
            severity: SeverityEngine 산정 등급(provisional 추적).

        Returns:
            갱신된 IncidentCase. 빈 fingerprint(봉합 불가) 면 None.
        """
        actor_id, _ = resolve_actor_id(alert)
        # 봉합 불가 → case 미개설: 빈 actor_id(공백 explicit "   " 포함, Codex M) 또는
        # 빈 fingerprint. resolve_actor_id 가 strip 하므로 not 로 판정.
        if not actor_id or is_empty_fingerprint(actor_id):
            return None
        case_id = f"case:{actor_id}"
        now = _now_iso()
        case = self._store.load(case_id)
        if case is None:
            case = IncidentCase(
                case_id=case_id, actor_id=actor_id, opened_at=now, updated_at=now
            )
        # 단조 전진(전이표 허용 edge만) — report 는 NEW→ANALYSIS.
        nxt = _REPORT_EDGES.get(case.state)
        if nxt is not None and _STATE_ORDER[nxt] > _STATE_ORDER[case.state]:
            case.state = nxt
        # 누적 갱신(provisional).
        if alert.id and alert.id not in case.member_alert_ids:
            case.member_alert_ids.append(alert.id)
            case.member_alert_ids = case.member_alert_ids[-_CASE_CAP:]
        stage = self._alert_stage(alert)
        case.kill_chain_stage = max(case.kill_chain_stage, stage)
        # severity_peak 는 provisional·informational — SeverityEngine 산출(자산·임무·
        # dynamics 반영). baseline 이 탐지소스 필드라 자기보고 영향은 플랫폼 severity
        # 전반과 동일 부류(권위 판정 비구동). case.provisional=True 로 표식.
        if _sev_rank(severity) > _sev_rank(case.severity_peak):
            case.severity_peak = severity
        case.cat = _provisional_cat(case.kill_chain_stage)
        case.updated_at = now
        self._store.save(case)
        return case

    def _alert_stage(self, alert: Alert) -> int:
        """alert 의 kill-chain order — CoverageMatrix 로 tactic→order 산정.

        정찰(order≤2)은 CAT6 판정에 필요. kill_chain_advanced(누적 후반)면 최소 후반
        order 보장. 커버리지 미가용 시 플래그 기반 이진 폴백(11/0).
        """
        advanced_floor = 11 if alert.kill_chain_advanced else 0
        matrix = self._coverage_matrix()
        if matrix is None:
            return advanced_floor
        raw = alert.mitre.get("tactics", [])
        tactics = [str(t) for t in raw] if isinstance(raw, list) else []
        return max(matrix.max_tactic_order(tactics), advanced_floor)

    def _coverage_matrix(self) -> CoverageMatrix | None:
        """CoverageMatrix 지연 로드(미주입 시 1회 시도, 실패 시 None 고정)."""
        if self._coverage is None:
            from core.exceptions import SOCPlatformError

            try:
                self._coverage = CoverageMatrix.from_yaml()
            except SOCPlatformError:
                return None
        return self._coverage


_SEV_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}


def _sev_rank(sev: Severity) -> int:
    return _SEV_RANK.get(sev, 0)
