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

from core.actor_fingerprint import (
    fingerprint,
    is_empty_fingerprint,
    resolve_actor_id,
)
from core.models import Alert, EnvVerdict, IncidentCase, IncidentState, Severity
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

    def delete(self, case_id: str) -> None:
        """case 를 삭제한다(reconciliation 병합 후 fp-case 제거)."""
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

    def delete(self, case_id: str) -> None:
        self._by_id.pop(case_id, None)

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


# 후반 단계 kill-chain order 임계(권위 CAT1 = root/admin intrusion).
_ROOT_ORDER = 11
# 재범 재개방 하드캡 — 신뢰소스 오작동/침해 시 무한 reopen/close 순환 방지(Codex H).
_MAX_REOPEN = 100
# DoS 시나리오 마커 — eval 명명 규약(의미적 DoS 탐지기 아님, 자문 분류용, Codex L).
_DOS_MARKERS = frozenset({"SWARM", "SATURATION", "DISABLE", "FLOOD", "DOS"})


def _is_dos_scenario(scenario_id: str) -> bool:
    """scenario_id 에 DoS 마커 포함 여부(대문자 매칭)."""
    up = scenario_id.upper()
    return any(m in up for m in _DOS_MARKERS)


def _authoritative_cat(
    env_verdict: EnvVerdict, kill_chain_stage: int, is_dos: bool = False
) -> str:
    """확증 CAT(CJCSM 6510) 순서 결정표(첫 매치·무중첩).

    CONFIRMED_FP → CAT3(unsuccessful). CONFIRMED_TP:
      DoS→CAT4 / order≥11→CAT1(root) / order≥3→CAT2(user) / order 1~2→CAT6(recon)
      / order 0→CAT2. (CAT7 SBOM 은 확정 SbomFinding plumbing 필요 → 후속.)
    """
    # CONFIRMED_FP 우선(무중첩) — 이하 분기는 CONFIRMED_TP 에만 적용(Codex H4).
    if env_verdict != EnvVerdict.CONFIRMED_TP:
        return "CAT3"  # CONFIRMED_FP → unsuccessful (INCONCLUSIVE 는 호출 전 차단)
    if is_dos:
        return "CAT4"  # DoS 는 효과유형 — 단계보다 우선
    if kill_chain_stage >= _ROOT_ORDER:
        return "CAT1"
    if kill_chain_stage > _RECON_MAX_ORDER:
        return "CAT2"
    if kill_chain_stage >= 1:
        return "CAT6"
    return "CAT2"


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

    def observe_outcome(
        self,
        alert: Alert,
        env_verdict: EnvVerdict,
        *,
        recovery_applied: bool = False,
        reoccurred: bool = False,
        no_effect_sustained: bool = False,
    ) -> IncidentCase | None:
        """신뢰 관측(OutcomeProbe)으로 case 후반 생명주기를 전진시킨다.

        INCONCLUSIVE 는 절대 전진 안 함(Codex M1). CONFIRMED_TP 도달 시 report 잠정
        fp-case 를 explicit case 로 병합(reconciliation, H2) + provisional=False +
        권위 CAT 부여. 스텝와이즈 단조(관측 1 = 전진 ≤1).

        Args:
            alert: 관측 재구성 알람(actor_id=신뢰 obs.actor_id).
            env_verdict: OutcomeProbe 물리효과 판정(CONFIRMED_TP/FP/INCONCLUSIVE).
            recovery_applied: 축출/복구 실행됨.
            reoccurred: 복구 후 재발(축출 실패).
            no_effect_sustained: 무효과 지속(정화).

        Returns:
            갱신된 IncidentCase. INCONCLUSIVE·봉합 불가 시 None.
        """
        if env_verdict == EnvVerdict.INCONCLUSIVE:
            return None
        actor_id, is_explicit = resolve_actor_id(alert)
        if not actor_id or is_empty_fingerprint(actor_id):
            return None
        case = self._resolve_case(alert, actor_id, is_explicit)
        is_new_alert = bool(alert.id) and alert.id not in case.member_alert_ids
        # 재범 재개방(단조성 유일 예외): CLOSED + 신뢰 CONFIRMED_TP + **새 이벤트** +
        # 캡 미만. 새 alert.id + _MAX_REOPEN 로 무한 순환 봉인(Codex H).
        if (
            case.state == IncidentState.CLOSED
            and env_verdict == EnvVerdict.CONFIRMED_TP
            and is_new_alert
            and case.reopen_count < _MAX_REOPEN
        ):
            case.state = IncidentState.CONTAINMENT
            case.reopen_count += 1
        else:
            target = self._outcome_target(
                case.state,
                env_verdict,
                recovery_applied=recovery_applied,
                reoccurred=reoccurred,
                no_effect_sustained=no_effect_sustained,
            )
            if target is not None and _STATE_ORDER[target] > _STATE_ORDER[case.state]:
                case.state = target
        if env_verdict == EnvVerdict.CONFIRMED_TP:
            case.provisional = False
        if is_new_alert:
            case.member_alert_ids.append(alert.id)
            case.member_alert_ids = case.member_alert_ids[-_CASE_CAP:]
        case.kill_chain_stage = max(case.kill_chain_stage, self._alert_stage(alert))
        if not case.provisional:
            case.cat = _authoritative_cat(
                env_verdict,
                case.kill_chain_stage,
                _is_dos_scenario(alert.scenario_id),
            )
        case.updated_at = _now_iso()
        self._store.save(case)
        return case

    def _resolve_case(
        self, alert: Alert, actor_id: str, is_explicit: bool
    ) -> IncidentCase:
        """explicit case 로 봉합 + report 잠정 fp-case 병합(reconciliation)."""
        case_id = f"case:{actor_id}"
        case = self._store.load(case_id)
        if case is None:
            case = IncidentCase(
                case_id=case_id,
                actor_id=actor_id,
                opened_at=_now_iso(),
                updated_at=_now_iso(),
            )
        # explicit 봉합인데 **이 alert 을 member 로 가진** fingerprint case 가 따로 열려
        # 있으면 병합. alert.id 멤버십으로 동일 사건 확증 — fingerprint(actor_id 무시)만
        # 으론 다른 actor 의 우연한 속성일치 case 를 오병합할 수 있어서(Codex NEW-A).
        if is_explicit and alert.id:
            fp_id = f"case:{fingerprint(alert)}"
            if fp_id != case_id:
                fp_case = self._store.load(fp_id)
                if fp_case is not None and alert.id in fp_case.member_alert_ids:
                    for aid in fp_case.member_alert_ids:
                        if aid not in case.member_alert_ids:
                            case.member_alert_ids.append(aid)
                    if _STATE_ORDER[fp_case.state] > _STATE_ORDER[case.state]:
                        case.state = fp_case.state
                    case.kill_chain_stage = max(
                        case.kill_chain_stage, fp_case.kill_chain_stage
                    )
                    self._store.delete(fp_id)
        return case

    @staticmethod
    def _outcome_target(
        state: IncidentState,
        env_verdict: EnvVerdict,
        *,
        recovery_applied: bool,
        reoccurred: bool,
        no_effect_sustained: bool,
    ) -> IncidentState | None:
        """현 상태+신뢰신호 → 다음 허용 상태(스텝와이즈, 없으면 None)."""
        tp = env_verdict == EnvVerdict.CONFIRMED_TP
        fp = env_verdict == EnvVerdict.CONFIRMED_FP
        if tp and _STATE_ORDER[state] < _STATE_ORDER[IncidentState.CONTAINMENT]:
            return IncidentState.CONTAINMENT
        if tp and state == IncidentState.CONTAINMENT and recovery_applied:
            return IncidentState.ERADICATION
        if (
            tp
            and state == IncidentState.ERADICATION
            and recovery_applied
            and not reoccurred
        ):
            return IncidentState.RECOVERY
        if state == IncidentState.RECOVERY and (fp or no_effect_sustained):
            return IncidentState.CLOSED
        return None

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
