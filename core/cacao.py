"""CACAO 2.0 대응 플레이북 카탈로그 — 표준 정합 모델 + 검증(권고전용).

OASIS CACAO 2.0 스키마로 UAV 대응 플레이북을 표현한다. 실행은 command `type="manual"`
(인간 실행)만 — 자동 actuator/agent dispatch 없음(권고전용·no-hack-back 교리). 모델은
`extra="forbid"` 로 command_b64·실행형 type·machine agent·live target 을 **구조적으로**
거부한다(no-exec 불변식). NIST SP 800-53 IR 통제·800-61 생애주기·800-184 복구·800-160v2
회복탄력을 라벨/external_references 로 매핑하고, MITRE ATT&CK for UAV 전술로 키잉한다.

임무영향 게이트(if-condition.condition)는 **결정론 화이트리스트 미니식** — eval/exec
절대 없음(AST 파싱 + 노드 whitelist). 파싱·검증만; 평가는 후속 response_agent 담당.

Spec: docs/superpowers/specs/2026-07-09-cacao-playbooks-design.md
"""

from __future__ import annotations

import ast
from pathlib import Path
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
import yaml

from core.exceptions import PlaybookError, SOCPlatformError
from core.models import MissionRisk

_POLICY_DIR = Path(__file__).resolve().parent / "policy"
_CATALOG = _POLICY_DIR / "cacao-playbooks.yaml"

_ATTACK_RE = re.compile(r"^(AML\.)?T\d{4}(\.\d{3})?$")
# NIST SP 800-53 Rev5: IR-1~9 + IR-4(11)(구 IR-10 흡수). IR-10 은 폐지 → 거부.
_IR_ALLOWED = frozenset([f"IR-{i}" for i in range(1, 10)] + ["IR-4(11)"])
_PHASES = frozenset({"contain", "eradicate", "recover", "adapt"})
_HIGH_IMPACT_TACTICS = frozenset(
    {"Impact", "ImpairProcessControl", "InhibitResponseFunction"}
)
_MAX_STR = 2000
# mission-gate 미니식: mission_risk.score / mission_risk.factors["<k>"] /
# mission_risk.is_key_terrain.
_ALLOWED_ATTR = frozenset({"score", "factors", "is_key_terrain"})


class _Strict(BaseModel):
    """미지 키를 거부하는 기반(no-exec 구조 강제 — command_b64/target 등 차단)."""

    model_config = ConfigDict(extra="forbid")


class CacaoExternalReference(_Strict):
    """CACAO external_reference(ATT&CK·NIST 표준 연결)."""

    source_name: str
    external_id: str = ""
    url: str = ""
    description: str = ""


class CacaoCommand(_Strict):
    """CACAO command — `manual`(인간 실행)만. 실행형은 extra=forbid 로 거부."""

    type: Literal["manual"]
    command: str


class CacaoAgentDefinition(_Strict):
    """CACAO agent — 인간 role(`individual`)만. machine agent 는 Literal 거부."""

    type: Literal["individual"]
    name: str = ""


class CacaoStep(_Strict):
    """CACAO workflow step(start|action|if-condition|end)."""

    type: Literal["start", "action", "if-condition", "end"]
    name: str = ""
    description: str = ""
    commands: list[CacaoCommand] = Field(default_factory=list)
    agent: str = ""
    on_completion: str = ""
    on_true: str = ""
    on_false: str = ""
    condition: str = ""
    external_references: list[CacaoExternalReference] = Field(default_factory=list)
    labels: dict[str, object] = Field(default_factory=dict)


class CacaoPlaybook(_Strict):
    """CACAO 2.0 정합 플레이북(전술 키잉)."""

    type: Literal["playbook"]
    spec_version: str
    id: str
    name: str
    description: str = ""
    created: str
    modified: str
    created_by: str = ""
    playbook_types: list[str] = Field(default_factory=list)
    playbook_activities: list[str] = Field(default_factory=list)
    tactic: str
    workflow_start: str
    workflow: dict[str, CacaoStep]
    agent_definitions: dict[str, CacaoAgentDefinition] = Field(default_factory=dict)
    external_references: list[CacaoExternalReference] = Field(default_factory=list)
    labels: dict[str, object] = Field(default_factory=dict)


def _is_mr(node: ast.AST) -> bool:
    """노드가 정확히 `mission_risk` 이름인지."""
    return isinstance(node, ast.Name) and node.id == "mission_risk"


def _is_gate_term(node: ast.expr) -> bool:
    """허용 term 인지 — **전체 경로** 검증(Codex diff M — 잎 이름만 X).

    정확히: `mission_risk.score` | `mission_risk.is_key_terrain` |
    `mission_risk.factors["<str>"]` | int/bool 리터럴. 중첩·잘못된 경로 거부.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, bool)):
        return True  # str 단독 리터럴은 비교항 불가(factors 키에서만)
    if isinstance(node, ast.Attribute) and node.attr in {"score", "is_key_terrain"}:
        return _is_mr(node.value)
    if isinstance(node, ast.Subscript):
        base = node.value
        if not (isinstance(base, ast.Attribute) and base.attr == "factors"):
            return False
        if not _is_mr(base.value):
            return False
        return isinstance(node.slice, ast.Constant) and isinstance(
            node.slice.value, str
        )
    return False


def _check_gate_expr(node: ast.expr, expr: str) -> None:
    """조건식이 BoolOp(and/or) 또는 Compare(허용항·연산자)인지 재귀 검증."""
    if isinstance(node, ast.BoolOp):
        if not isinstance(node.op, (ast.And, ast.Or)):
            raise PlaybookError(f"비허용 BoolOp in {expr!r}")
        for value in node.values:
            _check_gate_expr(value, expr)
        return
    if isinstance(node, ast.Compare):
        if not all(isinstance(op, (ast.GtE, ast.Gt, ast.Eq)) for op in node.ops):
            raise PlaybookError(f"허용 연산자는 >=,>,== 만: {expr!r}")
        for operand in (node.left, *node.comparators):
            if not _is_gate_term(operand):
                raise PlaybookError(f"비허용 비교항: {ast.dump(operand)} in {expr!r}")
        return
    # bare bool 항(예 `mission_risk.is_key_terrain and ...`) 허용 — 상수-only 는
    # 아래 mission_risk 참조 검사가 잡는다.
    if _is_gate_term(node):
        return
    raise PlaybookError(f"비허용 식 구조 {type(node).__name__} in {expr!r}")


def validate_condition(expr: str) -> None:
    """mission-gate 조건식을 결정론 화이트리스트로 파싱·검증한다(평가 없음).

    허용: 비교(>=,>,==)·and/or + 항 `mission_risk.score`·
    `mission_risk.factors["<키>"]`·`mission_risk.is_key_terrain`·정수/bool 리터럴.
    **전체 경로** 검증 — 중첩(mission_risk.score.score)·상수-only(True·"x"=="x") 거부.
    함수호출·import·임의 이름·dunder 접근 거부. mission_risk 를 반드시 참조해야 함.

    Args:
        expr: if-condition 조건식.

    Raises:
        PlaybookError: 파싱 실패 또는 비허용 구조/항/상수-only.
    """
    if not expr or len(expr) > _MAX_STR:
        raise PlaybookError("mission-gate 조건식이 비었거나 과대함")
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise PlaybookError(f"조건식 파싱 실패: {expr!r} ({exc})") from exc
    _check_gate_expr(tree.body, expr)
    # 상수-only(mission_risk 미참조) 게이트 거부 — 의미없는 게이트 방지.
    if not any(_is_mr(n) for n in ast.walk(tree)):
        raise PlaybookError(f"조건식이 mission_risk 를 참조하지 않음: {expr!r}")


def _term_value(node: ast.expr, mr: MissionRisk) -> object:
    """허용 term 을 MissionRisk 값으로 바인딩(validate_condition 이 형태 보장)."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Attribute):
        if node.attr == "score":
            return mr.score
        if node.attr == "is_key_terrain":
            return mr.is_key_terrain
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        # mission_risk.factors["<키>"] — 결측 키는 0(크래시 방지).
        return mr.factors.get(str(node.slice.value), 0)
    raise PlaybookError(f"평가 불가 term: {ast.dump(node)}")


def _eval_node(node: ast.expr, mr: MissionRisk) -> bool:
    """검증된 조건식 AST 를 결정론 평가(eval 없음)."""
    if isinstance(node, ast.BoolOp):
        vals = [_eval_node(v, mr) for v in node.values]
        return all(vals) if isinstance(node.op, ast.And) else any(vals)
    if isinstance(node, ast.Compare):
        cur = _term_value(node.left, mr)
        ok = True
        for op, comp in zip(node.ops, node.comparators, strict=True):
            rhs = _term_value(comp, mr)
            if isinstance(op, ast.GtE):
                ok = ok and cur >= rhs  # type: ignore[operator]
            elif isinstance(op, ast.Gt):
                ok = ok and cur > rhs  # type: ignore[operator]
            elif isinstance(op, ast.Eq):
                ok = ok and cur == rhs
            else:
                ok = False
            cur = rhs
        return ok
    # bare bool term(예 mission_risk.is_key_terrain)
    return bool(_term_value(node, mr))


def evaluate_condition(expr: str, mr: MissionRisk) -> bool:
    """mission-gate 조건식을 MissionRisk 로 **결정론 평가**한다(eval/exec 없음).

    validate_condition 으로 whitelist 재검증 후, 검증된 AST 만 계산한다.

    Args:
        expr: if-condition 조건식.
        mr: 평가 컨텍스트(triage 산출 MissionRisk).

    Returns:
        조건 충족 여부.

    Raises:
        PlaybookError: 조건식이 비허용(재검증 실패) 시.
    """
    validate_condition(expr)
    return _eval_node(ast.parse(expr, mode="eval").body, mr)


class ResolvedPlan(BaseModel):
    """CACAO workflow 워크 결과(권고전용 표면용)."""

    playbook_id: str
    steps: list[dict[str, object]] = Field(default_factory=list)
    mission_branch: str = "auto"
    hitl_required: bool = False


def select_playbook(tactic: str, catalog: list[CacaoPlaybook]) -> CacaoPlaybook | None:
    """전술로 카탈로그 플레이북 선택(없으면 None → 폴백 유도)."""
    if not tactic:
        return None
    return next((pb for pb in catalog if pb.tactic == tactic), None)


def resolve_playbook(pb: CacaoPlaybook, mr: MissionRisk | None) -> ResolvedPlan:
    """workflow 를 start→...→end 워크해 임무-분기 행동을 resolve(평가 없이 표면).

    if-condition 은 evaluate_condition 으로 분기(mr None → **보수 on_true/HITL**
    fail-safe). action 은 manual command 를 순서대로 수집(권고전용 — 실행 없음).
    """
    steps: list[dict[str, object]] = []
    branch = "auto"
    hitl = False
    sid = pb.workflow_start
    visited: set[str] = set()
    while sid:
        if sid in visited:  # 루프 → 부분 plan 대신 실패(Codex M — 폴백 유도)
            raise PlaybookError(f"{pb.id}: workflow 루프 {sid}")
        visited.add(sid)
        step = pb.workflow.get(sid)
        if step is None:  # 미해결 step → 실패(조용한 부분 plan 금지)
            raise PlaybookError(f"{pb.id}: 미해결 workflow step {sid!r}")
        if step.type == "action":
            steps.append(
                {
                    "name": step.name,
                    "phase": step.labels.get("phase"),
                    "nist_ir": step.labels.get("nist_ir"),
                    "commands": [c.command for c in step.commands],
                }
            )
            sid = step.on_completion
        elif step.type == "if-condition":
            take_true = True if mr is None else evaluate_condition(step.condition, mr)
            if take_true:
                branch, hitl = "conservative", True
                sid = step.on_true
            else:
                branch = "auto"
                sid = step.on_false
        elif step.type == "end":
            break
        else:  # start
            sid = step.on_completion
    return ResolvedPlan(
        playbook_id=pb.id, steps=steps, mission_branch=branch, hitl_required=hitl
    )


def scenario_tactic_map(path: str | Path | None = None) -> dict[str, str]:
    """bas-scenarios 에서 scenario_id→tactic 맵(로드 실패 → 빈 맵 → 폴백)."""
    try:
        from core.bas import BASRunner

        return {
            s.id: s.tactic for s in BASRunner.from_yaml(path)._scenarios if s.tactic
        }
    except SOCPlatformError:
        return {}


def _check_external_refs(refs: list[CacaoExternalReference]) -> None:
    for ref in refs:
        if len(ref.external_id) > _MAX_STR or len(ref.url) > _MAX_STR:
            raise PlaybookError("external_reference 필드 과대")
        if ref.url and not ref.url.startswith("https://"):
            raise PlaybookError(f"external_reference url 은 https 필수: {ref.url}")
        if ref.source_name == "mitre-attack" and not _ATTACK_RE.match(ref.external_id):
            raise PlaybookError(f"부정 ATT&CK id: {ref.external_id}")
        if ref.source_name == "nist-800-53" and ref.external_id not in _IR_ALLOWED:
            raise PlaybookError(f"미허용 NIST IR 통제: {ref.external_id}")


def _resolve_source_ref(ref: str, coa: dict, rec: dict) -> bool:  # type: ignore[type-arg]
    """source_ref(coa:T:D / recovery:T:phase[:idx])가 실 매트릭스 셀에 존재하는지."""
    parts = ref.split(":")
    if parts[0] == "coa" and len(parts) == 3:
        cell = coa.get(parts[1], {})
        cell = cell.get(parts[2]) if isinstance(cell, dict) else None
        return bool(isinstance(cell, dict) and cell.get("action"))
    if parts[0] == "recovery" and len(parts) in (3, 4):
        entry = rec.get(parts[1], {})
        phase = entry.get(parts[2]) if isinstance(entry, dict) else None
        if len(parts) == 4:
            try:
                idx = int(parts[3])
            except ValueError:
                return False
            return isinstance(phase, list) and 0 <= idx < len(phase)
        return phase is not None
    return False


def _load_matrix_raw(name: str) -> dict:  # type: ignore[type-arg]
    raw = yaml.safe_load((_POLICY_DIR / name).read_text(encoding="utf-8"))
    matrix = raw.get("matrix", {}) if isinstance(raw, dict) else {}
    return matrix if isinstance(matrix, dict) else {}


def validate_playbook(pb: CacaoPlaybook, coa: dict, rec: dict) -> None:  # type: ignore[type-arg]
    """CACAO 정합·no-exec·phase·임무게이트·IR·source_ref 를 검증한다.

    Raises:
        PlaybookError: 어느 규칙이라도 위반 시(명확한 메시지 동반).
    """
    wf = pb.workflow
    # 1. 필수 구조 — start/end 존재, workflow_start→start, 참조 해결.
    if pb.workflow_start not in wf or wf[pb.workflow_start].type != "start":
        raise PlaybookError(f"{pb.id}: workflow_start 가 start step 아님")
    if not any(s.type == "end" for s in wf.values()):
        raise PlaybookError(f"{pb.id}: end step 부재")
    for sid, step in wf.items():
        for nxt in (step.on_completion, step.on_true, step.on_false):
            if nxt and nxt not in wf:
                raise PlaybookError(f"{pb.id}:{sid} 미해결 참조 {nxt}")
    # 2. playbook_types populated → playbook_activities ≥1.
    if pb.playbook_types and not pb.playbook_activities:
        raise PlaybookError(f"{pb.id}: playbook_types 있으나 activities 없음")
    # 3. external_references 앵커/화이트리스트/https(플레이북 + 스텝).
    _check_external_refs(pb.external_references)
    for step in wf.values():
        _check_external_refs(step.external_references)
    # 4. no-exec — command 은 manual 만(Literal 로 이미 강제, 이중확인).
    for step in wf.values():
        for cmd in step.commands:
            if cmd.type != "manual":
                raise PlaybookError(f"{pb.id}: 비-manual command 금지")
    for agent in pb.agent_definitions.values():
        if agent.type != "individual":
            raise PlaybookError(f"{pb.id}: 인간(individual) agent 만 허용")
    # 5. action step 구조 + phase 커버 + recover 검증 step.
    phases_seen: set[str] = set()
    recover_verify = False
    for sid, step in wf.items():
        if step.type == "action":
            if not step.commands:
                raise PlaybookError(f"{pb.id}:{sid} action command 없음")
            if step.agent and step.agent not in pb.agent_definitions:
                raise PlaybookError(f"{pb.id}:{sid} 미정의 agent {step.agent}")
            # nist_ir 라벨은 존재 + **화이트리스트**(Codex diff M — IR-10 등 라벨
            # 경유 우회 차단; external_references 와 동일 기준).
            ir_label = step.labels.get("nist_ir")
            if ir_label is None:
                raise PlaybookError(f"{pb.id}:{sid} nist_ir 라벨 없음")
            if ir_label not in _IR_ALLOWED:
                raise PlaybookError(f"{pb.id}:{sid} 미허용 nist_ir 라벨 {ir_label!r}")
            phase = step.labels.get("phase")
            if not isinstance(phase, str) or phase not in _PHASES:
                raise PlaybookError(f"{pb.id}:{sid} 부정 phase {phase!r}")
            phases_seen.add(phase)
            if phase == "recover" and step.labels.get("verify"):
                recover_verify = True
            if phase == "adapt":
                # 회복탄력(800-160v2) — 매트릭스 셀 아닌 resiliency_technique 로 근거.
                if not step.labels.get("resiliency_technique"):
                    raise PlaybookError(
                        f"{pb.id}:{sid} adapt resiliency_technique 없음"
                    )
            else:
                sref = step.labels.get("source_ref")
                if not (isinstance(sref, str) and _resolve_source_ref(sref, coa, rec)):
                    raise PlaybookError(f"{pb.id}:{sid} source_ref 미해결 {sref!r}")
        elif step.type == "if-condition":
            if not (step.on_true and step.on_false and step.condition):
                raise PlaybookError(f"{pb.id}:{sid} if-condition 필드 누락")
    if _PHASES - phases_seen:
        raise PlaybookError(f"{pb.id}: phase 미커버 {_PHASES - phases_seen}")
    if not recover_verify:
        raise PlaybookError(f"{pb.id}: recover 검증(verify) step 없음(800-184)")
    # 6. 고-임팩트 전술 → mission_gate if-condition + 화이트리스트 조건.
    if pb.tactic in _HIGH_IMPACT_TACTICS:
        gates = [
            s
            for s in wf.values()
            if s.type == "if-condition" and s.labels.get("mission_gate")
        ]
        if not gates:
            raise PlaybookError(f"{pb.id}: 고-임팩트 전술 mission_gate 없음")
        for g in gates:
            validate_condition(g.condition)


def load_playbooks(path: str | Path | None = None) -> list[CacaoPlaybook]:
    """cacao-playbooks 카탈로그를 로드·검증한다.

    Args:
        path: 카탈로그 경로(미지정 시 기본 정책).

    Returns:
        검증 통과한 CACAO 플레이북 목록.

    Raises:
        PlaybookError: 파일/스키마/정합 오류 시.
    """
    p = Path(path) if path else _CATALOG
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PlaybookError(f"카탈로그 로드 실패: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("playbooks"), list):
        raise PlaybookError("카탈로그 구조 오류(playbooks 리스트 부재)")
    coa = _load_matrix_raw("coa-matrix.yaml")
    rec = _load_matrix_raw("recovery-matrix.yaml")
    result: list[CacaoPlaybook] = []
    for item in raw["playbooks"]:
        try:
            pb = CacaoPlaybook.model_validate(item)
        except ValidationError as exc:
            raise PlaybookError(f"CACAO 스키마 검증 실패: {exc}") from exc
        validate_playbook(pb, coa, rec)
        result.append(pb)
    return result
