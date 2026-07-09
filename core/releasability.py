"""JADC2 연합상호운용성 — Releasability 파트너 스코핑(결정론·읽기전용·외향 없음).

내부 STIX 번들에서 **파트너 릴리서블 파생물**을 만든다 — 파트너 티어별로 허용된 SDO
type·field 만 남기고(default-deny allowlist) REL-TO/NOFORN statement 마킹을 붙인다.
외향 push 없음(파생 번들 생산·직렬화만).

**OPSEC(Codex Critical): allowlist·default-deny.** type-level strip 만으론 잔존 객체에
내부 식별자(자산/시나리오/우리 identity)가 남는다. 허용 type + 허용 field 만 통과시켜
created_by_ref·description·labels·x_* 를 원천 차단. 입력 번들 무변이(deepcopy).

Spec: docs/superpowers/specs/2026-07-09-jadc2-releasability-design.md
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re

from pydantic import BaseModel, ConfigDict, Field

from core.policy_loader import load_policy_mapping
from core.stix_export import _TLP_MARKINGS, _sid

_POLICY = Path(__file__).resolve().parent / "policy" / "releasability.yaml"

# 잔존 객체가 유지할 수 있는 필드(SDO type→허용 집합). 이 외 전부 drop(default-deny).
# object_marking_refs 는 사후 재설정하므로 여기 포함 안 함(잔여 ref 봉쇄).
_SAFE_FIELDS: dict[str, frozenset[str]] = {
    # name 제외 — free-form 이라 내부 문자열 잠입 위험(Codex). 공개 참조는
    # external_references.external_id(T-id)가 canonical — 그것만 releasable.
    "attack-pattern": frozenset(
        {"type", "id", "spec_version", "created", "modified", "external_references"}
    ),
    "indicator": frozenset(
        {
            "type",
            "id",
            "spec_version",
            "created",
            "modified",
            "pattern",
            "pattern_type",
            "valid_from",
        }
    ),
    "relationship": frozenset(
        {
            "type",
            "id",
            "spec_version",
            "created",
            "modified",
            "relationship_type",
            "source_ref",
            "target_ref",
        }
    ),
    "marking-definition": frozenset(
        {
            "type",
            "id",
            "spec_version",
            "created",
            "definition_type",
            "definition",
            "name",
        }
    ),
}

# external_references 중첩 allowlist — 공개 ATT&CK 참조만(url/description 등 내부 차단).
_SAFE_EXTREF: frozenset[str] = frozenset({"source_name", "external_id"})
# 공개 MITRE 출처·id 형식 강제(free-form external_id 로 내부 문자열 잠입 차단, Codex).
_MITRE_SOURCES: frozenset[str] = frozenset({"mitre-attack", "mitre-atlas"})
_MITRE_ID_RE = re.compile(r"^(AML\.)?T\d{4}(\.\d{3})?$")
# STIX 표준 relationship 어휘만 통과(free-form relationship_type 차단).
_STD_REL_TYPES: frozenset[str] = frozenset(
    {"uses", "indicates", "mitigates", "targets", "attributed-to", "related-to"}
)


def _safe_extrefs(refs: list[object]) -> list[dict[str, object]]:
    """external_references 중첩 스크럽 — 공개 MITRE 출처·T-id 형식만 유지."""
    out: list[dict[str, object]] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        src = ref.get("source_name")
        ext = ref.get("external_id")
        if src in _MITRE_SOURCES and isinstance(ext, str) and _MITRE_ID_RE.match(ext):
            out.append({"source_name": src, "external_id": ext})
    return out


class PartnerTier(BaseModel):
    """파트너 티어 릴리서빌리티 규칙(엄격 — 미지 필드 거부, fail-closed)."""

    model_config = ConfigDict(extra="forbid")

    rel_to: list[str] = Field(default_factory=list)
    caveat: str
    release_types: list[str] = Field(default_factory=list)


class ReleasabilityPolicy(BaseModel):
    """파트너 티어별 릴리서빌리티 정책."""

    model_config = ConfigDict(extra="forbid")

    partner_tiers: dict[str, PartnerTier] = Field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> ReleasabilityPolicy:
        """releasability.yaml 적재·검증(fail-closed).

        Raises:
            PolicyError: 파일 부재/파싱/구조 불일치 시(공유 로더). 미지 필드도 거부
                (extra=forbid — 잘못된 정책이 광범위 릴리스로 빠지지 않게).
        """
        raw = load_policy_mapping(path, _POLICY, label="releasability")
        return cls.model_validate(raw)


def for_partner(
    bundle: dict[str, object],
    tier: str,
    policy: ReleasabilityPolicy,
    created_at: str,
    tlp: str = "amber",
) -> dict[str, object] | None:
    """내부 STIX 번들 → 파트너 릴리서블 파생 번들(default-deny·순수).

    Args:
        bundle: 내부 STIX 번들(from_diamond/from_campaign 산출).
        tier: 파트너 티어명(정책 키).
        policy: 릴리서빌리티 정책.
        created_at: statement marking created(ISO).
        tlp: TLP 등급(기본 amber).

    Returns:
        파트너 스코프 번들. 미지 티어/공유대상 0 이면 None(fail-safe). 입력 무변이.

    Note:
        입력 bundle 은 StixExporter(from_diamond/from_campaign) 산출을 전제한다 —
        객체 id 는 _sid uuid5(불투명, 내부 문자열 미임베드)라 그대로 복사해도 안전.
        임의/외부 번들의 id 에 내부 문자열이 박혀 있으면 복사될 수 있음(경계 조건).
    """
    pt = policy.partner_tiers.get(tier)
    if pt is None:
        return None  # 정책 밖 파트너 — 유출 차단.
    tlp_ref = _TLP_MARKINGS.get(tlp.lower(), _TLP_MARKINGS["amber"])
    # 입력 marking-definition 은 통과 금지(Codex Critical) — 내부 마킹 유출·empty-check
    # 우회 방지. 출력엔 우리가 새로 만든 statement 만. relationship 은 사후 댕글링 정리.
    allowed = set(pt.release_types) | {"relationship"}
    raw_objs = bundle.get("objects")
    objs = (
        [o for o in raw_objs if isinstance(o, dict)]
        if isinstance(raw_objs, list)
        else []
    )

    # statement marking-definition(표준 STIX 2.1) — 결정론 id.
    stmt_id = _sid("marking-definition", f"statement:{pt.caveat}")
    stmt: dict[str, object] = {
        "type": "marking-definition",
        "id": stmt_id,
        "spec_version": "2.1",
        "created": created_at,
        "definition_type": "statement",
        "definition": {"statement": pt.caveat},
        "name": pt.caveat,
    }
    marks: list[str] = [tlp_ref, stmt_id]

    def _scrub(obj: dict[str, object]) -> dict[str, object]:
        safe = _SAFE_FIELDS[str(obj.get("type"))]
        clean: dict[str, object] = {}
        for k, v in obj.items():
            if k not in safe:
                continue
            if k == "external_references" and isinstance(v, list):
                clean[k] = _safe_extrefs(v)  # 중첩 스크럽 + MITRE 출처·id 형식 강제.
            else:
                clean[k] = deepcopy(v)
        clean["object_marking_refs"] = list(marks)  # 재설정 — 잔여/댕글링 ref 제거.
        return clean

    # 1. 비-relationship 데이터 객체: type allowlist + field allowlist.
    scrubbed: list[dict[str, object]] = []
    surviving: set[str] = {stmt_id}
    for o in objs:
        t = str(o.get("type"))
        if t == "relationship" or t not in allowed or t not in _SAFE_FIELDS:
            continue  # default-deny.
        clean = _scrub(o)
        # 공개 MITRE 참조가 남지 않은 attack-pattern 은 releasable 내용 없음 → 제외.
        if t == "attack-pattern" and not clean.get("external_references"):
            continue
        scrubbed.append(clean)
        surviving.add(str(o.get("id")))

    if not scrubbed:
        return None  # 공유할 데이터 없음.

    # 2. relationship: 표준 어휘 + 양 끝 잔존일 때만(free-form·댕글링 SRO 차단).
    for o in objs:
        if str(o.get("type")) != "relationship":
            continue
        if o.get("relationship_type") not in _STD_REL_TYPES:
            continue  # free-form relationship_type 차단.
        if (
            str(o.get("source_ref")) in surviving
            and str(o.get("target_ref")) in surviving
        ):
            scrubbed.append(_scrub(o))

    return {
        "type": "bundle",
        "id": _sid("bundle", f"partner:{tier}:{bundle.get('id')}"),
        "objects": [stmt, *scrubbed],
    }
