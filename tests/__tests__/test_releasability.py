"""JADC2 releasability — allowlist·OPSEC no-leak·댕글링·fail-safe·순수."""

import copy
import json

import pytest

from core.exceptions import PolicyError
from core.models import DiamondEvent
from core.releasability import ReleasabilityPolicy, for_partner
from core.stix_export import StixExporter

_TS = "2026-07-09T00:00:00Z"


def _objs(bundle: dict[str, object]) -> list[dict[str, object]]:
    raw = bundle.get("objects")
    return [o for o in raw if isinstance(o, dict)] if isinstance(raw, list) else []


def _policy() -> ReleasabilityPolicy:
    return ReleasabilityPolicy.from_yaml()


def _internal_bundle() -> dict[str, object]:
    """내부 번들 — identity·threat-actor(내부라벨)·attack-pattern·indicator."""
    diamond = DiamondEvent(
        adversary="APT-SAT-INTERNAL",
        capabilities=["T1078"],
        infrastructure=["203.0.113.5"],
    )
    b = StixExporter(tlp="amber").from_diamond(diamond, _TS)
    assert b is not None
    return b


def _types(bundle: dict[str, object]) -> set[str]:
    return {str(o.get("type")) for o in _objs(bundle)}


class TestAllowlist:
    def test_only_release_types_survive(self) -> None:
        """FVEY=attack-pattern만 — identity/actor/indicator drop(default-deny)."""
        out = for_partner(_internal_bundle(), "FVEY", _policy(), _TS)
        assert out is not None
        t = _types(out)
        assert "attack-pattern" in t
        assert "identity" not in t  # 우리 조직 identity drop
        assert "threat-actor" not in t  # 내부 actor 라벨 drop
        assert "indicator" not in t  # IOC 미분류 — 전 티어 제외(Codex Critical)

    def test_nato_attack_pattern_only(self) -> None:
        out = for_partner(_internal_bundle(), "NATO", _policy(), _TS)
        assert out is not None
        assert "indicator" not in _types(out)

    def test_input_marking_dropped(self) -> None:
        """입력 내부 marking-definition 통과 금지 — 출력엔 우리 statement 만(Codex)."""
        b = _internal_bundle()
        objs = b["objects"]
        assert isinstance(objs, list)
        objs.append(
            {
                "type": "marking-definition",
                "id": "marking-definition--dead0000",
                "definition_type": "statement",
                "definition": {"statement": "INTERNAL ONLY MUAV"},
            }
        )
        out = for_partner(b, "FVEY", _policy(), _TS)
        assert out is not None
        blob = json.dumps(out, ensure_ascii=False)
        assert "INTERNAL ONLY MUAV" not in blob and "dead0000" not in blob
        md = [o for o in _objs(out) if o.get("type") == "marking-definition"]
        assert len(md) == 1  # 우리 statement 만

    def test_only_internal_marking_is_none(self) -> None:
        """내부 marking 만 있는 번들 → None(empty-check 우회 금지, Codex)."""
        b: dict[str, object] = {
            "type": "bundle",
            "id": "bundle--x",
            "objects": [
                {
                    "type": "marking-definition",
                    "id": "marking-definition--z",
                    "definition_type": "statement",
                    "definition": {"statement": "SECRET"},
                }
            ],
        }
        assert for_partner(b, "FVEY", _policy(), _TS) is None

    def test_external_references_nested_scrub(self) -> None:
        """external_references 중첩 allowlist — url/desc drop, external_id 유지."""
        b = _internal_bundle()
        for o in _objs(b):
            if o.get("type") == "attack-pattern":
                refs = o.get("external_references")
                assert isinstance(refs, list)
                refs[0]["url"] = "https://internal.mil/MUAV-AKS-001"
                refs[0]["description"] = "내부 SATCOM 임무"
        out = for_partner(b, "FVEY", _policy(), _TS)
        assert out is not None
        blob = json.dumps(out, ensure_ascii=False)
        assert "MUAV-AKS-001" not in blob and "내부 SATCOM" not in blob
        assert "T1078" in blob  # 공개 external_id 는 유지

    def test_attack_pattern_name_dropped(self) -> None:
        """free-form name 제외 — 내부 문자열 잠입 차단(Codex 재검토)."""
        b = _internal_bundle()
        for o in _objs(b):
            if o.get("type") == "attack-pattern":
                o["name"] = "SECRET-MUAV-임무 T1078"
        out = for_partner(b, "FVEY", _policy(), _TS)
        assert out is not None
        blob = json.dumps(out, ensure_ascii=False)
        assert "SECRET-MUAV" not in blob  # name drop
        assert "T1078" in blob  # external_id 유지

    def test_nonmitre_external_id_dropped(self) -> None:
        """비-MITRE external_id/source → ref 제거 → 공개참조 없는 ap 제외."""
        b = _internal_bundle()
        for o in _objs(b):
            if o.get("type") == "attack-pattern":
                o["external_references"] = [
                    {"source_name": "internal-db", "external_id": "SECRET-999"}
                ]
        out = for_partner(b, "FVEY", _policy(), _TS)
        if out is not None:
            assert "SECRET-999" not in json.dumps(out, ensure_ascii=False)

    def test_freeform_relationship_type_dropped(self) -> None:
        """비표준 relationship_type → 관계 제거(free-form 차단)."""
        ap = "attack-pattern--aaaa"
        b: dict[str, object] = {
            "type": "bundle",
            "id": "bundle--r",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": ap,
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1078"}
                    ],
                },
                {
                    "type": "relationship",
                    "id": "relationship--x",
                    "relationship_type": "내부-비밀-연결",
                    "source_ref": ap,
                    "target_ref": ap,
                },
            ],
        }
        out = for_partner(b, "FVEY", _policy(), _TS)
        assert out is not None
        assert "내부-비밀-연결" not in json.dumps(out, ensure_ascii=False)
        assert not [o for o in _objs(out) if o.get("type") == "relationship"]


class TestNoLeak:
    def test_no_internal_identifiers_leak(self) -> None:
        """OPSEC 핵심 — 파생 번들 어디에도 내부 식별자·라벨·created_by_ref 없음."""
        out = for_partner(_internal_bundle(), "FVEY", _policy(), _TS)
        assert out is not None
        blob = json.dumps(out, ensure_ascii=False)
        assert "APT-SAT-INTERNAL" not in blob  # 내부 actor 라벨
        assert "created_by_ref" not in blob  # 우리 identity 참조
        assert "관측 IOC" not in blob  # 내부 한글 라벨(indicator.name)
        assert "identity--" not in blob  # 우리 조직 identity id

    def test_object_marking_refs_reset(self) -> None:
        """object_marking_refs 는 [TLP, statement]로 재설정 — 잔여 ref 없음."""
        out = for_partner(_internal_bundle(), "FVEY", _policy(), _TS)
        assert out is not None
        for o in _objs(out):
            if isinstance(o, dict) and o.get("type") != "marking-definition":
                refs = o.get("object_marking_refs")
                assert isinstance(refs, list) and len(refs) == 2

    def test_field_allowlist_drops_extra(self) -> None:
        """주입된 위험 필드(x_secret/description)도 field allowlist 로 drop."""
        b = _internal_bundle()
        for o in _objs(b):
            if isinstance(o, dict) and o.get("type") == "attack-pattern":
                o["x_internal_asset"] = "MUAV-AKS-001"
                o["description"] = "내부 임무 SATCOM"
        out = for_partner(b, "FVEY", _policy(), _TS)
        assert out is not None
        blob = json.dumps(out, ensure_ascii=False)
        assert "MUAV-AKS-001" not in blob and "내부 임무" not in blob


class TestDangling:
    def test_relationship_pruned_when_ref_stripped(self) -> None:
        """indicator→actor 관계 — actor drop 시 관계도 제거(댕글링 방지)."""
        out = for_partner(_internal_bundle(), "FVEY", _policy(), _TS)
        assert out is not None
        objs = _objs(out)
        ids = {o["id"] for o in objs}
        for o in objs:
            if isinstance(o, dict) and o.get("type") == "relationship":
                assert o["source_ref"] in ids and o["target_ref"] in ids


class TestMarking:
    def test_statement_marking_added(self) -> None:
        out = for_partner(_internal_bundle(), "FVEY", _policy(), _TS)
        assert out is not None
        md = [o for o in _objs(out) if o.get("type") == "marking-definition"]
        assert len(md) == 1
        assert md[0]["definition_type"] == "statement"
        assert md[0]["definition"] == {"statement": "REL TO FVEY"}


class TestFailSafe:
    def test_unknown_tier_none(self) -> None:
        assert for_partner(_internal_bundle(), "ENEMY", _policy(), _TS) is None

    def test_empty_after_strip_none(self) -> None:
        """release_types 로 남는 데이터 0 → None."""
        # actor+ioc만 + NATO(attack-pattern only) → indicator drop → 빈 데이터.
        d = DiamondEvent(adversary="X", capabilities=[], infrastructure=["203.0.113.9"])
        b = StixExporter().from_diamond(d, _TS)
        assert b is not None
        assert for_partner(b, "NATO", _policy(), _TS) is None

    def test_input_bundle_not_mutated(self) -> None:
        """순수 — 입력 번들 무변이(내부 원본 오염 금지)."""
        b = _internal_bundle()
        snapshot = copy.deepcopy(b)
        for_partner(b, "FVEY", _policy(), _TS)
        assert b == snapshot


class TestPolicy:
    def test_missing_policy_raises(self) -> None:
        with pytest.raises(PolicyError):
            ReleasabilityPolicy.from_yaml("/tmp/__no_rel__.yaml")

    def test_extra_field_rejected(self) -> None:
        """미지 필드 거부 — fail-closed(광범위 릴리스 폴백 차단)."""
        with pytest.raises(Exception):  # noqa: B017 - ValidationError
            ReleasabilityPolicy.model_validate(
                {"partner_tiers": {"X": {"caveat": "c", "bogus": 1}}}
            )
