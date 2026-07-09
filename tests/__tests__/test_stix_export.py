"""STIX 2.1 TI 생산 — DiamondEvent → 공유 bundle(OPSEC·TLP·결정론)."""

from core.models import CampaignMatch, DiamondEvent
from core.stix_export import StixExporter, _ioc_pattern

_TS = "2026-07-09T00:00:00Z"


def _diamond(**kw: object) -> DiamondEvent:
    base: dict[str, object] = {
        "adversary": "APT-X",
        "capabilities": ["T1071"],
        "infrastructure": ["1.2.3.4"],
        "victim": "UAV-ANHEUNG-07",
        "victim_tier": "T1-Critical",
        "mission_phase": "on-station",
    }
    base.update(kw)
    return DiamondEvent.model_validate(base)


def _bundle(**kw: object) -> dict:
    b = StixExporter().from_diamond(_diamond(**kw), _TS)
    assert b is not None
    return b


def _objs(b: dict, otype: str) -> list[dict]:
    return [o for o in b["objects"] if o["type"] == otype]


class TestSDOs:
    def test_threat_actor(self) -> None:
        ta = _objs(_bundle(), "threat-actor")
        assert len(ta) == 1 and ta[0]["name"] == "APT-X"
        assert ta[0]["spec_version"] == "2.1" and ta[0]["created"] == _TS

    def test_attack_pattern_attack_ref(self) -> None:
        ap = _objs(_bundle(), "attack-pattern")[0]
        assert ap["external_references"][0]["external_id"] == "T1071"
        assert ap["name"] == "MITRE ATT&CK T1071"

    def test_indicator_required_fields(self) -> None:
        ind = _objs(_bundle(), "indicator")[0]
        assert ind["pattern_type"] == "stix" and ind["valid_from"] == _TS
        assert ind["pattern"] == "[ipv4-addr:value = '1.2.3.4']"

    def test_producer_identity(self) -> None:
        ident = _objs(_bundle(), "identity")
        assert len(ident) == 1 and ident[0]["identity_class"] == "organization"


class TestOpsec:
    def test_victim_never_exported(self) -> None:
        """Critical — 내부 자산 id/tier/임무단계 미노출."""
        b = _bundle()
        blob = str(b)
        assert "UAV-ANHEUNG-07" not in blob
        assert "T1-Critical" not in blob
        assert "on-station" not in blob


class TestTlp:
    def test_all_objects_marked(self) -> None:
        b = _bundle()
        assert all("object_marking_refs" in o for o in b["objects"])

    def test_amber_default(self) -> None:
        ta = _objs(_bundle(), "threat-actor")[0]
        assert "f88d31f6" in ta["object_marking_refs"][0]  # 표준 AMBER

    def test_red_selectable(self) -> None:
        b = StixExporter(tlp="red").from_diamond(_diamond(), _TS)
        assert b is not None
        ta = _objs(b, "threat-actor")[0]
        assert "5e57c739" in ta["object_marking_refs"][0]  # 표준 RED


class TestRelationships:
    def test_uses_and_indicates(self) -> None:
        rels = _objs(_bundle(), "relationship")
        uses = [r for r in rels if r["relationship_type"] == "uses"]
        ind = [r for r in rels if r["relationship_type"] == "indicates"]
        assert uses and uses[0]["source_ref"].startswith("threat-actor--")
        # 방향: source=indicator, target=threat-actor
        assert ind and ind[0]["source_ref"].startswith("indicator--")
        assert ind[0]["target_ref"].startswith("threat-actor--")


class TestIocClassify:
    def test_ipv4_and_cidr(self) -> None:
        assert _ioc_pattern("1.2.3.4") == "[ipv4-addr:value = '1.2.3.4']"
        assert _ioc_pattern("10.0.0.0/24") == "[ipv4-addr:value = '10.0.0.0/24']"

    def test_domain(self) -> None:
        assert _ioc_pattern("evil.com") == "[domain-name:value = 'evil.com']"

    def test_hashes(self) -> None:
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        assert _ioc_pattern(md5) == f"[file:hashes.'MD5' = '{md5}']"

    def test_unknown_skipped(self) -> None:
        assert _ioc_pattern("garbage!!") is None
        assert _ioc_pattern("") is None

    def test_hyphen_edge_domain_rejected(self) -> None:
        """Codex Med — 하이픈 시작/끝 라벨 도메인 무효(skip)."""
        assert _ioc_pattern("-a.com") is None
        assert _ioc_pattern("a-.com") is None
        assert _ioc_pattern("a-b.com") == "[domain-name:value = 'a-b.com']"

    def test_bundle_skips_bad_ioc(self) -> None:
        b = _bundle(infrastructure=["1.2.3.4", "garbage!!"])
        assert len(_objs(b, "indicator")) == 1  # bad IOC skip


class TestCampaign:
    def _cm(self, **kw: object) -> CampaignMatch:
        base: dict[str, object] = {
            "chain_id": "C3",
            "name": "GCS 탈취 흐름",
            "matched": 2,
            "total": 4,
            "next_expected": "S12-GCS-HIJACK",
            "severity": "high",
        }
        base.update(kw)
        return CampaignMatch.model_validate(base)

    def test_campaign_sdo(self) -> None:
        b = StixExporter().from_campaign(self._cm(), _TS)
        assert b is not None
        camp = _objs(b, "campaign")[0]
        assert camp["name"] == "GCS 탈취 흐름"
        assert "2/4" in camp["objective"] and camp["spec_version"] == "2.1"
        assert "object_marking_refs" in camp

    def test_next_expected_omitted(self) -> None:
        """OPSEC — 내부 탐지 시나리오 id 미노출."""
        b = StixExporter().from_campaign(self._cm(), _TS)
        assert b is not None and "S12-GCS-HIJACK" not in str(b)

    def test_empty_chain_none(self) -> None:
        assert StixExporter().from_campaign(self._cm(chain_id=""), _TS) is None

    def test_deterministic(self) -> None:
        a = StixExporter().from_campaign(self._cm(), _TS)
        b = StixExporter().from_campaign(self._cm(), _TS)
        assert a is not None and b is not None and a["id"] == b["id"]


class TestDeterminismAndEmpty:
    def test_deterministic_ids(self) -> None:
        a = StixExporter().from_diamond(_diamond(), _TS)
        b = StixExporter().from_diamond(_diamond(), _TS)
        assert a is not None and b is not None and a["id"] == b["id"]

    def test_empty_diamond_none(self) -> None:
        assert StixExporter().from_diamond(DiamondEvent(), _TS) is None

    def test_invalid_only_iocs_none(self) -> None:
        """Codex Low — IOC 전부 무효(위협 SDO 0) → identity-only 아닌 None."""
        d = DiamondEvent(infrastructure=["garbage!!", "also bad"])
        assert StixExporter().from_diamond(d, _TS) is None
