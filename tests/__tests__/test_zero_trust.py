"""ZTMM self-attested 통제 매핑 — 근거강제·씨어터방지(CISA ZTMM 2.0)."""

from core.models import ZtAttestation
from core.zero_trust import ZtAssessor, _effective, load_zt_mapping


def _att(**kw: object) -> ZtAttestation:
    base: dict[str, object] = {
        "name": "X",
        "kind": "pillar",
        "declared": "advanced",
        "evidence": "implemented_static",
    }
    base.update(kw)
    a = ZtAttestation.model_validate(base)
    return ZtAttestation(
        name=a.name,
        kind=a.kind,
        declared=a.declared,
        effective=_effective(a.declared, a.evidence),
        control_ref=a.control_ref,
        evidence=a.evidence,
    )


class TestEvidenceGate:
    def test_verified_keeps_declared(self) -> None:
        assert _effective("advanced", "implemented_static") == "advanced"
        assert _effective("optimal", "verified_runtime") == "optimal"

    def test_unverified_high_capped(self) -> None:
        """근거 없는 advanced/optimal → initial 로 cap(거버넌스 씨어터 봉쇄)."""
        assert _effective("advanced", "self_attested") == "initial"
        assert _effective("optimal", "self_attested") == "initial"

    def test_low_unaffected(self) -> None:
        assert _effective("initial", "self_attested") == "initial"
        assert _effective("traditional", "self_attested") == "traditional"


class TestAssess:
    def test_theater_finding(self) -> None:
        a = ZtAssessor(
            [_att(name="Bogus", declared="optimal", evidence="self_attested")]
        )
        r = a.assess()
        assert r.capabilities[0].effective == "initial"
        assert any("unverified_maturity_claim" in f for f in r.findings)

    def test_verified_no_finding(self) -> None:
        a = ZtAssessor([_att(declared="advanced", evidence="implemented_static")])
        assert a.assess().findings == []

    def test_minimum_effective_weakest_link(self) -> None:
        a = ZtAssessor(
            [
                _att(name="A", declared="optimal", evidence="implemented_static"),
                _att(name="B", declared="initial", evidence="self_attested"),
            ]
        )
        assert a.assess().minimum_effective == "initial"

    def test_measurement_status_labeled(self) -> None:
        r = load_zt_mapping()
        assert r.measurement_status == "not_measured"
        assert r.assessment_basis == "self_attested_policy_yaml"


class TestDefaultPolicy:
    def test_5_pillars_3_cross(self) -> None:
        r = load_zt_mapping()
        pillars = [c for c in r.capabilities if c.kind == "pillar"]
        cross = [c for c in r.capabilities if c.kind == "cross_cutting"]
        assert len(pillars) == 5 and len(cross) == 3

    def test_default_no_theater(self) -> None:
        """기본 매핑은 정직 — 근거 없는 고등급 주장 없음(findings 빈)."""
        assert load_zt_mapping().findings == []

    def test_control_refs_present(self) -> None:
        for c in load_zt_mapping().capabilities:
            if c.evidence == "implemented_static":
                assert c.control_ref  # 근거 검증분은 감사 참조 필수

    def test_graceful_degraded(self) -> None:
        from core.exceptions import PolicyError

        try:
            ZtAssessor.from_yaml("/tmp/__no_ztmm__.yaml")
            raise AssertionError("should raise")
        except PolicyError:
            pass
