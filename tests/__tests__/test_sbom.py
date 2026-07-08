"""SBOMVerifier 테스트 — 미등록/변조/취약 3요소 공급망 검증."""

import pytest

from core.models import SbomComponent, VulnFinding
from core.sbom import ApprovedSbom, SBOMVerifier


class _StubVuln:
    """CVE → known_exploited 결정론 stub."""

    def __init__(self, exploited: set[str]) -> None:
        self._exploited = exploited

    async def aenrich(self, cves: list[str]) -> list[VulnFinding]:
        return [
            VulnFinding(cve=c, known_exploited=c in self._exploited, source="stub")
            for c in cves
        ]


class TestApprovedSbom:
    def test_loads_from_yaml(self) -> None:
        sbom = ApprovedSbom.from_yaml()
        assert sbom.approved("px4-autopilot") is not None

    def test_approved_has_version_hash(self) -> None:
        sbom = ApprovedSbom.from_yaml()

        entry = sbom.approved("px4-autopilot")

        assert entry is not None
        assert entry["version"] == "1.14.3"
        assert entry["hash"].startswith("sha256:")


def _comp(name: str, **kw: object) -> SbomComponent:
    return SbomComponent(name=name, **kw)  # type: ignore[arg-type]


class TestSBOMVerifier:
    def _verifier(self) -> SBOMVerifier:
        return SBOMVerifier(ApprovedSbom.from_yaml())

    @pytest.mark.asyncio
    async def test_approved_component_clean(self) -> None:
        """승인 목록 일치(버전+해시) → 위험 없음."""
        comp = _comp("px4-autopilot", version="1.14.3", hash="sha256:a1b2c3d4e5f6")

        findings = await self._verifier().averify([comp])

        assert findings == []

    @pytest.mark.asyncio
    async def test_unregistered_component(self) -> None:
        """승인 목록에 없는 컴포넌트 → unregistered."""
        comp = _comp("rogue-lib", version="9.9.9")

        findings = await self._verifier().averify([comp])

        assert len(findings) == 1
        assert findings[0].issue == "unregistered"

    @pytest.mark.asyncio
    async def test_tampered_hash(self) -> None:
        """승인 컴포넌트지만 해시 불일치 → tampered."""
        comp = _comp("px4-autopilot", version="1.14.3", hash="sha256:BADHASH")

        findings = await self._verifier().averify([comp])

        assert len(findings) == 1
        assert findings[0].issue == "tampered"

    @pytest.mark.asyncio
    async def test_version_mismatch(self) -> None:
        """승인 컴포넌트지만 버전 불일치 → version_mismatch(다운그레이드/변조)."""
        comp = _comp("px4-autopilot", version="1.0.0", hash="sha256:a1b2c3d4e5f6")

        findings = await self._verifier().averify([comp])

        assert any(f.issue == "version_mismatch" for f in findings)

    @pytest.mark.asyncio
    async def test_missing_observed_hash_is_tampered(self) -> None:
        """승인 컴포넌트는 해시 필수 — 관측 해시 없으면 검증 불가=tampered."""
        comp = _comp("px4-autopilot", version="1.14.3")  # hash 없음

        findings = await self._verifier().averify([comp])

        assert any(f.issue == "tampered" for f in findings)

    @pytest.mark.asyncio
    async def test_vulnerable_via_vuln_tool(self) -> None:
        """승인·무결하나 선언 CVE 가 악용중(KEV) → vulnerable."""
        comp = _comp(
            "px4-autopilot",
            version="1.14.3",
            hash="sha256:a1b2c3d4e5f6",
            cves=["CVE-2024-1"],
        )
        vuln = _StubVuln({"CVE-2024-1"})

        findings = await self._verifier().averify([comp], vuln=vuln)

        assert any(f.issue == "vulnerable" and f.cve == "CVE-2024-1" for f in findings)

    @pytest.mark.asyncio
    async def test_non_exploited_cve_clean(self) -> None:
        """선언 CVE 지만 미악용이면 vulnerable 아님."""
        comp = _comp(
            "px4-autopilot",
            version="1.14.3",
            hash="sha256:a1b2c3d4e5f6",
            cves=["CVE-2024-2"],
        )
        vuln = _StubVuln(set())  # 아무것도 악용 안 됨

        findings = await self._verifier().averify([comp], vuln=vuln)

        assert not any(f.issue == "vulnerable" for f in findings)

    @pytest.mark.asyncio
    async def test_no_vuln_tool_skips_cve(self) -> None:
        """vuln_tool 미주입 시 CVE 검사 스킵(승인+해시만)."""
        comp = _comp(
            "px4-autopilot",
            version="1.14.3",
            hash="sha256:a1b2c3d4e5f6",
            cves=["CVE-2024-1"],
        )

        findings = await self._verifier().averify([comp])

        assert findings == []
