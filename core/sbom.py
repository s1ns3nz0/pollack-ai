"""공급망 보안 — SBOM 3요소 검증(미등록 / 변조 / 취약).

NIST SSDF / SLSA 공급망 보안의 결정론 구현. 관측된 SBOM 컴포넌트를 승인 목록
(`approved-sbom.yaml`)과 대조해:

  ① unregistered — 승인 목록에 없는 컴포넌트(비인가 공급망 유입)
  ② tampered     — 승인 컴포넌트지만 해시 불일치(변조·서명 위반)
  ③ vulnerable   — 컴포넌트 선언 CVE 가 악용중(vuln_tool 로 CISA KEV 조회)

를 판정한다. CVE 조회는 기존 VulnContext(vuln_tool) 를 옵션 주입 — 미주입 시
CVE 검사를 스킵해 승인/해시 검증만 결정론으로 수행한다. S4 펌웨어 변조 시나리오·
STRIDE Tampering·kill chain Persistence 와 정합.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from core.models import SbomComponent, SbomFinding, VulnFinding
from core.policy_loader import load_policy_mapping, require_mapping

_POLICY = Path(__file__).resolve().parent / "policy" / "approved-sbom.yaml"


@runtime_checkable
class VulnLookup(Protocol):
    """컴포넌트 CVE 악용여부 조회 계약(VulnContext 호환)."""

    async def aenrich(self, cves: list[str]) -> list[VulnFinding]:
        """CVE 목록의 악용여부/심각도를 조회한다."""
        ...


class ApprovedSbom:
    """approved-sbom.yaml 로더 — 승인 컴포넌트 version/hash 기준."""

    def __init__(self, components: dict[str, dict[str, str]]) -> None:
        self._components = components

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> ApprovedSbom:
        """승인 SBOM YAML 을 적재한다.

        Args:
            path: 정책 경로. 생략 시 기본 approved-sbom.yaml.

        Returns:
            로드된 ApprovedSbom.

        Raises:
            PolicyError: 파일 부재/파싱 실패/구조 불일치 시.
        """
        raw = load_policy_mapping(path, _POLICY, label="승인 SBOM")
        components: dict[str, dict[str, str]] = {}
        for name, cell in require_mapping(
            raw.get("components"), label="SBOM components"
        ).items():
            if isinstance(cell, dict):
                components[str(name)] = {
                    "version": str(cell.get("version", "")),
                    "hash": str(cell.get("hash", "")),
                }
        return cls(components)

    def approved(self, name: str) -> dict[str, str] | None:
        """컴포넌트 승인 항목(version/hash)을 반환한다(미승인이면 None)."""
        return self._components.get(name)


class SBOMVerifier:
    """SBOM 공급망 3요소 검증기 — 미등록/변조/취약.

    Args:
        approved: 승인 SBOM 기준.
    """

    def __init__(self, approved: ApprovedSbom) -> None:
        self._approved = approved

    async def averify(
        self,
        components: list[SbomComponent],
        vuln: VulnLookup | None = None,
    ) -> list[SbomFinding]:
        """관측 컴포넌트를 승인 목록/해시/CVE 로 검증한다.

        Args:
            components: 관측 SBOM 컴포넌트.
            vuln: CVE 악용여부 조회기(옵션 — 미주입 시 CVE 검사 스킵).

        Returns:
            공급망 위험 목록(정상 컴포넌트는 미포함).
        """
        findings: list[SbomFinding] = []
        for comp in components:
            entry = self._approved.approved(comp.name)
            if entry is None:
                findings.append(
                    SbomFinding(
                        component=comp.name,
                        issue="unregistered",
                        detail=f"승인 SBOM 미등록 컴포넌트(v{comp.version})",
                    )
                )
                continue
            # 버전 불일치 — 다운그레이드/치환 공격(승인 버전 있을 때만 비교).
            if entry["version"] and comp.version != entry["version"]:
                findings.append(
                    SbomFinding(
                        component=comp.name,
                        issue="version_mismatch",
                        detail=(
                            f"버전 불일치 — 관측 v{comp.version} != "
                            f"승인 v{entry['version']}"
                        ),
                    )
                )
            # 해시 무결성 — 승인 컴포넌트는 해시 필수. 관측 해시 누락 시 검증
            # 불가로 간주해 tampered(fail-closed) — 빈 해시로 우회 못 하게.
            if entry["hash"]:
                if not comp.hash:
                    findings.append(
                        SbomFinding(
                            component=comp.name,
                            issue="tampered",
                            detail="관측 해시 누락 — 무결성 검증 불가(fail-closed)",
                        )
                    )
                elif comp.hash != entry["hash"]:
                    findings.append(
                        SbomFinding(
                            component=comp.name,
                            issue="tampered",
                            detail=(
                                f"해시 불일치 — 관측 {comp.hash} != "
                                f"승인 {entry['hash']}"
                            ),
                        )
                    )
            findings.extend(await self._check_cves(comp, vuln))
        return findings

    @staticmethod
    async def _check_cves(
        comp: SbomComponent, vuln: VulnLookup | None
    ) -> list[SbomFinding]:
        """컴포넌트 선언 CVE 중 악용중(KEV)인 것을 취약 위험으로 판정한다."""
        if vuln is None or not comp.cves:
            return []
        out: list[SbomFinding] = []
        for finding in await vuln.aenrich(comp.cves):
            if finding.known_exploited:
                out.append(
                    SbomFinding(
                        component=comp.name,
                        issue="vulnerable",
                        detail=f"악용중 CVE({finding.cve}) — 즉시 패치·격리",
                        cve=finding.cve,
                    )
                )
        return out
