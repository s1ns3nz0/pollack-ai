"""취약점(CVE) 컨텍스트 도구 — CISA KEV 악용여부 + NVD 심각도.

경보가 참조하는 CVE 에 대해 "실제 악용 중인가(KEV)"와 "얼마나 심각한가(CVSS)"를
보강한다. KEV 등재 = 능동 악용 → 최우선. 모든 어댑터는 동일
`aenrich(cves) -> list[VulnFinding]` 계약을 따른다(Protocol 주입):

- `StubVuln`       : 오프라인 결정론(데모/테스트).
- `CisaKevTool`    : CISA KEV 카탈로그(공개 JSON) — 악용 여부.
- `NvdTool`        : NVD CVE API — CVSS 점수/심각도.
- `CompositeVuln`  : 여러 소스를 묶어 CVE 별 1건으로 병합(KEV 악용 OR + 최대 CVSS).
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Protocol, runtime_checkable
from urllib.parse import quote

import httpx

from core.exceptions import VulnLookupError
from core.models import VulnFinding
from core.settings import Settings, get_settings
from utils.logging import get_logger

_logger = get_logger("vuln_tool")


@runtime_checkable
class VulnEnricher(Protocol):
    """취약점 컨텍스트 어댑터 계약."""

    async def aenrich(self, cves: list[str]) -> list[VulnFinding]:
        """CVE 목록의 악용여부/심각도를 보강해 반환한다."""
        ...


class StubVuln:
    """오프라인 결정론 취약점 컨텍스트(데모용).

    Args:
        exploited: KEV 악용으로 표시할 CVE 집합.
        scores: CVE→CVSS 점수 매핑(미지정 CVE 는 0.0).
    """

    def __init__(
        self,
        exploited: frozenset[str] | None = None,
        scores: dict[str, float] | None = None,
    ) -> None:
        self._exploited = exploited or frozenset()
        self._scores = scores or {}

    async def aenrich(self, cves: list[str]) -> list[VulnFinding]:
        """CVE 목록을 결정론적으로 보강한다."""
        return [
            VulnFinding(
                cve=cve,
                known_exploited=cve in self._exploited,
                cvss_score=self._scores.get(cve, 0.0),
                severity=_severity_of(self._scores.get(cve, 0.0)),
                source="stub-vuln",
            )
            for cve in cves
        ]


class CisaKevTool:
    """CISA KEV 카탈로그 어댑터 — CVE 가 실제 악용 중(등재)인지.

    Args:
        settings: 전역 설정(미지정 시 환경 로드). `cisa_kev_url`(공개) 사용.
        client_factory: 비동기 HTTP 클라이언트 팩토리(테스트 주입용).
    """

    def __init__(
        self, settings: Settings | None = None, client_factory: object | None = None
    ) -> None:
        self._settings = settings or get_settings()
        self._client_factory = client_factory

    def _make_client(self) -> httpx.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory()  # type: ignore[operator,no-any-return]
        return httpx.AsyncClient(timeout=self._settings.vuln_timeout_seconds)

    async def aenrich(self, cves: list[str]) -> list[VulnFinding]:
        """KEV 카탈로그를 조회해 CVE 별 악용 여부를 표시한다.

        Raises:
            VulnLookupError: 카탈로그 조회/검증 실패 시(컴포지트가 건너뜀).
        """
        if not cves:
            return []
        exploited = await self._fetch_catalog()
        return [
            VulnFinding(
                cve=cve,
                known_exploited=cve in exploited,
                source="cisa-kev",
            )
            for cve in cves
        ]

    async def _fetch_catalog(self) -> set[str]:
        """KEV 카탈로그에서 악용 CVE ID 집합을 가져온다."""
        try:
            async with self._make_client() as client:
                resp = await client.get(self._settings.cisa_kev_url)
                resp.raise_for_status()
                body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise VulnLookupError(f"CISA KEV 카탈로그 조회 실패: {exc}") from exc
        if not isinstance(body, dict):
            raise VulnLookupError("CISA KEV 응답 형식 검증 실패")
        vulns = body.get("vulnerabilities")
        if not isinstance(vulns, list):
            raise VulnLookupError("CISA KEV vulnerabilities 누락")
        return {
            v["cveID"]
            for v in vulns
            if isinstance(v, dict) and isinstance(v.get("cveID"), str)
        }


class NvdTool:
    """NVD CVE API 어댑터 — CVSS 점수/심각도(API 키 선택).

    Args:
        settings: 전역 설정(미지정 시 환경 로드).
        client_factory: 비동기 HTTP 클라이언트 팩토리(테스트 주입용).
    """

    def __init__(
        self, settings: Settings | None = None, client_factory: object | None = None
    ) -> None:
        self._settings = settings or get_settings()
        self._client_factory = client_factory

    def _make_client(self) -> httpx.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory()  # type: ignore[operator,no-any-return]
        return httpx.AsyncClient(timeout=self._settings.vuln_timeout_seconds)

    async def aenrich(self, cves: list[str]) -> list[VulnFinding]:
        """CVE 별 CVSS 심각도를 조회한다(키 없으면 낮은 레이트리밋)."""
        if not cves:
            return []
        key = self._settings.nvd_api_key.get_secret_value()
        headers = {"apiKey": key} if key else {}
        findings: list[VulnFinding] = []
        async with self._make_client() as client:
            for cve in cves:
                findings.append(await self._lookup(client, cve, headers))
        return findings

    async def _lookup(
        self, client: httpx.AsyncClient, cve: str, headers: dict[str, str]
    ) -> VulnFinding:
        url = f"{self._settings.nvd_base_url}?cveId={quote(cve)}"
        try:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            _logger.warning("NVD 조회 실패(%s): %s", cve, exc)
            return VulnFinding(cve=cve, source="nvd")
        return self.parse(cve, body)

    @staticmethod
    def parse(cve: str, body: object) -> VulnFinding:
        """NVD 응답에서 CVSS(v3.1→v3.0→v2 순) 점수/심각도를 추출한다."""
        score, severity = _extract_cvss(body)
        return VulnFinding(cve=cve, cvss_score=score, severity=severity, source="nvd")


class BoundedVuln:
    """VulnEnricher 를 벽시계 데드라인으로 감싸는 어댑터(fail-open).

    report-side SBOM 검증 등 InvestigationAgent 의 `_bounded` 밖에서 `vuln.aenrich` 를
    직접 호출하는 경로도 데드라인/graceful fallback 을 갖게 한다(Codex diff High).
    초과·오류 시 빈 목록 반환(비crash) — 외부 조회가 hotpath 를 무한정 붙잡지 않는다.

    Args:
        inner: 감쌀 취약점 어댑터.
        deadline_seconds: 벽시계 데드라인(초).
    """

    def __init__(self, inner: VulnEnricher, deadline_seconds: float) -> None:
        self._inner = inner
        self._deadline = deadline_seconds

    async def aenrich(self, cves: list[str]) -> list[VulnFinding]:
        """데드라인 내 조회. 초과·조회오류 시 빈 목록(fail-open)."""
        try:
            return await asyncio.wait_for(
                self._inner.aenrich(cves), timeout=self._deadline
            )
        except (TimeoutError, VulnLookupError) as exc:
            _logger.warning("취약점 보강 데드라인/오류, 강등(fail-open): %s", exc)
            return []


class CompositeVuln:
    """여러 취약점 소스를 묶어 CVE 별 1건으로 병합한다.

    동시 조회 후, CVE 별로 악용여부(any True)·최대 CVSS·출처 합침으로 합친다. 한
    소스 실패는 건너뛰고 나머지로 계속한다(가용성).

    Args:
        sources: 묶을 취약점 어댑터들.
    """

    def __init__(self, sources: Sequence[VulnEnricher]) -> None:
        self._sources = list(sources)

    async def aenrich(self, cves: list[str]) -> list[VulnFinding]:
        """모든 소스를 동시 조회 후 CVE 별로 병합한다."""
        if not cves or not self._sources:
            return []
        per_source = await asyncio.gather(*(self._safe(s, cves) for s in self._sources))
        flat = [finding for result in per_source for finding in result]
        return self._merge(flat)

    async def _safe(self, source: VulnEnricher, cves: list[str]) -> list[VulnFinding]:
        """한 소스 조회. 실패 시 빈 목록으로 강등."""
        try:
            return await source.aenrich(cves)
        except VulnLookupError as exc:
            _logger.warning(
                "취약점 소스 조회 실패, 건너뜀: %s (%s)", type(source).__name__, exc
            )
            return []

    @staticmethod
    def _merge(findings: list[VulnFinding]) -> list[VulnFinding]:
        """CVE 별로 악용여부 OR + 최대 CVSS + 출처 합침."""
        merged: dict[str, VulnFinding] = {}
        sources: dict[str, set[str]] = {}
        for f in findings:
            sources.setdefault(f.cve, set()).add(f.source)
            current = merged.get(f.cve)
            if current is None:
                merged[f.cve] = f.model_copy()
                continue
            best_score = max(current.cvss_score, f.cvss_score)
            severity = (
                f.severity if f.cvss_score >= current.cvss_score else current.severity
            )
            merged[f.cve] = current.model_copy(
                update={
                    "known_exploited": current.known_exploited or f.known_exploited,
                    "cvss_score": best_score,
                    "severity": severity or current.severity,
                }
            )
        return [
            f.model_copy(update={"source": ",".join(sorted(sources[cve]))})
            for cve, f in merged.items()
        ]


def _severity_of(score: float) -> str:
    """CVSS 점수 → 심각도 등급(NVD 기준)."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return ""


def _extract_cvss(body: object) -> tuple[float, str]:
    """NVD 응답에서 CVSS(v3.1→v3.0→v2) baseScore/baseSeverity 안전 추출."""
    if not isinstance(body, dict):
        return 0.0, ""
    vulns = body.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        return 0.0, ""
    first = vulns[0]
    cve = first.get("cve") if isinstance(first, dict) else None
    metrics = cve.get("metrics") if isinstance(cve, dict) else None
    if not isinstance(metrics, dict):
        return 0.0, ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        data = entries[0].get("cvssData") if isinstance(entries[0], dict) else None
        if not isinstance(data, dict):
            continue
        raw_score = data.get("baseScore")
        score = float(raw_score) if isinstance(raw_score, (int, float)) else 0.0
        sev = data.get("baseSeverity")
        severity = sev if isinstance(sev, str) else _severity_of(score)
        return score, severity
    return 0.0, ""
