"""외부 위협 인텔리전스(TI) IOC 조회 도구.

Investigation 이 경보의 IOC(해시/IP/도메인 등)를 외부 TI 로 보강한다. 모든 어댑터는
동일 `alookup(indicators) -> list[ThreatIntelFinding]` 계약을 따른다(Protocol 주입):

- `StubThreatIntel`  : 오프라인 결정론(데모/테스트).
- `VirusTotalTool`   : 실 VirusTotal v3 어댑터(httpx). 응답을 검증 후 채택.
- `CompositeThreatIntel`: 여러 소스(VT/OTX/AbuseIPDB/MISP/내부피드…)를 하나의
  `alookup` 뒤에 묶는 aggregator. 동시 조회 + 지표별 최악 판정 병합 + 소스별
  graceful degrade. Investigation 은 이 컴포지트 하나만 주입받으면 된다.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
import ipaddress
import re
from typing import Protocol, runtime_checkable
from urllib.parse import quote

import httpx

from core.exceptions import ThreatIntelError
from core.models import ThreatIntelFinding, TiVerdict
from core.settings import Settings, get_settings
from utils.logging import get_logger

_logger = get_logger("ti_tool")

# 지표별 병합 시 우선순위(악성이 가장 강함). 여러 소스 중 최악 판정을 채택.
_VERDICT_RANK: dict[TiVerdict, int] = {
    TiVerdict.MALICIOUS: 3,
    TiVerdict.SUSPICIOUS: 2,
    TiVerdict.CLEAN: 1,
    TiVerdict.UNKNOWN: 0,
}

# 데모용 알려진 악성/의심 IOC(실 배포 시 외부 TI API 응답으로 대체).
_DEFAULT_MALICIOUS = frozenset(
    {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4",  # 변조 펌웨어 해시(S4)
        "45.146.165.37",  # 비인가 GCS 접속 IP(S6)
        "com.tac.gcs.malic",  # 악성 모바일 GCS 앱 패키지(S11)
    }
)
_DEFAULT_SUSPICIOUS = frozenset(
    {
        "185.220.101.4",  # Tor 출구노드(정황상 의심)
    }
)


class StubThreatIntel:
    """오프라인 결정론 TI(데모용). 실 TI API 로 교체 가능.

    Args:
        malicious: 악성 판정할 IOC 집합(미지정 시 기본 데모 집합).
        suspicious: 의심 판정할 IOC 집합.
    """

    def __init__(
        self,
        malicious: frozenset[str] | None = None,
        suspicious: frozenset[str] | None = None,
    ) -> None:
        self._malicious = malicious if malicious is not None else _DEFAULT_MALICIOUS
        self._suspicious = suspicious if suspicious is not None else _DEFAULT_SUSPICIOUS

    async def alookup(self, indicators: list[str]) -> list[ThreatIntelFinding]:
        """IOC 목록의 평판을 조회해 결과를 반환한다.

        Args:
            indicators: 조회할 IOC(해시/IP/도메인/패키지명 등).

        Returns:
            각 IOC 의 `ThreatIntelFinding`(미등록은 UNKNOWN).
        """
        findings: list[ThreatIntelFinding] = []
        for ind in indicators:
            if ind in self._malicious:
                verdict, detail = TiVerdict.MALICIOUS, "알려진 악성 지표"
            elif ind in self._suspicious:
                verdict, detail = TiVerdict.SUSPICIOUS, "의심 정황 지표"
            else:
                verdict, detail = TiVerdict.UNKNOWN, "TI 미등록"
            findings.append(
                ThreatIntelFinding(
                    indicator=ind,
                    verdict=verdict,
                    source="stub-ti",
                    detail=detail,
                )
            )
        return findings


@runtime_checkable
class ThreatIntelSource(Protocol):
    """TI 어댑터 계약(컴포지트가 묶는 단위)."""

    async def alookup(self, indicators: list[str]) -> list[ThreatIntelFinding]:
        """IOC 목록의 평판을 조회해 반환한다."""
        ...


class CompositeThreatIntel:
    """여러 TI 소스를 하나의 `alookup` 뒤에 묶는 aggregator.

    각 소스를 동시(`asyncio.gather`)에 조회하고, 지표별로 *가장 위협적인* 판정을
    채택해 병합한다. 한 소스가 실패해도(예외) 그 소스만 건너뛰고 나머지로 계속한다
    (가용성 — Investigation 의 graceful degrade 와 정합). 새 TI(OTX/AbuseIPDB/MISP
    /내부피드)는 동일 계약 어댑터를 만들어 `sources` 에 추가하기만 하면 된다.

    Args:
        sources: 묶을 TI 어댑터들(순서 무관).
    """

    def __init__(self, sources: Sequence[ThreatIntelSource]) -> None:
        self._sources = list(sources)

    async def alookup(self, indicators: list[str]) -> list[ThreatIntelFinding]:
        """모든 소스를 동시 조회 후 지표별 최악 판정으로 병합한다.

        Args:
            indicators: 조회할 IOC 목록.

        Returns:
            지표별 1건으로 병합된 `ThreatIntelFinding` 목록(빈 입력/소스면 빈 목록).
        """
        if not indicators or not self._sources:
            return []
        per_source = await asyncio.gather(
            *(self._safe_lookup(s, indicators) for s in self._sources)
        )
        flat = [finding for result in per_source for finding in result]
        return self._merge(flat)

    async def _safe_lookup(
        self, source: ThreatIntelSource, indicators: list[str]
    ) -> list[ThreatIntelFinding]:
        """한 소스 조회. 실패 시 빈 목록으로 강등(다른 소스는 계속)."""
        try:
            return await source.alookup(indicators)
        except ThreatIntelError as exc:
            _logger.warning(
                "TI 소스 조회 실패, 건너뜀: %s (%s)",
                type(source).__name__,
                exc,
            )
            return []

    @staticmethod
    def _merge(findings: list[ThreatIntelFinding]) -> list[ThreatIntelFinding]:
        """지표별로 최악(rank 최대) 판정을 채택하고 출처를 합친다."""
        best: dict[str, ThreatIntelFinding] = {}
        sources: dict[str, set[str]] = {}
        for finding in findings:
            sources.setdefault(finding.indicator, set()).add(finding.source)
            current = best.get(finding.indicator)
            if current is None or (
                _VERDICT_RANK[finding.verdict] > _VERDICT_RANK[current.verdict]
            ):
                best[finding.indicator] = finding
        merged: list[ThreatIntelFinding] = []
        for indicator, finding in best.items():
            merged.append(
                finding.model_copy(
                    update={"source": ",".join(sorted(sources[indicator]))}
                )
            )
        return merged


class VirusTotalTool:
    """VirusTotal v3 IOC 평판 어댑터(httpx). 응답을 검증 후 채택.

    Args:
        settings: 전역 설정(미지정 시 환경 로드). `virustotal_api_key` 필요.
        client_factory: 비동기 HTTP 클라이언트 팩토리(테스트 주입용).
    """

    def __init__(
        self,
        settings: Settings | None = None,
        client_factory: object | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._client_factory = client_factory

    def _make_client(self) -> httpx.AsyncClient:
        """HTTP 클라이언트 생성(테스트에서 client_factory 로 치환)."""
        if self._client_factory is not None:
            return self._client_factory()  # type: ignore[operator,no-any-return]
        return httpx.AsyncClient(timeout=self._settings.ti_timeout_seconds)

    async def alookup(self, indicators: list[str]) -> list[ThreatIntelFinding]:
        """IOC 목록을 VirusTotal 로 조회한다.

        Args:
            indicators: 조회할 IOC(해시/IP/도메인).

        Returns:
            지표별 `ThreatIntelFinding`. 지원하지 않는 유형/미등록은 UNKNOWN.

        Raises:
            ThreatIntelError: API 키 미설정 시(컴포지트가 이 소스를 건너뛴다).
        """
        key = self._settings.virustotal_api_key.get_secret_value()
        if not key:
            raise ThreatIntelError("VirusTotal API 키 미설정(virustotal_api_key).")
        headers = {"x-apikey": key}
        findings: list[ThreatIntelFinding] = []
        async with self._make_client() as client:
            for indicator in indicators:
                findings.append(await self._lookup_one(client, indicator, headers))
        return findings

    async def _lookup_one(
        self, client: httpx.AsyncClient, indicator: str, headers: dict[str, str]
    ) -> ThreatIntelFinding:
        """단일 IOC 조회. 전송/검증 실패는 UNKNOWN 으로 강등(다른 IOC 계속)."""
        path = self._classify(indicator)
        if path is None:
            return ThreatIntelFinding(
                indicator=indicator,
                verdict=TiVerdict.UNKNOWN,
                source="virustotal",
                detail="지원하지 않는 IOC 유형",
            )
        base = self._settings.virustotal_base_url.rstrip("/")
        url = f"{base}/{path}/{quote(indicator)}"
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                return ThreatIntelFinding(
                    indicator=indicator,
                    verdict=TiVerdict.UNKNOWN,
                    source="virustotal",
                    detail="VT 미등록(404)",
                )
            resp.raise_for_status()
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            _logger.warning("VT 조회 실패(%s), UNKNOWN 강등: %s", indicator, exc)
            return ThreatIntelFinding(
                indicator=indicator,
                verdict=TiVerdict.UNKNOWN,
                source="virustotal",
                detail="조회 실패",
            )
        return self.parse(indicator, body)

    @staticmethod
    def _classify(indicator: str) -> str | None:
        """IOC 유형 → VT v3 엔드포인트 경로. 미지원이면 None."""
        if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", indicator):
            return "files"
        try:
            ipaddress.ip_address(indicator)
            return "ip_addresses"
        except ValueError:
            pass
        if "." in indicator and any(c.isalpha() for c in indicator):
            return "domains"
        return None

    @staticmethod
    def parse(indicator: str, body: object) -> ThreatIntelFinding:
        """VT v3 응답(`last_analysis_stats`)을 검증·판정한다(미검증 입력 가드).

        Args:
            indicator: 조회 IOC.
            body: VT 응답 JSON(신뢰 불가 외부 입력).

        Returns:
            검증 통과 시 통계 기반 판정, 형식 불일치면 UNKNOWN.
        """
        stats = _extract_stats(body)
        if stats is None:
            return ThreatIntelFinding(
                indicator=indicator,
                verdict=TiVerdict.UNKNOWN,
                source="virustotal",
                detail="응답 형식 검증 실패",
            )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 0:
            verdict = TiVerdict.MALICIOUS
        elif suspicious > 0:
            verdict = TiVerdict.SUSPICIOUS
        elif (stats.get("harmless", 0) + stats.get("undetected", 0)) > 0:
            verdict = TiVerdict.CLEAN
        else:
            verdict = TiVerdict.UNKNOWN
        return ThreatIntelFinding(
            indicator=indicator,
            verdict=verdict,
            source="virustotal",
            detail=f"VT mal={malicious} susp={suspicious}",
        )


def _extract_stats(body: object) -> dict[str, int] | None:
    """VT 응답에서 `data.attributes.last_analysis_stats`(정수 dict)를 안전 추출."""
    if not isinstance(body, dict):
        return None
    data = body.get("data")
    if not isinstance(data, dict):
        return None
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        return None
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return None
    if not all(isinstance(v, int) for v in stats.values()):
        return None
    return {str(k): int(v) for k, v in stats.items()}


def _is_ip(indicator: str) -> bool:
    """IP(v4/v6) 여부."""
    try:
        ipaddress.ip_address(indicator)
        return True
    except ValueError:
        return False


def _ip_only_finding(indicator: str, source: str) -> ThreatIntelFinding:
    """IP 전용 소스에 IP 가 아닌 IOC 가 들어온 경우의 UNKNOWN 결과."""
    return ThreatIntelFinding(
        indicator=indicator,
        verdict=TiVerdict.UNKNOWN,
        source=source,
        detail="IP 전용 소스",
    )


class GreyNoiseTool:
    """GreyNoise Community 어댑터 — *배경 스캔 노이즈 vs 표적 악성* 판별(IP 전용).

    FP 감축 특화: classification=malicious → MALICIOUS, benign → CLEAN, 그 외
    noise=True(인터넷 전체를 훑는 스캐너) → SUSPICIOUS(소음). 미등록은 UNKNOWN.

    Args:
        settings: 전역 설정(미지정 시 환경 로드). `greynoise_api_key` 필요.
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
        return httpx.AsyncClient(timeout=self._settings.ti_timeout_seconds)

    async def alookup(self, indicators: list[str]) -> list[ThreatIntelFinding]:
        """IP 평판/노이즈 분류를 조회한다.

        Raises:
            ThreatIntelError: API 키 미설정 시(컴포지트가 건너뜀).
        """
        key = self._settings.greynoise_api_key.get_secret_value()
        if not key:
            raise ThreatIntelError("GreyNoise API 키 미설정.")
        headers = {"key": key, "Accept": "application/json"}
        base = self._settings.greynoise_base_url.rstrip("/")
        findings: list[ThreatIntelFinding] = []
        async with self._make_client() as client:
            for indicator in indicators:
                if not _is_ip(indicator):
                    findings.append(_ip_only_finding(indicator, "greynoise"))
                    continue
                findings.append(await self._lookup_ip(client, base, indicator, headers))
        return findings

    async def _lookup_ip(
        self,
        client: httpx.AsyncClient,
        base: str,
        indicator: str,
        headers: dict[str, str],
    ) -> ThreatIntelFinding:
        try:
            resp = await client.get(f"{base}/{quote(indicator)}", headers=headers)
            if resp.status_code == 404:
                return ThreatIntelFinding(
                    indicator=indicator,
                    verdict=TiVerdict.UNKNOWN,
                    source="greynoise",
                    detail="GreyNoise 미관측",
                )
            resp.raise_for_status()
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            _logger.warning("GreyNoise 조회 실패(%s): %s", indicator, exc)
            return ThreatIntelFinding(
                indicator=indicator,
                verdict=TiVerdict.UNKNOWN,
                source="greynoise",
                detail="조회 실패",
            )
        return self.parse(indicator, body)

    @staticmethod
    def parse(indicator: str, body: object) -> ThreatIntelFinding:
        """GreyNoise 응답(classification/noise)을 판정한다."""
        if not isinstance(body, dict):
            verdict, detail = TiVerdict.UNKNOWN, "응답 형식 검증 실패"
        else:
            classification = body.get("classification")
            if classification == "malicious":
                verdict, detail = TiVerdict.MALICIOUS, "표적/악성 스캐너"
            elif classification == "benign":
                verdict, detail = TiVerdict.CLEAN, "양성(known good)"
            elif body.get("noise") is True:
                verdict, detail = TiVerdict.SUSPICIOUS, "인터넷 배경 스캔 노이즈"
            else:
                verdict, detail = TiVerdict.UNKNOWN, "미분류"
        return ThreatIntelFinding(
            indicator=indicator, verdict=verdict, source="greynoise", detail=detail
        )


class AbuseIpdbTool:
    """AbuseIPDB 어댑터 — IP 악용 신고 신뢰도(0~100) 기반 판정(IP 전용).

    Args:
        settings: 전역 설정(미지정 시 환경 로드). `abuseipdb_api_key` 필요.
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
        return httpx.AsyncClient(timeout=self._settings.ti_timeout_seconds)

    async def alookup(self, indicators: list[str]) -> list[ThreatIntelFinding]:
        """IP 악용 신뢰도를 조회한다.

        Raises:
            ThreatIntelError: API 키 미설정 시(컴포지트가 건너뜀).
        """
        key = self._settings.abuseipdb_api_key.get_secret_value()
        if not key:
            raise ThreatIntelError("AbuseIPDB API 키 미설정.")
        headers = {"Key": key, "Accept": "application/json"}
        url = f"{self._settings.abuseipdb_base_url.rstrip('/')}/check"
        findings: list[ThreatIntelFinding] = []
        async with self._make_client() as client:
            for indicator in indicators:
                if not _is_ip(indicator):
                    findings.append(_ip_only_finding(indicator, "abuseipdb"))
                    continue
                findings.append(await self._lookup_ip(client, url, indicator, headers))
        return findings

    async def _lookup_ip(
        self,
        client: httpx.AsyncClient,
        url: str,
        indicator: str,
        headers: dict[str, str],
    ) -> ThreatIntelFinding:
        params = {"ipAddress": indicator, "maxAgeInDays": "90"}
        try:
            resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            _logger.warning("AbuseIPDB 조회 실패(%s): %s", indicator, exc)
            return ThreatIntelFinding(
                indicator=indicator,
                verdict=TiVerdict.UNKNOWN,
                source="abuseipdb",
                detail="조회 실패",
            )
        return self.parse(indicator, body)

    @staticmethod
    def parse(indicator: str, body: object) -> ThreatIntelFinding:
        """AbuseIPDB 응답(abuseConfidenceScore)을 판정한다."""
        score: int | None = None
        if isinstance(body, dict):
            data = body.get("data")
            if isinstance(data, dict):
                raw = data.get("abuseConfidenceScore")
                if isinstance(raw, int):
                    score = raw
        if score is None:
            verdict, detail = TiVerdict.UNKNOWN, "응답 형식 검증 실패"
        elif score >= 75:
            verdict, detail = TiVerdict.MALICIOUS, f"신뢰도 {score}"
        elif score >= 25:
            verdict, detail = TiVerdict.SUSPICIOUS, f"신뢰도 {score}"
        else:
            verdict, detail = TiVerdict.CLEAN, f"신뢰도 {score}"
        return ThreatIntelFinding(
            indicator=indicator, verdict=verdict, source="abuseipdb", detail=detail
        )


class ThreatFoxTool:
    """ThreatFox(abuse.ch) 어댑터 — 악성 IOC DB 검색(해시/IP/도메인/URL).

    Args:
        settings: 전역 설정(미지정 시 환경 로드). `threatfox_api_key`(Auth-Key) 필요.
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
        return httpx.AsyncClient(timeout=self._settings.ti_timeout_seconds)

    async def alookup(self, indicators: list[str]) -> list[ThreatIntelFinding]:
        """IOC 를 ThreatFox 악성 DB 에서 검색한다.

        Raises:
            ThreatIntelError: API 키 미설정 시(컴포지트가 건너뜀).
        """
        key = self._settings.threatfox_api_key.get_secret_value()
        if not key:
            raise ThreatIntelError("ThreatFox Auth-Key 미설정.")
        headers = {"Auth-Key": key}
        url = self._settings.threatfox_base_url.rstrip("/")
        findings: list[ThreatIntelFinding] = []
        async with self._make_client() as client:
            for indicator in indicators:
                findings.append(await self._lookup_one(client, url, indicator, headers))
        return findings

    async def _lookup_one(
        self,
        client: httpx.AsyncClient,
        url: str,
        indicator: str,
        headers: dict[str, str],
    ) -> ThreatIntelFinding:
        payload = {"query": "search_ioc", "search_term": indicator}
        try:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            _logger.warning("ThreatFox 조회 실패(%s): %s", indicator, exc)
            return ThreatIntelFinding(
                indicator=indicator,
                verdict=TiVerdict.UNKNOWN,
                source="threatfox",
                detail="조회 실패",
            )
        return self.parse(indicator, body)

    @staticmethod
    def parse(indicator: str, body: object) -> ThreatIntelFinding:
        """ThreatFox 응답(query_status/confidence_level)을 판정한다."""
        verdict, detail = TiVerdict.UNKNOWN, "미등록"
        if isinstance(body, dict):
            status = body.get("query_status")
            data = body.get("data")
            if status == "ok" and isinstance(data, list) and data:
                first = data[0] if isinstance(data[0], dict) else {}
                confidence = first.get("confidence_level")
                conf = confidence if isinstance(confidence, int) else 0
                if conf >= 75:
                    verdict, detail = TiVerdict.MALICIOUS, f"ThreatFox conf={conf}"
                else:
                    verdict, detail = TiVerdict.SUSPICIOUS, f"ThreatFox conf={conf}"
            elif status == "no_result":
                verdict, detail = TiVerdict.UNKNOWN, "ThreatFox 미등록"
        return ThreatIntelFinding(
            indicator=indicator, verdict=verdict, source="threatfox", detail=detail
        )
