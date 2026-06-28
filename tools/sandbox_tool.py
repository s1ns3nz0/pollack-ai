"""샌드박스 디토네이션/분석 도구.

의심 파일·펌웨어(S4) 아티팩트를 샌드박스에 넣어 *행위 기반* 판정을 얻는다. TI 가
"이 IOC 평판"이라면, 샌드박스는 "이 샘플을 터뜨리면 무슨 짓을 하나"다. 추출된
IOC(C2 IP/도메인 등)는 TI(`CompositeThreatIntel`)로 되먹여 보강할 수 있다.

모든 어댑터는 동일 `adetonate(artifact) -> SandboxReport` 계약을 따른다(Protocol 주입):

- `StubSandbox`        : 오프라인 결정론(데모/테스트).
- `HybridAnalysisTool` : 실 Hybrid Analysis(Falcon Sandbox) v2 어댑터(해시 조회).
  펌웨어 정적분석(FACT/binwalk 래퍼)도 같은 계약으로 추가할 수 있다.
"""

from __future__ import annotations

import re
from typing import Protocol, runtime_checkable
from urllib.parse import quote

import httpx

from core.exceptions import SandboxError
from core.models import SandboxReport, TiVerdict
from core.settings import Settings, get_settings
from utils.logging import get_logger

_logger = get_logger("sandbox_tool")

# Hybrid Analysis verdict 문자열 → 공통 판정 척도.
_HA_VERDICT: dict[str, TiVerdict] = {
    "malicious": TiVerdict.MALICIOUS,
    "suspicious": TiVerdict.SUSPICIOUS,
    "no specific threat": TiVerdict.CLEAN,
    "whitelisted": TiVerdict.CLEAN,
}


@runtime_checkable
class SandboxTool(Protocol):
    """샌드박스 어댑터 계약(파일/펌웨어 행위 분석)."""

    async def adetonate(self, artifact: str) -> SandboxReport:
        """아티팩트(해시/샘플 ID)를 분석해 행위 기반 보고서를 반환한다."""
        ...


class StubSandbox:
    """오프라인 결정론 샌드박스(데모용). 알려진 악성 해시 집합 기반.

    Args:
        malicious: 악성 판정할 아티팩트(해시) 집합.
        signatures: 악성 판정 시 첨부할 행위 시그니처.
        extracted_iocs: 악성 판정 시 추출 IOC(TI 되먹임용).
    """

    def __init__(
        self,
        malicious: frozenset[str] | None = None,
        signatures: list[str] | None = None,
        extracted_iocs: list[str] | None = None,
    ) -> None:
        self._malicious = malicious or frozenset()
        self._signatures = signatures or ["프로세스 인젝션", "C2 비콘"]
        self._extracted_iocs = extracted_iocs or []

    async def adetonate(self, artifact: str) -> SandboxReport:
        """아티팩트를 결정론적으로 판정한다."""
        if artifact in self._malicious:
            return SandboxReport(
                artifact=artifact,
                verdict=TiVerdict.MALICIOUS,
                score=90,
                signatures=list(self._signatures),
                extracted_iocs=list(self._extracted_iocs),
                source="stub-sandbox",
            )
        return SandboxReport(
            artifact=artifact,
            verdict=TiVerdict.UNKNOWN,
            score=0,
            source="stub-sandbox",
        )


class HybridAnalysisTool:
    """Hybrid Analysis(Falcon Sandbox) v2 어댑터 — 해시로 기존 분석 보고서 조회.

    Args:
        settings: 전역 설정(미지정 시 환경 로드). `hybridanalysis_api_key` 필요.
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
        return httpx.AsyncClient(timeout=self._settings.sandbox_timeout_seconds)

    async def adetonate(self, artifact: str) -> SandboxReport:
        """해시 아티팩트의 Hybrid Analysis overview 보고서를 조회한다.

        Args:
            artifact: 파일 해시(md5/sha1/sha256).

        Returns:
            행위 기반 `SandboxReport`. 해시 형식이 아니거나 미등록은 UNKNOWN.

        Raises:
            SandboxError: API 키 미설정 시.
        """
        key = self._settings.hybridanalysis_api_key.get_secret_value()
        if not key:
            raise SandboxError("Hybrid Analysis API 키 미설정.")
        if not _is_hash(artifact):
            return SandboxReport(
                artifact=artifact,
                verdict=TiVerdict.UNKNOWN,
                source="hybrid-analysis",
            )
        headers = {
            "api-key": key,
            "User-Agent": "Falcon Sandbox",
            "accept": "application/json",
        }
        base = self._settings.hybridanalysis_base_url.rstrip("/")
        url = f"{base}/overview/{quote(artifact)}"
        try:
            async with self._make_client() as client:
                response = await client.get(url, headers=headers)
                if response.status_code == 404:
                    return SandboxReport(
                        artifact=artifact,
                        verdict=TiVerdict.UNKNOWN,
                        score=0,
                        source="hybrid-analysis",
                    )
                response.raise_for_status()
                body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            _logger.warning("Hybrid Analysis 조회 실패(%s): %s", artifact, exc)
            return SandboxReport(
                artifact=artifact, verdict=TiVerdict.UNKNOWN, source="hybrid-analysis"
            )
        return self.parse(artifact, body)

    @staticmethod
    def parse(artifact: str, body: object) -> SandboxReport:
        """Hybrid Analysis overview 응답을 검증·판정한다(미검증 입력 가드)."""
        if not isinstance(body, dict):
            return SandboxReport(
                artifact=artifact, verdict=TiVerdict.UNKNOWN, source="hybrid-analysis"
            )
        verdict_raw = body.get("verdict")
        verdict = (
            _HA_VERDICT.get(verdict_raw, TiVerdict.UNKNOWN)
            if isinstance(verdict_raw, str)
            else TiVerdict.UNKNOWN
        )
        score_raw = body.get("threat_score")
        score = score_raw if isinstance(score_raw, int) else 0
        tags = body.get("tags")
        signatures = (
            [t for t in tags if isinstance(t, str)] if isinstance(tags, list) else []
        )
        return SandboxReport(
            artifact=artifact,
            verdict=verdict,
            score=score,
            signatures=signatures,
            source="hybrid-analysis",
        )


def _is_hash(artifact: str) -> bool:
    """md5/sha1/sha256 16진 해시 형식 여부."""
    return bool(
        re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", artifact)
    )
