"""외부 위협 인텔리전스(TI) IOC 조회 도구.

Investigation 이 경보의 IOC(해시/IP/도메인 등)를 외부 TI 로 보강한다. 오프라인
데모용 `StubThreatIntel`(결정론 — 알려진 악성/의심 IOC 집합 기반)을 제공하며,
동일 `alookup` 시그니처로 실 VirusTotal/OTX 클라이언트를 교체할 수 있다(Protocol 주입).
"""

from __future__ import annotations

from core.models import ThreatIntelFinding, TiVerdict

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
