"""IOC egress 필터 — untrusted wire IOC 를 외부(TI/샌드박스)로 내보내기 전 정제.

외부 조회는 조회 대상 IOC 를 외부 서비스(+ 관전 적)에 노출한다. `alert.iocs` 는
공격자 제어 wire 필드이므로, 내부 IP/호스트를 IOC 로 실으면 **내부 토폴로지가
누설**되고 IOC 폭주는 API **쿼터를 소진**시킨다. 이 필터가 외부 호출 직전에
사설/내부/불정 지표를 드롭하고 정규화·중복제거·상한(cap)한다.

표준 사설대역 판정은 `ipaddress` 표준(코드 상수 — 튜닝 불요), alert당 상한만 정책
(Settings.ioc_egress_max_per_alert). 정규화 형태로만 통과시켜 octal/decimal IP·
IPv6-mapped·punycode·URL userinfo 우회를 차단한다.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# 해시 IOC(소문자 hex): md5(32)/sha1(40)/sha256(64).
_HASH_RE = re.compile(r"\A(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\Z")
# 도메인 라벨(정규 — LDH, 최대 63): IDNA 정규화 후 검증.
_DOMAIN_LABEL = re.compile(r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
# 내부 도메인 접미사(조직 내부/쿠버네티스) — 외부 조회 금지.
_INTERNAL_SUFFIXES = (
    ".local",
    ".lan",
    ".internal",
    ".corp",
    ".home",
    ".intranet",
    ".svc",
    ".cluster.local",
)


class IocEgressFilter:
    """외부 조회 전 IOC 정제(사설/내부/불정 드롭 + 정규화 + cap)."""

    def sanitize(self, iocs: list[str], *, cap: int) -> tuple[list[str], list[str]]:
        """공개·정형 IOC 만 정규화해 통과, 나머지는 드롭. cap 으로 상한한다.

        Args:
            iocs: 원시 IOC 목록(untrusted wire + 샌드박스 추출).
            cap: 통과 IOC 상한(alert당 단일 outbound 예산).

        Returns:
            (통과[정규화·중복제거·cap 적용], 드롭[telemetry용 원본]).
        """
        kept: list[str] = []
        seen: set[str] = set()
        dropped: list[str] = []
        for raw in iocs:
            norm = self._normalize(raw.strip()) if isinstance(raw, str) else None
            if norm is None:
                dropped.append(str(raw))
                continue
            if norm in seen:  # 정규화 후 중복(대소문자 변형 등) — slot 낭비 방지
                continue
            seen.add(norm)
            kept.append(norm)
        if len(kept) > cap:
            dropped.extend(kept[cap:])
            kept = kept[:cap]
        return kept, dropped

    def _normalize(self, ioc: str) -> str | None:
        """IOC 를 정규 형태로 변환(공개·정형만), 아니면 None."""
        if not ioc:
            return None
        low = ioc.lower()
        if _HASH_RE.match(low):
            return low
        if "://" in ioc:
            return self._normalize_url(ioc)
        return self._public_host(ioc)

    def _public_host(self, value: str) -> str | None:
        """IP 또는 도메인 호스트가 공개면 정규 형태, 아니면 None."""
        ip = self._public_ip(value)
        if ip is not None:
            return ip
        return self._public_domain(value)

    def _public_ip(self, value: str) -> str | None:
        """공개 IP 면 정규 str, 사설/예약/비정규면 None."""
        try:
            ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(
                value
            )
        except ValueError:
            return None  # octal/decimal/비정규 표기는 파싱 실패 → IP 아님
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped  # IPv6-mapped IPv4 우회 차단 — 매핑 v4 로 판정
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return None
        return str(ip)  # 정규 형태

    def _public_domain(self, value: str) -> str | None:
        """공개 도메인이면 IDNA 정규 형태, 단일라벨/내부/불정이면 None."""
        host = value.rstrip(".").lower()
        if not host or "." not in host:  # 단일 라벨 = 내부 호스트 추정
            return None
        try:
            host = host.encode("idna").decode("ascii")  # 유니코드/punycode 정규화
        except (UnicodeError, ValueError):
            return None
        if host.endswith(_INTERNAL_SUFFIXES):
            return None
        labels = host.split(".")
        if not all(_DOMAIN_LABEL.match(lb) for lb in labels):
            return None
        # TLD(마지막 라벨)에 알파벳이 없으면 불정 IP 표기(예: 0x7f.0.0.1, 999.999.x)
        # → 드롭. 실 공개도메인/IDN TLD(xn--...)는 알파 포함.
        if not any(ch.isalpha() for ch in labels[-1]):
            return None
        return host

    def _normalize_url(self, value: str) -> str | None:
        """http(s)·공개호스트 URL 만 통과(userinfo/query/fragment 제거)."""
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https"):
            return None
        if parts.username or parts.password:  # user@host userinfo = 내부문자열 누설
            return None
        host = parts.hostname
        if not host:
            return None
        public = self._public_host(host)
        if public is None:
            return None
        netloc = public if parts.port is None else f"{public}:{parts.port}"
        # host-only 정규화 — path/query/fragment 전부 제거(Codex diff Medium: path 에
        # 내부 IP/호스트 문자열이 실려 외부 TI 로 누설되는 벡터 차단).
        return f"{parts.scheme}://{netloc}"
