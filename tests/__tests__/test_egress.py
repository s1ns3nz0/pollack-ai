"""IOC egress 필터 — 사설/내부/불정 드롭 + 정규화 + 단일 cap(내부누설·쿼터번 방지)."""

from core.egress import IocEgressFilter

_F = IocEgressFilter()
_SHA256 = "a" * 64
_CAP = 32


def _keep(iocs: list[str]) -> list[str]:
    kept, _ = _F.sanitize(iocs, cap=_CAP)
    return kept


class TestPrivateIpDropped:
    def test_rfc1918_and_loopback_linklocal_dropped(self) -> None:
        """사설/루프백/링크로컬/메타데이터 IP 전부 드롭."""
        assert (
            _keep(
                [
                    "10.0.0.5",
                    "192.168.1.1",
                    "172.16.0.1",
                    "127.0.0.1",
                    "169.254.169.254",  # 클라우드 메타데이터
                    "::1",
                    "fc00::1",
                    "0.0.0.0",
                ]
            )
            == []
        )

    def test_ipv6_mapped_ipv4_private_dropped(self) -> None:
        """IPv6-mapped IPv4 사설 → 매핑 v4 로 판정해 드롭(우회 차단)."""
        assert _keep(["::ffff:10.0.0.1", "::ffff:192.168.0.1"]) == []

    def test_octal_decimal_ip_dropped(self) -> None:
        """비정규(octal/decimal) IP 표기는 파싱 실패 → 드롭."""
        assert _keep(["0177.0.0.1", "2130706433", "0x7f.0.0.1"]) == []

    def test_public_ip_kept(self) -> None:
        """공개 IP 는 정규 형태로 통과."""
        assert _keep(["8.8.8.8", "1.1.1.1"]) == ["8.8.8.8", "1.1.1.1"]


class TestDomainRules:
    def test_single_label_and_internal_suffix_dropped(self) -> None:
        """단일 라벨·내부 접미사(.local/.corp/.svc/.cluster.local 등) 드롭."""
        assert (
            _keep(
                [
                    "printer",  # 단일 라벨
                    "svc.cluster.local",
                    "host.corp",
                    "printer.lan",
                    "foo.internal",
                    "db.svc",
                ]
            )
            == []
        )

    def test_public_domain_kept_lowercased(self) -> None:
        """공개 도메인은 소문자 정규화 통과."""
        assert _keep(["Example.COM", "sub.example.org"]) == [
            "example.com",
            "sub.example.org",
        ]

    def test_unicode_domain_idna_normalized(self) -> None:
        """유니코드 도메인은 punycode(IDNA)로 정규화 통과."""
        kept = _keep(["münchen.de"])
        assert kept == ["xn--mnchen-3ya.de"]

    def test_already_punycode_domain_kept_lowercased(self) -> None:
        """이미 punycode(xn--)인 입력도 소문자 canonical 로 통과(Codex diff Low)."""
        assert _keep(["XN--MNCHEN-3YA.DE"]) == ["xn--mnchen-3ya.de"]

    def test_all_numeric_labels_dropped(self) -> None:
        """전부 숫자 라벨(불정 IP 형태)은 드롭."""
        assert _keep(["999.999.999.999"]) == []


class TestUrlRules:
    def test_userinfo_url_dropped(self) -> None:
        """userinfo(user@host) URL 은 내부문자열 누설 벡터 → 드롭."""
        assert _keep(["https://10.0.0.5@evil.example/path"]) == []

    def test_url_canonicalized_host_only(self) -> None:
        """공개호스트 URL 은 host-only 로 정규화(path/query/fragment 전부 제거)."""
        assert _keep(["https://example.com/p?token=secret#frag"]) == [
            "https://example.com"
        ]

    def test_url_path_internal_ip_not_leaked(self) -> None:
        """path 에 내부 IP/호스트 문자열이 실려도 외부로 안 나감(Codex diff Medium)."""
        assert _keep(["https://example.com/internal/10.0.0.5/secret"]) == [
            "https://example.com"
        ]

    def test_private_host_url_dropped(self) -> None:
        """사설 호스트 URL 드롭."""
        assert _keep(["http://192.168.0.1/admin"]) == []

    def test_non_http_scheme_dropped(self) -> None:
        """http(s) 외 스킴 드롭."""
        assert _keep(["ftp://example.com/x", "file:///etc/passwd"]) == []


class TestHashAndDedup:
    def test_hash_lowercased_and_deduped(self) -> None:
        """해시는 소문자 정규화 + 대소문자 변형 중복 제거(slot 낭비 방지)."""
        kept = _keep([_SHA256.upper(), _SHA256])
        assert kept == [_SHA256]

    def test_malformed_dropped(self) -> None:
        """정형 아닌 문자열 드롭."""
        assert _keep(["not an ioc", "", "  ", "zzzz"]) == []

    def test_duplicate_public_ip_deduped(self) -> None:
        assert _keep(["8.8.8.8", "8.8.8.8"]) == ["8.8.8.8"]


class TestCap:
    def test_cap_truncates_and_reports_dropped(self) -> None:
        """cap 초과분은 잘리고 dropped 로 보고(단일 outbound 예산)."""
        iocs = [f"{i}.{i}.{i}.{i}" for i in range(1, 40)]  # 39개 공개 IP 후보
        kept, dropped = IocEgressFilter().sanitize(iocs, cap=10)
        assert len(kept) == 10
        assert len(dropped) >= 29  # 초과분(+ 사설/불정 드롭)
