from __future__ import annotations

import ipaddress
from unittest import mock

import pytest

from kekkai.scanners.url_policy import (
    UrlPolicy,
    UrlPolicyError,
    _is_blocked_ip,
    is_private_ip_range,
    validate_target_url,
)


class TestValidateTargetUrl:
    def test_valid_public_url(self) -> None:
        url = validate_target_url("https://example.com/path")
        assert url == "https://example.com/path"

    def test_valid_url_with_query(self) -> None:
        url = validate_target_url("https://example.com/path?foo=bar")
        assert url == "https://example.com/path?foo=bar"

    def test_normalizes_missing_path(self) -> None:
        url = validate_target_url("https://example.com")
        assert url == "https://example.com/"

    def test_rejects_unsupported_scheme(self) -> None:
        with pytest.raises(UrlPolicyError, match="unsupported scheme"):
            validate_target_url("ftp://example.com")

    def test_rejects_file_scheme(self) -> None:
        with pytest.raises(UrlPolicyError, match="unsupported scheme"):
            validate_target_url("file:///etc/passwd")

    def test_rejects_missing_host(self) -> None:
        with pytest.raises(UrlPolicyError, match="missing host"):
            validate_target_url("https:///path")

    def test_rejects_credentials_in_url(self) -> None:
        with pytest.raises(UrlPolicyError, match="credentials"):
            validate_target_url("https://user:pass@example.com")

    def test_rejects_localhost(self) -> None:
        with pytest.raises(UrlPolicyError, match="local hostnames"):
            validate_target_url("http://localhost/")

    def test_rejects_localhost_variants(self) -> None:
        with pytest.raises(UrlPolicyError, match="local hostnames"):
            validate_target_url("http://test.local/")


class TestPrivateIPBlocking:
    def test_blocks_loopback_ipv4(self) -> None:
        with pytest.raises(UrlPolicyError, match="private/internal IP"):
            validate_target_url("http://127.0.0.1/")

    def test_blocks_private_10_range(self) -> None:
        with pytest.raises(UrlPolicyError, match="private/internal IP"):
            validate_target_url("http://10.0.0.1/")

    def test_blocks_private_172_range(self) -> None:
        with pytest.raises(UrlPolicyError, match="private/internal IP"):
            validate_target_url("http://172.16.0.1/")

    def test_blocks_private_192_range(self) -> None:
        with pytest.raises(UrlPolicyError, match="private/internal IP"):
            validate_target_url("http://192.168.1.1/")

    def test_blocks_link_local(self) -> None:
        with pytest.raises(UrlPolicyError, match="private/internal IP"):
            validate_target_url("http://169.254.169.254/")

    def test_blocks_loopback_ipv6(self) -> None:
        with pytest.raises(UrlPolicyError, match="private/internal IP"):
            validate_target_url("http://[::1]/")


class TestAllowPrivateIPs:
    def test_allows_private_ip_with_policy(self) -> None:
        policy = UrlPolicy(allow_private_ips=True)
        url = validate_target_url("http://192.168.1.1/test", policy)
        assert url == "http://192.168.1.1/test"

    def test_allows_loopback_with_policy(self) -> None:
        policy = UrlPolicy(allow_private_ips=True)
        url = validate_target_url("http://127.0.0.1/api", policy)
        assert url == "http://127.0.0.1/api"


def _mock_resolve_public(*args: object, **kwargs: object) -> list[ipaddress.IPv4Address]:
    """Mock DNS resolution returning a public IP."""
    return [ipaddress.IPv4Address("93.184.216.34")]


class TestDomainAllowlist:
    def test_rejects_domain_not_in_allowlist(self) -> None:
        policy = UrlPolicy(allowed_domains=frozenset({"example.com"}))
        with pytest.raises(UrlPolicyError, match="not in allowlist"):
            validate_target_url("https://evil.com/", policy)

    def test_allows_domain_in_allowlist(self) -> None:
        policy = UrlPolicy(allowed_domains=frozenset({"example.com"}))
        with mock.patch("kekkai.scanners.url_policy._resolve_host", _mock_resolve_public):
            url = validate_target_url("https://example.com/path", policy)
            assert url == "https://example.com/path"

    def test_allows_subdomain_of_allowlisted(self) -> None:
        policy = UrlPolicy(allowed_domains=frozenset({"example.com"}))
        with mock.patch("kekkai.scanners.url_policy._resolve_host", _mock_resolve_public):
            url = validate_target_url("https://sub.example.com/path", policy)
            assert url == "https://sub.example.com/path"


class TestDomainBlocklist:
    def test_blocks_domain_in_blocklist(self) -> None:
        policy = UrlPolicy(blocked_domains=frozenset({"evil.com"}))
        with pytest.raises(UrlPolicyError, match="blocked domain"):
            validate_target_url("https://evil.com/", policy)

    def test_blocks_subdomain_of_blocked(self) -> None:
        policy = UrlPolicy(blocked_domains=frozenset({"evil.com"}))
        with pytest.raises(UrlPolicyError, match="blocked domain"):
            validate_target_url("https://sub.evil.com/", policy)

    def test_allows_similar_domain(self) -> None:
        policy = UrlPolicy(blocked_domains=frozenset({"evil.com"}))
        url = validate_target_url("https://notevil.com/", policy)
        assert url == "https://notevil.com/"


class TestIsBlockedIp:
    def test_loopback_is_blocked(self) -> None:
        assert _is_blocked_ip(ipaddress.ip_address("127.0.0.1"))

    def test_private_is_blocked(self) -> None:
        assert _is_blocked_ip(ipaddress.ip_address("10.0.0.1"))

    def test_link_local_is_blocked(self) -> None:
        assert _is_blocked_ip(ipaddress.ip_address("169.254.1.1"))

    def test_public_ip_not_blocked(self) -> None:
        assert not _is_blocked_ip(ipaddress.ip_address("8.8.8.8"))

    def test_ipv6_loopback_blocked(self) -> None:
        assert _is_blocked_ip(ipaddress.ip_address("::1"))


class TestIsPrivateIpRange:
    def test_private_cidr_is_private(self) -> None:
        assert is_private_ip_range("10.0.0.0/8")
        assert is_private_ip_range("192.168.0.0/16")

    def test_invalid_cidr_is_private(self) -> None:
        # Invalid CIDRs should be treated as blocked/private
        assert is_private_ip_range("not-a-cidr")
