from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from dataclasses import dataclass, field


class UrlPolicyError(ValueError):
    """Raised when a URL fails policy validation."""


@dataclass(frozen=True)
class UrlPolicy:
    """URL validation policy for DAST scanning targets.

    By default, blocks all private/internal IP ranges (SSRF protection).
    Can be configured with explicit allowlist patterns.
    """

    allow_private_ips: bool = False
    allowed_domains: frozenset[str] = field(default_factory=frozenset)
    blocked_domains: frozenset[str] = field(default_factory=frozenset)
    max_redirects: int = 2
    allowed_schemes: frozenset[str] = field(default_factory=lambda: frozenset({"http", "https"}))


def validate_target_url(url: str, policy: UrlPolicy | None = None) -> str:
    """Validate and normalize a target URL for DAST scanning.

    Args:
        url: The URL to validate
        policy: Optional URL policy (uses default restrictive policy if None)

    Returns:
        Normalized URL string

    Raises:
        UrlPolicyError: If URL fails validation
    """
    policy = policy or UrlPolicy()

    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()

    if scheme not in policy.allowed_schemes:
        raise UrlPolicyError(f"unsupported scheme: {scheme}")

    if not parsed.netloc:
        raise UrlPolicyError("missing host")

    if parsed.username or parsed.password:
        raise UrlPolicyError("credentials in URL not allowed")

    hostname = parsed.hostname
    if not hostname:
        raise UrlPolicyError("missing hostname")

    hostname_lower = hostname.lower()

    # Check blocked domains
    if policy.blocked_domains:
        for blocked in policy.blocked_domains:
            if hostname_lower == blocked or hostname_lower.endswith(f".{blocked}"):
                raise UrlPolicyError(f"blocked domain: {hostname}")

    # Check localhost variants
    if hostname_lower in {"localhost"} or hostname_lower.endswith(".local"):
        raise UrlPolicyError("local hostnames are blocked")

    # Check allowed domains (if specified, acts as allowlist)
    if policy.allowed_domains:
        allowed = False
        for domain in policy.allowed_domains:
            if hostname_lower == domain or hostname_lower.endswith(f".{domain}"):
                allowed = True
                break
        if not allowed:
            raise UrlPolicyError(f"domain not in allowlist: {hostname}")

    # Validate IP addresses
    if _is_ip_literal(hostname):
        ip = ipaddress.ip_address(hostname)
        if not policy.allow_private_ips and _is_blocked_ip(ip):
            raise UrlPolicyError(f"private/internal IP blocked: {hostname}")
    else:
        # Resolve hostname and check all IPs
        resolved = _resolve_host(hostname)
        if not resolved:
            raise UrlPolicyError(f"hostname resolution failed: {hostname}")
        if not policy.allow_private_ips:
            for ip in resolved:
                if _is_blocked_ip(ip):
                    raise UrlPolicyError(f"hostname resolves to blocked IP: {hostname} -> {ip}")

    # Normalize the URL
    normalized = urllib.parse.urlunsplit(
        (scheme, parsed.netloc, parsed.path or "/", parsed.query, "")
    )
    return normalized


def _is_ip_literal(hostname: str) -> bool:
    """Check if hostname is an IP address literal."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _resolve_host(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve hostname to IP addresses."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []

    resolved: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        address = sockaddr[0]
        try:
            resolved.append(ipaddress.ip_address(address))
        except ValueError:
            continue
    return resolved


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if IP is in a blocked range (non-global/public)."""
    # Block all non-global IPs by default (private, loopback, link-local, etc.)
    return not ip.is_global


def is_private_ip_range(cidr: str) -> bool:
    """Check if a CIDR range is private/internal."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # A range is "private" if it's not fully global
        return not all(
            ipaddress.ip_address(int(network.network_address) + i).is_global
            for i in range(min(256, network.num_addresses))
        )
    except ValueError:
        return True  # Invalid CIDR = blocked


# Common private/internal CIDR ranges for reference
PRIVATE_CIDRS = frozenset(
    {
        "10.0.0.0/8",  # RFC 1918
        "172.16.0.0/12",  # RFC 1918
        "192.168.0.0/16",  # RFC 1918
        "127.0.0.0/8",  # Loopback
        "169.254.0.0/16",  # Link-local
        "::1/128",  # IPv6 loopback
        "fe80::/10",  # IPv6 link-local
        "fc00::/7",  # IPv6 ULA
    }
)
