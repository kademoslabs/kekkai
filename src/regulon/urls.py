from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, BinaryIO


class UrlPolicyError(ValueError):
    pass


class FetchError(RuntimeError):
    pass


@dataclass(frozen=True)
class FetchResult:
    url: str
    status_code: int
    content_type: str | None
    body: bytes


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def validate_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise UrlPolicyError("unsupported scheme")
    if not parsed.netloc:
        raise UrlPolicyError("missing host")
    if parsed.username or parsed.password:
        raise UrlPolicyError("credentials not allowed")

    hostname = parsed.hostname
    if not hostname:
        raise UrlPolicyError("missing hostname")
    if hostname.lower() in {"localhost"} or hostname.lower().endswith(".local"):
        raise UrlPolicyError("local hostnames are blocked")

    if _is_ip_literal(hostname):
        ip = ipaddress.ip_address(hostname)
        if _is_blocked_ip(ip):
            raise UrlPolicyError("blocked ip")
    else:
        resolved = _resolve_host(hostname)
        if not resolved:
            raise UrlPolicyError("hostname resolution failed")
        for ip in resolved:
            if _is_blocked_ip(ip):
                raise UrlPolicyError("blocked ip")

    normalized = urllib.parse.urlunsplit(
        (scheme, parsed.netloc, parsed.path or "/", parsed.query, "")
    )
    return normalized


def safe_fetch(
    url: str,
    *,
    timeout_seconds: float = 5.0,
    max_redirects: int = 2,
    max_bytes: int = 1_000_000,
) -> FetchResult:
    current = validate_url(url)
    redirects = 0
    opener = urllib.request.build_opener(_NoRedirect())

    while True:
        request = urllib.request.Request(  # noqa: S310
            current,
            headers={"User-Agent": "Regulon/0.1"},
            method="GET",
        )
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                status = response.getcode()
                content_type = response.headers.get("Content-Type")
                if status and 300 <= status < 400:
                    current = _handle_redirect(
                        current, response.headers.get("Location"), max_redirects, redirects
                    )
                    redirects += 1
                    continue
                if status and status >= 400:
                    raise FetchError(f"upstream status {status}")
                body = _read_limited(response, max_bytes)
                return FetchResult(
                    url=current,
                    status_code=status or 0,
                    content_type=content_type,
                    body=body,
                )
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                current = _handle_redirect(
                    current, exc.headers.get("Location"), max_redirects, redirects
                )
                redirects += 1
                continue
            raise FetchError(f"upstream status {exc.code}") from exc
        except UrlPolicyError:
            raise
        except Exception as exc:  # pragma: no cover - unexpected
            raise FetchError("fetch failed") from exc


def _handle_redirect(
    current: str,
    location: str | None,
    max_redirects: int,
    redirects: int,
) -> str:
    if redirects >= max_redirects:
        raise UrlPolicyError("too many redirects")
    if not location:
        raise UrlPolicyError("redirect missing location")
    next_url = urllib.parse.urljoin(current, location)
    return validate_url(next_url)


def _read_limited(response: BinaryIO, max_bytes: int) -> bytes:
    data = bytearray()
    while True:
        chunk = response.read(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > max_bytes:
            raise FetchError("response too large")
    return bytes(data)


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def _resolve_host(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
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
    return not ip.is_global
