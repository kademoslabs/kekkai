from __future__ import annotations

import ipaddress
import socket

import pytest

import regulon.urls as urls
from regulon.urls import UrlPolicyError, validate_url


def test_validate_url_missing_host() -> None:
    with pytest.raises(UrlPolicyError):
        validate_url("http:///path")


def test_validate_url_missing_hostname() -> None:
    with pytest.raises(UrlPolicyError):
        validate_url("http://")


def test_validate_url_blocks_local_domain() -> None:
    with pytest.raises(UrlPolicyError):
        validate_url("https://example.local")


def test_handle_redirect_too_many(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(urls, "validate_url", lambda value: value)
    with pytest.raises(UrlPolicyError):
        urls._handle_redirect("https://example.com", "https://example.com", 0, 0)


def test_resolve_host_parses_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, port: int | None):
        return [
            (socket.AF_INET, None, None, None, ("93.184.216.34", 0)),
            (socket.AF_INET6, None, None, None, ("2001:db8::1", 0, 0, 0)),
        ]

    monkeypatch.setattr(urls.socket, "getaddrinfo", fake_getaddrinfo)
    resolved = urls._resolve_host("example.com")
    assert ipaddress.ip_address("93.184.216.34") in resolved
    assert ipaddress.ip_address("2001:db8::1") in resolved


def test_resolve_host_handles_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, port: int | None):
        raise socket.gaierror("fail")

    monkeypatch.setattr(urls.socket, "getaddrinfo", fake_getaddrinfo)
    assert urls._resolve_host("example.com") == []
