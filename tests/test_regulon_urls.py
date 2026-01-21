import ipaddress

import pytest

import regulon.urls as urls
from regulon.urls import UrlPolicyError, validate_url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/",
        "http://10.0.0.1/",
        "http://192.168.0.1/",
        "http://172.16.0.1/",
    ],
)
def test_validate_url_blocks_private_hosts(url: str) -> None:
    with pytest.raises(UrlPolicyError):
        validate_url(url)


def test_validate_url_rejects_credentials() -> None:
    with pytest.raises(UrlPolicyError):
        validate_url("http://user:pass@example.com")


def test_validate_url_accepts_public_ip() -> None:
    assert validate_url("http://93.184.216.34/path") == "http://93.184.216.34/path"


def test_validate_url_rejects_bad_scheme() -> None:
    with pytest.raises(UrlPolicyError):
        validate_url("file:///etc/passwd")


def test_validate_url_allows_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        urls,
        "_resolve_host",
        lambda _: [ipaddress.ip_address("93.184.216.34")],
    )
    assert validate_url("https://example.com") == "https://example.com/"
