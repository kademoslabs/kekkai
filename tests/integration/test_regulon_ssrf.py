import pytest

from regulon.urls import UrlPolicyError, safe_fetch


@pytest.mark.integration
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
def test_safe_fetch_blocks_private_ips(url: str) -> None:
    with pytest.raises(UrlPolicyError):
        safe_fetch(url, timeout_seconds=0.1)
