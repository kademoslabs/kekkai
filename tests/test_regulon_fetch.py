from __future__ import annotations

import ipaddress
from typing import Any
from unittest.mock import patch

import pytest

import regulon.urls
from regulon.urls import FetchError, UrlPolicyError, safe_fetch


class FakeResponse:
    def __init__(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        self._status = status
        self._body = body
        self.headers = headers or {}
        self._offset = 0

    def getcode(self) -> int:
        return self._status

    def read(self, size: int = 4096) -> bytes:
        if self._offset >= len(self._body):
            return b""
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        pass


class FakeOpener:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = responses

    def open(self, request, timeout: float):  # type: ignore[no-untyped-def]
        return self._responses.pop(0)


def _patch_public_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        regulon.urls,
        "_resolve_host",
        lambda _: [ipaddress.ip_address("93.184.216.34")],
    )


def test_safe_fetch_follows_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_public_resolution(monkeypatch)
    opener = FakeOpener(
        [
            FakeResponse(302, b"", {"Location": "https://example.com/final"}),
            FakeResponse(200, b"ok"),
        ]
    )
    with patch.object(regulon.urls.urllib.request, "build_opener", return_value=opener):  # type: ignore[attr-defined]
        result = safe_fetch("https://example.com/start", max_redirects=2)
        assert result.status_code == 200
        assert result.body == b"ok"


def test_safe_fetch_rejects_missing_location(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_public_resolution(monkeypatch)
    opener = FakeOpener([FakeResponse(302, b"", {})])
    with (
        patch.object(regulon.urls.urllib.request, "build_opener", return_value=opener),  # type: ignore[attr-defined]
        pytest.raises(UrlPolicyError),
    ):
        safe_fetch("https://example.com/start", max_redirects=1)


def test_safe_fetch_rejects_large_response(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_public_resolution(monkeypatch)
    opener = FakeOpener([FakeResponse(200, b"too-large")])
    with (
        patch.object(regulon.urls.urllib.request, "build_opener", return_value=opener),  # type: ignore[attr-defined]
        pytest.raises(FetchError),
    ):
        safe_fetch("https://example.com/start", max_bytes=1)
