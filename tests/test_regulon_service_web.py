from __future__ import annotations

import io
from pathlib import Path

import pytest

import regulon.service as service
import regulon.web as web
from regulon.checklist import generate_checklist
from regulon.models import Checklist
from regulon.pdf import generate_pdf_bytes
from regulon.rate_limit import RateLimiter
from regulon.storage import ArtifactRecord, ArtifactStore
from regulon.urls import FetchResult, UrlPolicyError


def test_process_submission_creates_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ArtifactStore(tmp_path)

    def fake_fetch(url: str) -> FetchResult:
        return FetchResult(url=url, status_code=200, content_type="text/html", body=b"support")

    monkeypatch.setattr(service, "safe_fetch", fake_fetch)

    record = service.process_submission("https://example.com", store)
    assert record.pdf_path.exists()
    assert record.metadata_path.exists()


def test_process_submission_propagates_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ArtifactStore(tmp_path)

    def fake_fetch(url: str) -> FetchResult:
        raise UrlPolicyError("blocked")

    monkeypatch.setattr(service, "safe_fetch", fake_fetch)

    with pytest.raises(UrlPolicyError):
        service.process_submission("https://example.com", store)


def test_web_get_form() -> None:
    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]):
        captured["status"] = status
        captured["headers"] = headers
        return lambda _: None

    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/", "REMOTE_ADDR": "127.0.0.1"}
    body = b"".join(web.application(environ, start_response))
    assert captured["status"] == "200 OK"
    assert b"Regulon PSTI Checker" in body


def test_web_post_submission(monkeypatch: pytest.MonkeyPatch) -> None:
    record = ArtifactRecord(
        artifact_id="a" * 32,
        pdf_path=Path("/tmp/fake.pdf"),
        metadata_path=Path("/tmp/fake.json"),
    )

    def fake_process(url: str, store: ArtifactStore) -> ArtifactRecord:
        return record

    monkeypatch.setattr(web, "process_submission", fake_process)

    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]):
        captured["status"] = status
        captured["headers"] = headers
        return lambda _: None

    body_bytes = b"url=https%3A%2F%2Fexample.com"
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/",
        "REMOTE_ADDR": "127.0.0.1",
        "CONTENT_LENGTH": str(len(body_bytes)),
        "wsgi.input": io.BytesIO(body_bytes),
    }
    body = b"".join(web.application(environ, start_response))
    assert captured["status"] == "200 OK"
    assert b"/artifacts/" in body


def test_web_rate_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    record = ArtifactRecord(
        artifact_id="b" * 32,
        pdf_path=Path("/tmp/fake.pdf"),
        metadata_path=Path("/tmp/fake.json"),
    )

    def fake_process(url: str, store: ArtifactStore) -> ArtifactRecord:
        return record

    monkeypatch.setattr(web, "process_submission", fake_process)
    limiter = RateLimiter(limit=1, window_seconds=60, time_fn=lambda: 0.0)
    monkeypatch.setattr(web, "_RATE_LIMITER", limiter)

    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]):
        captured["status"] = status
        captured["headers"] = headers
        return lambda _: None

    body_bytes = b"url=https%3A%2F%2Fexample.com"
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/",
        "REMOTE_ADDR": "127.0.0.1",
        "CONTENT_LENGTH": str(len(body_bytes)),
        "wsgi.input": io.BytesIO(body_bytes),
    }
    web.application(environ, start_response)
    captured.clear()
    body = b"".join(web.application(environ, start_response))
    assert captured["status"] == "429 Too Many Requests"
    assert b"Too many requests" in body


def test_web_rejects_bad_submission(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_process(url: str, store: ArtifactStore) -> ArtifactRecord:
        raise UrlPolicyError("blocked")

    monkeypatch.setattr(web, "process_submission", fake_process)

    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]):
        captured["status"] = status
        captured["headers"] = headers
        return lambda _: None

    body_bytes = b"url=https%3A%2F%2Fexample.com"
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/",
        "REMOTE_ADDR": "127.0.0.1",
        "CONTENT_LENGTH": str(len(body_bytes)),
        "wsgi.input": io.BytesIO(body_bytes),
    }
    body = b"".join(web.application(environ, start_response))
    assert captured["status"] == "400 Bad Request"
    assert b"Request failed" in body


def test_web_serves_pdf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = ArtifactStore(tmp_path)
    checklist: Checklist = generate_checklist("https://example.com", "support")
    pdf_bytes = generate_pdf_bytes(checklist)
    record = store.create(checklist, pdf_bytes)

    monkeypatch.setenv("REGULON_STORAGE_DIR", str(tmp_path))

    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]):
        captured["status"] = status
        captured["headers"] = headers
        return lambda _: None

    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": f"/artifacts/{record.artifact_id}.pdf",
        "REMOTE_ADDR": "127.0.0.1",
    }
    body = b"".join(web.application(environ, start_response))
    assert captured["status"] == "200 OK"
    assert body == pdf_bytes
