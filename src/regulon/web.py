from __future__ import annotations

import html
import logging
import os
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, BinaryIO, cast
from urllib.parse import parse_qs

from kekkai_core import redact

from .rate_limit import RateLimiter
from .service import process_submission
from .storage import ArtifactStore
from .urls import FetchError, UrlPolicyError

logger = logging.getLogger(__name__)

_RATE_LIMITER = RateLimiter(limit=5, window_seconds=60)

Environ = dict[str, Any]
StartResponse = Callable[[str, list[tuple[str, str]]], Callable[[bytes], Any]]


def application(environ: Environ, start_response: StartResponse) -> Iterable[bytes]:
    path = str(environ.get("PATH_INFO", "/"))
    method = str(environ.get("REQUEST_METHOD", "GET"))
    client_ip = str(environ.get("REMOTE_ADDR", "unknown"))

    if path.startswith("/artifacts/") and path.endswith(".pdf"):
        return _serve_pdf(path, start_response)

    if method == "POST":
        decision = _RATE_LIMITER.allow(client_ip)
        if not decision.allowed:
            retry_after = str(int(decision.retry_after or 0))
            start_response(
                "429 Too Many Requests",
                [("Content-Type", "text/plain"), ("Retry-After", retry_after)],
            )
            return [b"Too many requests"]

        length = int(str(environ.get("CONTENT_LENGTH", "0")) or 0)
        input_stream = environ.get("wsgi.input")
        body = (
            cast(BinaryIO, input_stream).read(length)
            if length and input_stream is not None
            else b""
        )
        params = parse_qs(body.decode("utf-8"))
        target_url = params.get("url", [""])[0]
        try:
            record = process_submission(target_url, _store())
        except (UrlPolicyError, FetchError, ValueError) as exc:
            logger.info("submission rejected: %s", redact(str(exc)))
            start_response("400 Bad Request", [("Content-Type", "text/plain")])
            return [b"Request failed"]

        link = f"/artifacts/{record.artifact_id}.pdf"
        response = _render_html(
            "Submission complete",
            f'Download your report: <a href="{html.escape(link)}">PDF</a>',
        )
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [response.encode("utf-8")]

    response = _render_html(
        "Regulon PSTI Checker",
        '<form method="POST">\n'
        '<label>Target URL <input name="url" type="url" required></label>\n'
        '<button type="submit">Generate</button>\n'
        "</form>",
    )
    start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
    return [response.encode("utf-8")]


def _store() -> ArtifactStore:
    base_dir = Path(os.environ.get("REGULON_STORAGE_DIR", ".regulon/artifacts"))
    return ArtifactStore(base_dir)


def _serve_pdf(path: str, start_response: StartResponse) -> Iterable[bytes]:
    artifact_id = path.split("/")[-1].replace(".pdf", "")
    try:
        pdf_bytes = _store().load_pdf(artifact_id)
    except Exception as exc:  # pragma: no cover - defensive
        logger.info("pdf fetch failed: %s", redact(str(exc)))
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Not found"]

    start_response("200 OK", [("Content-Type", "application/pdf")])
    return [pdf_bytes]


def _render_html(title: str, body: str) -> str:
    return (
        "<!doctype html>"
        '<html><head><meta charset="utf-8"><title>'
        + html.escape(title)
        + "</title></head><body><h1>"
        + html.escape(title)
        + "</h1><div>"
        + body
        + "</div></body></html>"
    )
