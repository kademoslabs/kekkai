from __future__ import annotations

import logging

from kekkai_core import redact

from .checklist import generate_checklist
from .models import Checklist
from .pdf import generate_pdf_bytes
from .storage import ArtifactRecord, ArtifactStore
from .urls import FetchError, UrlPolicyError, safe_fetch

logger = logging.getLogger(__name__)


def process_submission(url: str, store: ArtifactStore) -> ArtifactRecord:
    try:
        result = safe_fetch(url)
    except (UrlPolicyError, FetchError) as exc:
        logger.warning("submission failed: %s", redact(str(exc)))
        raise

    body_text = result.body.decode("utf-8", errors="replace")
    checklist: Checklist = generate_checklist(result.url, body_text)
    pdf_bytes = generate_pdf_bytes(checklist)
    return store.create(checklist, pdf_bytes)
