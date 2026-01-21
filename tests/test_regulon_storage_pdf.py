from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from regulon.checklist import generate_checklist
from regulon.models import Checklist, ChecklistItem, CheckStatus
from regulon.pdf import generate_pdf_bytes
from regulon.storage import ArtifactStore


def test_pdf_escapes_text() -> None:
    checklist = Checklist(
        url="https://example.com",
        items=[
            ChecklistItem(
                check_id="escape",
                title="Ensure escaping",
                status=CheckStatus.PASS,
                evidence="support (team) \\ ok",
            )
        ],
    )
    pdf_bytes = generate_pdf_bytes(checklist)
    assert b"\\(" in pdf_bytes
    assert b"\\)" in pdf_bytes
    assert b"\\\\" in pdf_bytes


def test_artifact_store_writes_files(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    checklist = generate_checklist("https://example.com", "support")
    pdf_bytes = generate_pdf_bytes(checklist)
    record = store.create(checklist, pdf_bytes)
    assert record.pdf_path.exists()
    assert record.metadata_path.exists()
    assert store.base_dir == tmp_path

    content = store.load_pdf(record.artifact_id)
    assert hashlib.sha256(content).hexdigest() == hashlib.sha256(pdf_bytes).hexdigest()


def test_artifact_store_loads_metadata(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    checklist = generate_checklist("https://example.com", "support")
    pdf_bytes = generate_pdf_bytes(checklist)
    record = store.create(checklist, pdf_bytes)
    data = store.load_metadata(record.artifact_id)
    assert data["artifact_id"] == record.artifact_id


def test_artifact_store_rejects_invalid_id(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    with pytest.raises(ValueError):
        store.load_pdf("not-a-valid-id")
