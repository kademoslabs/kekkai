from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .models import Checklist

_ARTIFACT_RE = re.compile(r"^[a-f0-9]{32}$")


@dataclass(frozen=True)
class ArtifactRecord:
    artifact_id: str
    pdf_path: Path
    metadata_path: Path


class ArtifactStore:
    def __init__(self, base_dir: Path) -> None:
        self._base_dir = base_dir
        self._base_dir.mkdir(parents=True, exist_ok=True)

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def create(self, checklist: Checklist, pdf_bytes: bytes) -> ArtifactRecord:
        artifact_id = uuid.uuid4().hex
        pdf_path = self._safe_path(f"{artifact_id}.pdf")
        metadata_path = self._safe_path(f"{artifact_id}.json")
        pdf_path.write_bytes(pdf_bytes)
        metadata_path.write_text(
            json.dumps(
                {
                    "artifact_id": artifact_id,
                    "url": checklist.url,
                    "items": [
                        {
                            "check_id": item.check_id,
                            "title": item.title,
                            "status": item.status.value,
                            "evidence": item.evidence,
                        }
                        for item in checklist.items
                    ],
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return ArtifactRecord(
            artifact_id=artifact_id,
            pdf_path=pdf_path,
            metadata_path=metadata_path,
        )

    def load_pdf(self, artifact_id: str) -> bytes:
        artifact_id = self._validate_id(artifact_id)
        pdf_path = self._safe_path(f"{artifact_id}.pdf")
        return pdf_path.read_bytes()

    def load_metadata(self, artifact_id: str) -> dict[str, object]:
        artifact_id = self._validate_id(artifact_id)
        metadata_path = self._safe_path(f"{artifact_id}.json")
        data = json.loads(metadata_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("invalid metadata")
        return cast(dict[str, object], data)

    def _safe_path(self, filename: str) -> Path:
        target = (self._base_dir / filename).resolve()
        base = self._base_dir.resolve()
        if not target.is_relative_to(base):
            raise ValueError("path traversal detected")
        return target

    def _validate_id(self, artifact_id: str) -> str:
        if not _ARTIFACT_RE.fullmatch(artifact_id):
            raise ValueError("invalid artifact id")
        return artifact_id
