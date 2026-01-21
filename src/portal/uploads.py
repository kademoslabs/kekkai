"""File upload handling with validation and security controls.

Security controls:
- ASVS V5.2.2: Validate file uploads (type, content)
- ASVS V5.2.4: Enforce file size limits
- Files stored outside web root in secure temp location
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from kekkai_core import redact

if TYPE_CHECKING:
    from .tenants import Tenant

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = frozenset({".json", ".sarif"})
ALLOWED_CONTENT_TYPES = frozenset(
    {
        "application/json",
        "application/sarif+json",
        "application/octet-stream",
    }
)
DEFAULT_MAX_SIZE_BYTES = 10 * 1024 * 1024
MIN_FILE_SIZE = 2
FILENAME_PATTERN = re.compile(r"^[\w\-. ]{1,255}$")
UPLOAD_ID_LENGTH = 24


@dataclass(frozen=True)
class UploadResult:
    """Result of upload validation/processing."""

    success: bool
    upload_id: str | None = None
    file_path: Path | None = None
    file_hash: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class UploadValidation:
    """Validated upload metadata."""

    filename: str
    extension: str
    content_type: str
    size: int
    content: bytes


def validate_upload(
    filename: str | None,
    content_type: str | None,
    content: bytes,
    tenant: Tenant,
) -> UploadResult:
    """Validate an uploaded file.

    Args:
        filename: Original filename
        content_type: MIME type from request
        content: File content bytes
        tenant: Tenant performing upload (for size limits)

    Returns:
        UploadResult with error if validation fails
    """
    if not filename:
        return UploadResult(success=False, error="Missing filename")

    safe_filename = _sanitize_filename(filename)
    if not safe_filename:
        logger.warning("upload.invalid_filename original=%s", redact(filename))
        return UploadResult(success=False, error="Invalid filename")

    extension = _get_extension(safe_filename)
    if extension not in ALLOWED_EXTENSIONS:
        logger.warning(
            "upload.invalid_extension filename=%s extension=%s",
            redact(safe_filename),
            extension,
        )
        return UploadResult(
            success=False,
            error=f"Invalid file type. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    max_size = tenant.max_upload_size_mb * 1024 * 1024
    if len(content) > max_size:
        logger.warning(
            "upload.size_exceeded tenant=%s size=%d max=%d",
            tenant.id,
            len(content),
            max_size,
        )
        return UploadResult(
            success=False,
            error=f"File too large. Maximum: {tenant.max_upload_size_mb}MB",
        )

    if len(content) < MIN_FILE_SIZE:
        return UploadResult(success=False, error="File is empty or too small")

    if not _validate_json_content(content):
        logger.warning(
            "upload.invalid_json tenant=%s filename=%s", tenant.id, redact(safe_filename)
        )
        return UploadResult(success=False, error="Invalid JSON content")

    return UploadResult(success=True)


def process_upload(
    filename: str,
    content: bytes,
    tenant: Tenant,
    upload_dir: Path | None = None,
) -> UploadResult:
    """Process and store a validated upload.

    Files are stored outside web root in a secure temp directory.

    Args:
        filename: Sanitized filename
        content: Validated file content
        tenant: Tenant performing upload
        upload_dir: Override upload directory (for testing)

    Returns:
        UploadResult with file path and hash if successful
    """
    validation = validate_upload(filename, None, content, tenant)
    if not validation.success:
        return validation

    safe_filename = _sanitize_filename(filename)
    if not safe_filename:
        return UploadResult(success=False, error="Invalid filename")

    upload_id = _generate_upload_id()
    file_hash = hashlib.sha256(content).hexdigest()

    base_dir = upload_dir or _get_upload_dir()
    tenant_dir = base_dir / tenant.id
    tenant_dir.mkdir(parents=True, exist_ok=True)

    extension = _get_extension(safe_filename)
    stored_filename = f"{upload_id}{extension}"
    file_path = tenant_dir / stored_filename

    file_path.write_bytes(content)
    os.chmod(file_path, 0o600)

    logger.info(
        "upload.stored tenant=%s upload_id=%s hash=%s size=%d",
        tenant.id,
        upload_id,
        file_hash[:16],
        len(content),
    )

    return UploadResult(
        success=True,
        upload_id=upload_id,
        file_path=file_path,
        file_hash=file_hash,
    )


def get_upload_path(tenant: Tenant, upload_id: str, upload_dir: Path | None = None) -> Path | None:
    """Get the path to an upload file for a specific tenant.

    Enforces tenant boundary - only returns path if upload belongs to tenant.
    """
    if not _is_valid_upload_id(upload_id):
        return None

    base_dir = upload_dir or _get_upload_dir()
    tenant_dir = base_dir / tenant.id

    for ext in ALLOWED_EXTENSIONS:
        file_path = tenant_dir / f"{upload_id}{ext}"
        if file_path.exists() and file_path.is_file():
            resolved = file_path.resolve()
            if resolved.is_relative_to(tenant_dir.resolve()):
                return resolved
    return None


def delete_upload(tenant: Tenant, upload_id: str, upload_dir: Path | None = None) -> bool:
    """Delete an upload file."""
    file_path = get_upload_path(tenant, upload_id, upload_dir)
    if file_path and file_path.exists():
        file_path.unlink()
        logger.info("upload.deleted tenant=%s upload_id=%s", tenant.id, upload_id)
        return True
    return False


def _sanitize_filename(filename: str) -> str | None:
    """Sanitize filename to prevent path traversal."""
    basename = Path(filename).name
    if not basename or ".." in basename:
        return None
    basename = basename.replace("\x00", "")
    if not FILENAME_PATTERN.match(basename):
        cleaned = re.sub(r"[^\w\-. ]", "_", basename)
        if not cleaned or len(cleaned) > 255:
            return None
        return cleaned
    return basename


def _get_extension(filename: str) -> str:
    """Get lowercase file extension."""
    return Path(filename).suffix.lower()


def _validate_json_content(content: bytes) -> bool:
    """Validate that content is valid JSON."""
    try:
        json.loads(content.decode("utf-8"))
        return True
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False


def _generate_upload_id() -> str:
    """Generate a secure random upload ID."""
    return secrets.token_urlsafe(UPLOAD_ID_LENGTH)[:UPLOAD_ID_LENGTH]


def _is_valid_upload_id(upload_id: str) -> bool:
    """Validate upload ID format."""
    if not upload_id or len(upload_id) != UPLOAD_ID_LENGTH:
        return False
    return all(c.isalnum() or c in "-_" for c in upload_id)


def _get_upload_dir() -> Path:
    """Get the secure upload directory outside web root."""
    base = os.environ.get("PORTAL_UPLOAD_DIR")
    if base:
        return Path(base)
    return Path(tempfile.gettempdir()) / "kekkai-portal-uploads"
