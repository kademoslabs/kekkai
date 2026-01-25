"""Portal API endpoints for programmatic access.

Provides REST API endpoints that expose the same data visible in the UI.
All endpoints require authentication and enforce tenant isolation.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .tenants import Tenant

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class UploadInfo:
    """Information about an upload."""

    upload_id: str
    filename: str
    timestamp: str
    file_hash: str
    size_bytes: int


@dataclass(frozen=True)
class TenantStats:
    """Statistics for a tenant."""

    total_uploads: int
    total_size_bytes: int
    last_upload_time: str | None


def get_tenant_info(tenant: Tenant) -> dict[str, Any]:
    """Get tenant information for API response.

    Args:
        tenant: The authenticated tenant

    Returns:
        Dictionary containing tenant metadata
    """
    return {
        "id": tenant.id,
        "name": tenant.name,
        "dojo_product_id": tenant.dojo_product_id,
        "dojo_engagement_id": tenant.dojo_engagement_id,
        "enabled": tenant.enabled,
        "max_upload_size_mb": tenant.max_upload_size_mb,
        "auth_method": tenant.auth_method.value,
        "default_role": tenant.default_role,
    }


def list_uploads(tenant: Tenant, limit: int = 50) -> list[dict[str, Any]]:
    """List recent uploads for a tenant.

    Args:
        tenant: The authenticated tenant
        limit: Maximum number of uploads to return

    Returns:
        List of upload metadata dictionaries
    """
    upload_dir = Path(os.environ.get("PORTAL_UPLOAD_DIR", "/var/lib/kekkai-portal/uploads"))
    tenant_dir = upload_dir / tenant.id

    if not tenant_dir.exists():
        return []

    uploads: list[dict[str, Any]] = []

    # Get all upload files for this tenant
    try:
        upload_files = sorted(
            tenant_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:limit]

        for upload_file in upload_files:
            stat = upload_file.stat()
            uploads.append(
                {
                    "upload_id": upload_file.stem,
                    "filename": upload_file.name,
                    "timestamp": str(int(stat.st_mtime)),
                    "size_bytes": stat.st_size,
                }
            )
    except (OSError, PermissionError) as e:
        logger.warning("Failed to list uploads for tenant %s: %s", tenant.id, e)

    return uploads


def get_tenant_stats(tenant: Tenant) -> dict[str, Any]:
    """Get statistics for a tenant.

    Args:
        tenant: The authenticated tenant

    Returns:
        Dictionary containing tenant statistics
    """
    upload_dir = Path(os.environ.get("PORTAL_UPLOAD_DIR", "/var/lib/kekkai-portal/uploads"))
    tenant_dir = upload_dir / tenant.id

    if not tenant_dir.exists():
        return {
            "total_uploads": 0,
            "total_size_bytes": 0,
            "last_upload_time": None,
        }

    total_uploads = 0
    total_size_bytes = 0
    last_upload_time: int | None = None

    try:
        for upload_file in tenant_dir.glob("*.json"):
            stat = upload_file.stat()
            total_uploads += 1
            total_size_bytes += stat.st_size

            if last_upload_time is None or stat.st_mtime > last_upload_time:
                last_upload_time = int(stat.st_mtime)

    except (OSError, PermissionError) as e:
        logger.warning("Failed to get stats for tenant %s: %s", tenant.id, e)

    return {
        "total_uploads": total_uploads,
        "total_size_bytes": total_size_bytes,
        "last_upload_time": str(last_upload_time) if last_upload_time else None,
    }


def serialize_api_response(data: dict[str, Any]) -> bytes:
    """Serialize API response to JSON bytes.

    Args:
        data: Response data dictionary

    Returns:
        JSON-encoded bytes
    """
    return json.dumps(data, indent=2).encode("utf-8")
