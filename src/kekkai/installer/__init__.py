"""Tool installer module for automatic binary management."""

from .errors import (
    DownloadError,
    ExtractionError,
    InstallerError,
    SecurityError,
    UnsupportedPlatformError,
)
from .manager import ToolInstaller, get_installer
from .manifest import (
    TOOL_MANIFESTS,
    ToolManifest,
    get_download_url,
    get_expected_hash,
    get_manifest,
    get_platform_key,
    validate_manifest_url,
)
from .verify import compute_sha256, verify_checksum

__all__ = [
    "DownloadError",
    "ExtractionError",
    "InstallerError",
    "SecurityError",
    "TOOL_MANIFESTS",
    "ToolInstaller",
    "ToolManifest",
    "UnsupportedPlatformError",
    "compute_sha256",
    "get_download_url",
    "get_expected_hash",
    "get_installer",
    "get_manifest",
    "get_platform_key",
    "validate_manifest_url",
    "verify_checksum",
]
