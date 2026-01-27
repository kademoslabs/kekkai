"""Cryptographic verification for downloaded binaries."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from .errors import SecurityError

logger = logging.getLogger(__name__)

# Maximum file size for downloads (100MB)
MAX_DOWNLOAD_SIZE = 100 * 1024 * 1024


def compute_sha256(data: bytes) -> str:
    """Compute SHA256 hash of data.

    Args:
        data: Bytes to hash.

    Returns:
        Hex-encoded SHA256 hash.
    """
    return hashlib.sha256(data).hexdigest()


def compute_sha256_file(file_path: Path) -> str:
    """Compute SHA256 hash of a file.

    Args:
        file_path: Path to file.

    Returns:
        Hex-encoded SHA256 hash.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_checksum(data: bytes, expected_hash: str, tool_name: str) -> None:
    """Verify SHA256 checksum of downloaded data.

    Args:
        data: Downloaded bytes.
        expected_hash: Expected SHA256 hash (hex-encoded).
        tool_name: Name of tool (for error messages).

    Raises:
        SecurityError: If checksum doesn't match.
    """
    actual_hash = compute_sha256(data)

    if actual_hash != expected_hash:
        logger.error(
            "Checksum mismatch for %s: expected %s..., got %s...",
            tool_name,
            expected_hash[:16],
            actual_hash[:16],
        )
        raise SecurityError(
            f"Checksum mismatch for {tool_name}: "
            f"expected {expected_hash[:16]}..., got {actual_hash[:16]}..."
        )

    logger.info("Checksum verified for %s: %s", tool_name, actual_hash[:16])


def verify_file_size(size: int, tool_name: str) -> None:
    """Verify file size is within limits.

    Args:
        size: File size in bytes.
        tool_name: Name of tool (for error messages).

    Raises:
        SecurityError: If file exceeds size limit.
    """
    if size > MAX_DOWNLOAD_SIZE:
        raise SecurityError(
            f"Download size {size} exceeds maximum {MAX_DOWNLOAD_SIZE} for {tool_name}"
        )
