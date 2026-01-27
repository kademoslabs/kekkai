"""Metadata extraction utilities for CI/CD distribution triggers."""

import hashlib
import re
from pathlib import Path


def extract_version_from_tag(tag: str) -> str:
    """
    Extract semantic version from Git tag.

    Args:
        tag: Git tag string (e.g., "v0.0.1", "v0.0.1-rc1")

    Returns:
        Version string without 'v' prefix (e.g., "0.0.1", "0.0.1-rc1")

    Raises:
        ValueError: If tag format is invalid
    """
    if not tag:
        raise ValueError("Tag cannot be empty")

    # Remove 'v' prefix if present
    version = tag[1:] if tag.startswith("v") else tag

    # Validate basic semver pattern (with optional pre-release and build metadata)
    pattern = r"^\d+\.\d+\.\d+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?(\+[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$"
    if not re.match(pattern, version):
        raise ValueError(f"Invalid tag format: {tag}. Expected format: v0.0.1 or v0.0.1-rc1")

    return version


def calculate_sha256(file_path: Path) -> str:
    """
    Calculate SHA256 checksum of a file.

    Args:
        file_path: Path to file to checksum

    Returns:
        SHA256 hex digest string

    Raises:
        FileNotFoundError: If file doesn't exist
        OSError: If file cannot be read
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    sha256_hash = hashlib.sha256()
    with file_path.open("rb") as f:
        # Read in 64KB chunks for memory efficiency
        for chunk in iter(lambda: f.read(65536), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def extract_tarball_url(repo: str, version: str) -> str:
    """
    Generate GitHub release tarball URL.

    Args:
        repo: Repository name (e.g., "kademoslabs/kekkai")
        version: Version string (e.g., "0.0.1")

    Returns:
        GitHub release tarball URL
    """
    # Remove 'v' prefix if present for URL consistency
    clean_version = version[1:] if version.startswith("v") else version
    return f"https://github.com/{repo}/archive/refs/tags/v{clean_version}.tar.gz"


def format_dispatch_payload(
    event_type: str,
    version: str,
    sha256: str | None = None,
) -> dict[str, object]:
    """
    Format repository_dispatch payload for distribution updates.

    Args:
        event_type: Dispatch event type (e.g., "kekkai-release")
        version: Version string
        sha256: Optional SHA256 checksum

    Returns:
        JSON-serializable dispatch payload
    """
    payload: dict[str, object] = {
        "event_type": event_type,
        "client_payload": {
            "version": version,
        },
    }

    if sha256:
        assert isinstance(payload["client_payload"], dict)  # nosec B101
        payload["client_payload"]["sha256"] = sha256

    return payload
