"""Validation utilities for CI/CD distribution triggers."""

import re
from pathlib import Path


def validate_semver(version: str) -> bool:
    """
    Validate semantic versioning format.

    Args:
        version: Version string to validate

    Returns:
        True if valid semver, False otherwise

    Examples:
        >>> validate_semver("0.0.1")
        True
        >>> validate_semver("0.0.1-rc1")
        True
        >>> validate_semver("v0.0.1")
        False
        >>> validate_semver("1.2")
        False
    """
    # Strict semver: MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
    pattern = r"^\d+\.\d+\.\d+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?(\+[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$"
    return bool(re.match(pattern, version))


def verify_checksum(file_path: Path, expected_sha256: str) -> bool:
    """
    Verify file SHA256 checksum matches expected value.

    Args:
        file_path: Path to file to verify
        expected_sha256: Expected SHA256 hex digest

    Returns:
        True if checksums match, False otherwise

    Raises:
        FileNotFoundError: If file doesn't exist
    """
    from kekkai_core.ci.metadata import calculate_sha256

    actual_sha256 = calculate_sha256(file_path)
    return actual_sha256.lower() == expected_sha256.lower()


def validate_repo_format(repo: str) -> bool:
    """
    Validate GitHub repository format.

    Args:
        repo: Repository string (e.g., "kademoslabs/kekkai")

    Returns:
        True if valid format, False otherwise

    Examples:
        >>> validate_repo_format("kademoslabs/kekkai")
        True
        >>> validate_repo_format("kademoslabs")
        False
        >>> validate_repo_format("kademoslabs/kekkai/extra")
        False
    """
    pattern = r"^[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$"
    return bool(re.match(pattern, repo))


def validate_github_token(token: str) -> bool:
    """
    Validate GitHub token format (basic check).

    Args:
        token: GitHub token string

    Returns:
        True if format looks valid, False otherwise

    Note:
        This only validates format, not token validity or permissions.
    """
    if not token:
        return False

    # GitHub personal access tokens are typically 40+ characters
    # Classic tokens start with ghp_, fine-grained with github_pat_
    return not len(token) < 20
