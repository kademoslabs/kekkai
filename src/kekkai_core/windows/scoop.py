"""Scoop manifest generation and validation for Windows distribution."""

import json
import re
from typing import Any


def generate_scoop_manifest(
    version: str,
    sha256: str,
    whl_url: str,
    python_version: str = "3.12",
) -> dict[str, Any]:
    """
    Generate Scoop manifest for Kekkai package.

    Args:
        version: Package version (e.g., "0.0.1")
        sha256: SHA256 checksum of the wheel file
        whl_url: URL to wheel file (typically GitHub release)
        python_version: Minimum Python version required

    Returns:
        Scoop manifest as dictionary

    Raises:
        ValueError: If version format is invalid or URLs are not HTTPS
    """
    # Validate version format (basic semver)
    if not re.match(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$", version):
        raise ValueError(f"Invalid version format: {version}")

    # Validate HTTPS URLs only
    if not whl_url.startswith("https://"):
        raise ValueError(f"URL must use HTTPS: {whl_url}")

    # Validate SHA256 format (64 hex characters)
    if not re.match(r"^[a-fA-F0-9]{64}$", sha256):
        raise ValueError(f"Invalid SHA256 format: {sha256}")

    manifest: dict[str, Any] = {
        "version": version,
        "description": "Kekkai - Local-first AppSec orchestration and compliance checker",
        "homepage": "https://github.com/kademoslabs/kekkai",
        "license": "MIT",
        "depends": "python",
        "url": whl_url,
        "hash": sha256,
        "installer": {
            "script": [
                "# Validate Python version",
                (
                    "$pythonVersion = python --version 2>&1 | "
                    'Select-String -Pattern "Python (\\d+\\.\\d+)"'
                ),
                "$version = [version]$pythonVersion.Matches.Groups[1].Value",
                f'if ($version -lt [version]"{python_version}") {{',
                f'    Write-Error "Python {python_version}+ required, found $version"',
                "    exit 1",
                "}",
                "",
                "# Install Kekkai wheel",
                f'python -m pip install --force-reinstall --no-deps "{whl_url}"',
                "if ($LASTEXITCODE -ne 0) {",
                '    Write-Error "pip install failed"',
                "    exit 1",
                "}",
            ]
        },
        "uninstaller": {
            "script": [
                "python -m pip uninstall -y kekkai",
            ]
        },
        "checkver": {
            "github": "https://github.com/kademoslabs/kekkai",
        },
        "autoupdate": {
            "url": "https://github.com/kademoslabs/kekkai/releases/download/v$version/kekkai-$version-py3-none-any.whl",
        },
        "notes": [
            "Kekkai has been installed successfully!",
            "Run 'kekkai --help' to get started.",
            "For documentation, visit: https://github.com/kademoslabs/kekkai",
        ],
    }

    return manifest


def validate_scoop_manifest(manifest: dict[str, Any]) -> bool:
    """
    Validate Scoop manifest structure and required fields.

    Args:
        manifest: Scoop manifest dictionary

    Returns:
        True if manifest is valid

    Raises:
        ValueError: If manifest is invalid with detailed error message
    """
    # Required fields
    required_fields = ["version", "description", "homepage", "license", "url", "hash"]

    for field in required_fields:
        if field not in manifest:
            raise ValueError(f"Missing required field: {field}")

    # Validate version format
    version = manifest["version"]
    if not re.match(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$", version):
        raise ValueError(f"Invalid version format: {version}")

    # Validate URL is HTTPS
    url = manifest["url"]
    if not url.startswith("https://"):
        raise ValueError(f"URL must use HTTPS: {url}")

    # Validate SHA256 format
    sha256 = manifest["hash"]
    if not re.match(r"^[a-fA-F0-9]{64}$", sha256):
        raise ValueError(f"Invalid SHA256 format: {sha256}")

    # Validate installer/uninstaller structure
    if "installer" in manifest and "script" not in manifest["installer"]:
        raise ValueError("installer must contain 'script' field")

    if "uninstaller" in manifest and "script" not in manifest["uninstaller"]:
        raise ValueError("uninstaller must contain 'script' field")

    # Validate homepage URL
    homepage = manifest["homepage"]
    if not homepage.startswith("https://") and not homepage.startswith("http://"):
        raise ValueError(f"Invalid homepage URL: {homepage}")

    return True


def format_scoop_manifest_json(manifest: dict[str, Any]) -> str:
    """
    Format Scoop manifest as pretty-printed JSON.

    Args:
        manifest: Scoop manifest dictionary

    Returns:
        JSON string with 2-space indentation
    """
    return json.dumps(manifest, indent=2, ensure_ascii=False)


def generate_scoop_checksum_file(version: str, sha256: str) -> str:
    """
    Generate checksums.txt file for Scoop verification.

    Args:
        version: Package version
        sha256: SHA256 checksum

    Returns:
        Formatted checksum file content
    """
    return f"kekkai-{version}-py3-none-any.whl: {sha256}\n"
