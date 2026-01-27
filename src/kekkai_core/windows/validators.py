"""Windows-specific validation utilities."""

import re
import subprocess
import sys
from pathlib import Path


def validate_python_version(
    required_version: str = "3.12",
) -> tuple[bool, str]:
    """
    Validate that Python version meets minimum requirement.

    Args:
        required_version: Minimum Python version (e.g., "3.12")

    Returns:
        Tuple of (is_valid, message)
    """
    try:
        # Get current Python version
        version_info = sys.version_info
        current_version = f"{version_info.major}.{version_info.minor}"

        # Parse required version
        req_parts = required_version.split(".")
        if len(req_parts) < 2:
            return False, f"Invalid required version format: {required_version}"

        req_major = int(req_parts[0])
        req_minor = int(req_parts[1])

        # Compare versions
        if version_info.major > req_major or (
            version_info.major == req_major and version_info.minor >= req_minor
        ):
            return True, f"Python {current_version} meets requirement >= {required_version}"
        else:
            return (
                False,
                f"Python {required_version}+ required, found {current_version}",
            )

    except (ValueError, IndexError) as e:
        return False, f"Failed to validate Python version: {e}"


def validate_windows_path(executable: str) -> tuple[bool, str | None]:
    """
    Validate that an executable is in Windows PATH.

    Args:
        executable: Executable name (e.g., "python", "docker")

    Returns:
        Tuple of (is_found, path_or_none)
    """
    try:
        # For non-Windows systems, use 'which' or 'where' based on platform
        if sys.platform.startswith("win"):
            cmd = ["where", executable]
        else:
            cmd = ["which", executable]

        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )

        if result.returncode == 0 and result.stdout.strip():
            path = result.stdout.strip().split("\n")[0]  # Take first match
            return True, path
        else:
            return False, None

    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, None


def validate_pip_available() -> tuple[bool, str]:
    """
    Validate that pip is available via python -m pip.

    Returns:
        Tuple of (is_available, message)
    """
    try:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pip", "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

        if result.returncode == 0:
            version_line = result.stdout.strip()
            return True, f"pip is available: {version_line}"
        else:
            return False, "pip is not available or not working correctly"

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return False, f"Failed to check pip: {e}"


def validate_scoop_format(manifest_path: Path) -> tuple[bool, list[str]]:
    """
    Validate Scoop manifest file format and structure.

    Args:
        manifest_path: Path to Scoop manifest JSON file

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    import json

    errors: list[str] = []

    # Check file exists
    if not manifest_path.exists():
        errors.append(f"Manifest file not found: {manifest_path}")
        return False, errors

    # Check file is readable
    try:
        content = manifest_path.read_text(encoding="utf-8")
    except Exception as e:
        errors.append(f"Failed to read manifest: {e}")
        return False, errors

    # Check valid JSON
    try:
        manifest = json.loads(content)
    except json.JSONDecodeError as e:
        errors.append(f"Invalid JSON: {e}")
        return False, errors

    # Validate required fields
    required_fields = ["version", "description", "homepage", "license", "url", "hash"]
    for field in required_fields:
        if field not in manifest:
            errors.append(f"Missing required field: {field}")

    # Validate version format
    if "version" in manifest:
        version = manifest["version"]
        if not re.match(
            r"^\d+\.\d+\.\d+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$",
            version,
        ):
            errors.append(f"Invalid version format: {version}")

    # Validate URL is HTTPS
    if "url" in manifest:
        url = manifest["url"]
        if not url.startswith("https://"):
            errors.append(f"URL must use HTTPS: {url}")

    # Validate SHA256 format
    if "hash" in manifest:
        sha256 = manifest["hash"]
        if not re.match(r"^[a-fA-F0-9]{64}$", sha256):
            errors.append(f"Invalid SHA256 format: {sha256}")

    # Validate installer/uninstaller structure
    if "installer" in manifest and "script" not in manifest["installer"]:
        errors.append("installer must contain 'script' field")

    if "uninstaller" in manifest and "script" not in manifest["uninstaller"]:
        errors.append("uninstaller must contain 'script' field")

    return len(errors) == 0, errors


def validate_chocolatey_nuspec(nuspec_path: Path) -> tuple[bool, list[str]]:
    """
    Validate Chocolatey .nuspec file format and structure.

    Args:
        nuspec_path: Path to .nuspec XML file

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    import xml.etree.ElementTree as ET  # nosec B405 - validates local trusted nuspec files

    errors: list[str] = []

    # Check file exists
    if not nuspec_path.exists():
        errors.append(f"Nuspec file not found: {nuspec_path}")
        return False, errors

    # Parse XML
    try:
        tree = ET.parse(nuspec_path)  # noqa: S314  # nosec B314 - Local trusted file validation only
        root = tree.getroot()
    except ET.ParseError as e:
        errors.append(f"Invalid XML: {e}")
        return False, errors

    # Validate required fields (simplified)
    # Note: Full validation would need to handle XML namespaces
    required_fields = ["id", "version", "authors", "description"]
    metadata = root.find("metadata")

    if metadata is None:
        errors.append("Missing <metadata> element")
        return False, errors

    for field in required_fields:
        if metadata.find(field) is None:
            errors.append(f"Missing required field: {field}")

    return len(errors) == 0, errors
