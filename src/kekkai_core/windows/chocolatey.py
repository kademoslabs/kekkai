"""Chocolatey NuGet package generation and validation for Windows distribution."""

import re
import xml.etree.ElementTree as ET  # nosec B405 - generates trusted XML, not parsing untrusted
from typing import Any


def generate_nuspec(
    version: str,
    sha256: str,
    whl_url: str,
    python_version: str = "3.12",
) -> dict[str, Any]:
    """
    Generate Chocolatey NuGet package specification (nuspec).

    Args:
        version: Package version (e.g., "0.0.1")
        sha256: SHA256 checksum of the wheel file
        whl_url: URL to wheel file (typically GitHub release)
        python_version: Minimum Python version required

    Returns:
        Nuspec as dictionary (will be converted to XML)

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

    # Build nuspec structure
    nuspec: dict[str, Any] = {
        "id": "kekkai",
        "version": version,
        "title": "Kekkai",
        "authors": "Kademos Labs",
        "owners": "Kademos Labs",
        "licenseUrl": "https://github.com/kademoslabs/kekkai/blob/main/LICENSE",
        "projectUrl": "https://github.com/kademoslabs/kekkai",
        "iconUrl": "https://raw.githubusercontent.com/kademoslabs/kekkai/main/docs/assets/icon.png",
        "requireLicenseAcceptance": False,
        "description": (
            "Kekkai - Local-first AppSec orchestration and compliance checker. "
            "Integrates security scanning tools (Semgrep, Trivy, Gitleaks, OWASP ZAP) "
            "with DefectDojo for centralized vulnerability management."
        ),
        "summary": "Local-first AppSec orchestration and compliance checker",
        "tags": "security appsec cli devsecops vulnerability-scanner compliance",
        "copyright": "2024-2026 Kademos Labs",
        "dependencies": [
            {
                "id": "python",
                "version": f"[{python_version},)",
            }
        ],
        "files": [
            {"src": "tools\\**", "target": "tools"},
        ],
        # Metadata for package generation
        "_whl_url": whl_url,
        "_sha256": sha256,
        "_python_version": python_version,
    }

    return nuspec


def validate_nuspec(nuspec: dict[str, Any]) -> bool:
    """
    Validate Chocolatey nuspec structure and required fields.

    Args:
        nuspec: Nuspec dictionary

    Returns:
        True if nuspec is valid

    Raises:
        ValueError: If nuspec is invalid with detailed error message
    """
    # Required fields
    required_fields = [
        "id",
        "version",
        "authors",
        "description",
        "licenseUrl",
        "projectUrl",
    ]

    for field in required_fields:
        if field not in nuspec:
            raise ValueError(f"Missing required field: {field}")

    # Validate version format
    version = nuspec["version"]
    if not re.match(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$", version):
        raise ValueError(f"Invalid version format: {version}")

    # Validate URLs
    for url_field in ["licenseUrl", "projectUrl"]:
        if url_field in nuspec:
            url = nuspec[url_field]
            if not url.startswith("https://") and not url.startswith("http://"):
                raise ValueError(f"Invalid {url_field}: {url}")

    # Validate dependencies structure
    if "dependencies" in nuspec:
        deps = nuspec["dependencies"]
        if not isinstance(deps, list):
            raise ValueError("dependencies must be a list")

        for dep in deps:
            if not isinstance(dep, dict):
                raise ValueError("Each dependency must be a dict")
            if "id" not in dep:
                raise ValueError("Dependency missing 'id' field")

    # Validate internal metadata if present
    if "_sha256" in nuspec:
        sha256 = nuspec["_sha256"]
        if not re.match(r"^[a-fA-F0-9]{64}$", sha256):
            raise ValueError(f"Invalid SHA256 format: {sha256}")

    if "_whl_url" in nuspec:
        whl_url = nuspec["_whl_url"]
        if not whl_url.startswith("https://"):
            raise ValueError(f"Wheel URL must use HTTPS: {whl_url}")

    return True


def format_nuspec_xml(nuspec: dict[str, Any]) -> str:
    """
    Format nuspec dictionary as XML string for Chocolatey package.

    Args:
        nuspec: Nuspec dictionary

    Returns:
        XML string with proper formatting and namespace
    """
    # Define namespace
    ns = "http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd"
    ET.register_namespace("", ns)

    # Create root element
    package = ET.Element("package", xmlns=ns)
    metadata = ET.SubElement(package, "metadata")

    # Add simple fields
    simple_fields = [
        "id",
        "version",
        "title",
        "authors",
        "owners",
        "licenseUrl",
        "projectUrl",
        "iconUrl",
        "description",
        "summary",
        "tags",
        "copyright",
    ]

    for field in simple_fields:
        if field in nuspec:
            elem = ET.SubElement(metadata, field)
            elem.text = str(nuspec[field])

    # Add requireLicenseAcceptance
    if "requireLicenseAcceptance" in nuspec:
        elem = ET.SubElement(metadata, "requireLicenseAcceptance")
        elem.text = "true" if nuspec["requireLicenseAcceptance"] else "false"

    # Add dependencies
    if "dependencies" in nuspec and nuspec["dependencies"]:
        deps_elem = ET.SubElement(metadata, "dependencies")
        for dep in nuspec["dependencies"]:
            dep_attrs = {"id": dep["id"]}
            if "version" in dep:
                dep_attrs["version"] = dep["version"]
            ET.SubElement(deps_elem, "dependency", dep_attrs)

    # Add files section
    if "files" in nuspec and nuspec["files"]:
        files_elem = ET.SubElement(package, "files")
        for file_entry in nuspec["files"]:
            file_attrs = {}
            if "src" in file_entry:
                file_attrs["src"] = file_entry["src"]
            if "target" in file_entry:
                file_attrs["target"] = file_entry["target"]
            ET.SubElement(files_elem, "file", file_attrs)

    # Convert to string with XML declaration
    xml_str = '<?xml version="1.0" encoding="utf-8"?>\n'
    xml_str += _prettify_xml(package)

    return xml_str


def _prettify_xml(elem: ET.Element, level: int = 0) -> str:
    """
    Pretty-print XML element with 2-space indentation.

    Args:
        elem: XML Element
        level: Current indentation level

    Returns:
        Pretty-printed XML string
    """
    indent = "  " * level
    result = f"{indent}<{elem.tag}"

    # Add attributes
    for key, value in elem.attrib.items():
        result += f' {key}="{value}"'

    # Handle self-closing tags
    if not elem.text and len(elem) == 0:
        result += " />\n"
        return result

    result += ">"

    # Add text content
    if elem.text and elem.text.strip():
        result += elem.text

    # Add children
    if len(elem) > 0:
        result += "\n"
        for child in elem:
            result += _prettify_xml(child, level + 1)
        result += indent

    result += f"</{elem.tag}>\n"

    return result


def generate_chocolatey_package_structure(
    version: str,
    sha256: str,
    python_version: str = "3.12",
) -> dict[str, str]:
    """
    Generate complete Chocolatey package structure.

    Args:
        version: Package version
        sha256: SHA256 checksum of wheel
        python_version: Minimum Python version

    Returns:
        Dictionary mapping file paths to content:
        - "kekkai.nuspec": XML content
        - "tools/chocolateyinstall.ps1": Install script
        - "tools/chocolateyuninstall.ps1": Uninstall script
    """
    from kekkai_core.windows.installer import (
        generate_chocolatey_install_script,
        generate_chocolatey_uninstall_script,
    )

    whl_url = f"https://github.com/kademoslabs/kekkai/releases/download/v{version}/kekkai-{version}-py3-none-any.whl"

    # Generate nuspec
    nuspec = generate_nuspec(version, sha256, whl_url, python_version)
    nuspec_xml = format_nuspec_xml(nuspec)

    # Generate install/uninstall scripts
    install_script = generate_chocolatey_install_script(version, sha256, python_version)
    uninstall_script = generate_chocolatey_uninstall_script()

    # Return package structure
    return {
        "kekkai.nuspec": nuspec_xml,
        "tools/chocolateyinstall.ps1": install_script,
        "tools/chocolateyuninstall.ps1": uninstall_script,
    }


def generate_verification_file(version: str, sha256: str) -> str:
    """
    Generate VERIFICATION.txt for Chocolatey moderation.

    This file helps Chocolatey moderators verify package authenticity.

    Args:
        version: Package version
        sha256: SHA256 checksum

    Returns:
        VERIFICATION.txt content
    """
    whl_url = f"https://github.com/kademoslabs/kekkai/releases/download/v{version}/kekkai-{version}-py3-none-any.whl"

    verification = f"""VERIFICATION
Verification is intended to assist the Chocolatey moderators and community
in verifying that this package's contents are trustworthy.

Package can be verified like this:

1. Download wheel from official GitHub release:
   {whl_url}

2. Verify SHA256 checksum:
   Expected: {sha256}

   PowerShell command:
   Get-FileHash -Path kekkai-{version}-py3-none-any.whl -Algorithm SHA256

3. Install using the downloaded wheel:
   python -m pip install kekkai-{version}-py3-none-any.whl

The package scripts are included in this package under tools/ directory.
All scripts are also available in the official repository:
https://github.com/kademoslabs/kekkai
"""

    return verification
