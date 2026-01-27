"""Tool manifests with SHA256 checksums for secure downloads."""

from __future__ import annotations

import platform
import re
from dataclasses import dataclass

from .errors import UnsupportedPlatformError


@dataclass(frozen=True)
class ToolManifest:
    """Manifest for a downloadable security tool."""

    name: str
    version: str
    url_template: str
    sha256: dict[str, str]  # platform_key -> hash
    binary_name: str | None = None  # Name inside archive (if different from tool name)
    archive_type: str = "tar.gz"  # "tar.gz" or "zip"


def get_platform_key() -> str:
    """Get platform key for the current system.

    Returns:
        Platform key like 'linux_amd64', 'darwin_arm64', etc.

    Raises:
        UnsupportedPlatformError: If platform is not supported.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }

    arch = arch_map.get(machine)
    if not arch:
        raise UnsupportedPlatformError(f"Unsupported architecture: {machine}")

    if system not in ("linux", "darwin", "windows"):
        raise UnsupportedPlatformError(f"Unsupported OS: {system}")

    return f"{system}_{arch}"


def get_download_url(manifest: ToolManifest) -> str:
    """Build download URL for the current platform.

    Args:
        manifest: Tool manifest with URL template.

    Returns:
        Fully resolved download URL.
    """
    system = platform.system()
    machine = platform.machine().lower()

    arch_map = {
        "x86_64": "64bit",
        "amd64": "64bit",
        "aarch64": "ARM64",
        "arm64": "ARM64",
    }

    # Tool-specific URL formatting
    os_name = system
    if manifest.name == "trivy":
        os_name = system
        arch = arch_map.get(machine, "64bit")
    elif manifest.name == "semgrep":
        os_name = system.lower()
        arch = "x86_64" if machine in ("x86_64", "amd64") else "aarch64"
    elif manifest.name == "gitleaks":
        os_name = system.lower()
        arch = "x64" if machine in ("x86_64", "amd64") else "arm64"
    else:
        arch = machine

    return manifest.url_template.format(
        version=manifest.version,
        os=os_name,
        arch=arch,
    )


# Hardcoded manifests with official GitHub release URLs
# SHA256 checksums must be verified against official releases
TOOL_MANIFESTS: dict[str, ToolManifest] = {
    "trivy": ToolManifest(
        name="trivy",
        version="0.58.1",
        url_template=(
            "https://github.com/aquasecurity/trivy/releases/download/"
            "v{version}/trivy_{version}_{os}-{arch}.tar.gz"
        ),
        sha256={
            "linux_amd64": "01a6a89a6a8af9c830a1e6a762e42883e2ae68583514db81f5f2be3db3fb2ffc",
            "linux_arm64": "c1a551eedd0a0e0f5024f76c64dea5e7fa7ac41d84b4ff4f1ee18ec0bf11174c",
            "darwin_amd64": "8bca33df7022dfa76ea7ec03a2a19cfd86e2e6d8de8b94b5e70d9ab95f61c6e6",
            "darwin_arm64": "a7dae5017cf898e6dce0b3fcefcb3e88b1f8fd78a38a54f1d6c12b8c2bb5d0f4",
        },
        binary_name="trivy",
    ),
    "semgrep": ToolManifest(
        name="semgrep",
        version="1.102.0",
        url_template=(
            "https://github.com/semgrep/semgrep/releases/download/"
            "v{version}/semgrep-v{version}-{os}-{arch}.zip"
        ),
        sha256={
            "linux_amd64": "placeholder_semgrep_linux_amd64",
            "linux_arm64": "placeholder_semgrep_linux_arm64",
            "darwin_amd64": "placeholder_semgrep_darwin_amd64",
            "darwin_arm64": "placeholder_semgrep_darwin_arm64",
        },
        archive_type="zip",
        binary_name="semgrep",
    ),
    "gitleaks": ToolManifest(
        name="gitleaks",
        version="8.21.2",
        url_template=(
            "https://github.com/gitleaks/gitleaks/releases/download/"
            "v{version}/gitleaks_{version}_{os}_{arch}.tar.gz"
        ),
        sha256={
            "linux_amd64": "placeholder_gitleaks_linux_amd64",
            "linux_arm64": "placeholder_gitleaks_linux_arm64",
            "darwin_amd64": "placeholder_gitleaks_darwin_amd64",
            "darwin_arm64": "placeholder_gitleaks_darwin_arm64",
        },
        binary_name="gitleaks",
    ),
}


def get_manifest(tool_name: str) -> ToolManifest | None:
    """Get manifest for a tool.

    Args:
        tool_name: Name of the tool.

    Returns:
        ToolManifest if found, None otherwise.
    """
    return TOOL_MANIFESTS.get(tool_name)


def get_expected_hash(manifest: ToolManifest) -> str | None:
    """Get expected SHA256 hash for the current platform.

    Args:
        manifest: Tool manifest.

    Returns:
        Expected hash or None if platform not supported.
    """
    try:
        platform_key = get_platform_key()
        return manifest.sha256.get(platform_key)
    except UnsupportedPlatformError:
        return None


def validate_manifest_url(url: str) -> bool:
    """Validate that URL is from an allowed domain.

    Only official GitHub releases are allowed.

    Args:
        url: URL to validate.

    Returns:
        True if URL is from allowed domain.
    """
    allowed_patterns = [
        r"^https://github\.com/aquasecurity/trivy/releases/download/",
        r"^https://github\.com/semgrep/semgrep/releases/download/",
        r"^https://github\.com/gitleaks/gitleaks/releases/download/",
    ]
    return any(re.match(pattern, url) for pattern in allowed_patterns)
