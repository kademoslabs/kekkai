"""Main tool installer manager."""

from __future__ import annotations

import logging
import os
import shutil
import ssl
import tempfile
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

from .errors import DownloadError, InstallerError, SecurityError, UnsupportedPlatformError
from .extract import extract_archive
from .manifest import (
    ToolManifest,
    get_download_url,
    get_expected_hash,
    get_manifest,
    get_platform_key,
    validate_manifest_url,
)
from .verify import MAX_DOWNLOAD_SIZE, verify_checksum, verify_file_size

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Download timeout in seconds
DOWNLOAD_TIMEOUT = 120


class ToolInstaller:
    """Manages downloading and installing security tools."""

    def __init__(self, install_dir: Path | None = None) -> None:
        """Initialize the tool installer.

        Args:
            install_dir: Directory to install tools. Defaults to ~/.kekkai/bin/.
        """
        if install_dir is None:
            from kekkai.paths import bin_dir

            install_dir = bin_dir()

        self.install_dir = install_dir
        self.install_dir.mkdir(parents=True, exist_ok=True)

    def ensure_tool(self, name: str, auto_install: bool = False) -> Path:
        """Ensure a tool is installed, downloading if necessary.

        Args:
            name: Tool name (trivy, semgrep, gitleaks).
            auto_install: If True, install without prompting.

        Returns:
            Path to the installed tool binary.

        Raises:
            InstallerError: If installation fails.
        """
        # Check if already installed in our bin directory
        existing = self._find_installed(name)
        if existing:
            logger.debug("Tool %s already installed at %s", name, existing)
            return existing

        # Check if available in PATH
        path_tool = shutil.which(name)
        if path_tool:
            logger.debug("Tool %s found in PATH at %s", name, path_tool)
            return Path(path_tool)

        # Need to download
        manifest = get_manifest(name)
        if not manifest:
            raise InstallerError(f"Unknown tool: {name}")

        if not auto_install:
            logger.info("Tool %s not found. Use --auto-install or install manually.", name)
            raise InstallerError(
                f"Tool {name} not found. Use --auto-install to download automatically."
            )

        return self._download_and_install(manifest)

    def _find_installed(self, name: str) -> Path | None:
        """Find if tool is already installed in our bin directory.

        Args:
            name: Tool name.

        Returns:
            Path to binary if found, None otherwise.
        """
        candidates = [
            self.install_dir / name,
            self.install_dir / f"{name}.exe",
        ]

        for path in candidates:
            if path.exists() and os.access(path, os.X_OK):
                return path

        return None

    def _download_and_install(self, manifest: ToolManifest) -> Path:
        """Download and install a tool.

        Args:
            manifest: Tool manifest.

        Returns:
            Path to installed binary.

        Raises:
            SecurityError: If verification fails.
            DownloadError: If download fails.
        """
        # Get expected hash for platform
        expected_hash = get_expected_hash(manifest)
        if not expected_hash:
            platform_key = get_platform_key()
            raise UnsupportedPlatformError(
                f"No binary available for {manifest.name} on {platform_key}"
            )

        # Skip download if hash is a placeholder
        if expected_hash.startswith("placeholder_"):
            raise InstallerError(
                f"SHA256 hash not yet configured for {manifest.name}. "
                "Please install manually or wait for manifest update."
            )

        # Build download URL and validate
        url = get_download_url(manifest)
        if not validate_manifest_url(url):
            raise SecurityError(f"URL not from allowed domain: {url}")

        logger.info("Downloading %s v%s from %s", manifest.name, manifest.version, url)

        # Download with strict TLS
        content = self._download(url, manifest.name)

        # Verify checksum
        verify_checksum(content, expected_hash, manifest.name)

        # Extract to temp directory first
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_path = tmp_path / f"{manifest.name}.archive"
            archive_path.write_bytes(content)

            # Extract binary
            binary_name = manifest.binary_name or manifest.name
            extracted_path = extract_archive(
                archive_path, tmp_path, binary_name, manifest.archive_type
            )

            # Move to install directory
            final_path = self.install_dir / extracted_path.name
            shutil.move(str(extracted_path), str(final_path))

            # Make executable
            final_path.chmod(0o755)

            logger.info("Installed %s to %s", manifest.name, final_path)
            return final_path

    def _download(self, url: str, tool_name: str) -> bytes:
        """Download a file with strict TLS settings.

        Args:
            url: URL to download.
            tool_name: Tool name for error messages.

        Returns:
            Downloaded bytes.

        Raises:
            DownloadError: If download fails.
            SecurityError: If file too large.
        """
        # Create SSL context with TLS 1.2+ (1.3 preferred but 1.2 is widely supported)
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        try:
            req = urllib.request.Request(  # noqa: S310 - URL validated in validate_manifest_url
                url,
                headers={"User-Agent": "kekkai-installer/1.0"},
            )

            with urllib.request.urlopen(  # noqa: S310 - URL validated
                req, context=ctx, timeout=DOWNLOAD_TIMEOUT
            ) as resp:
                if resp.status != 200:
                    raise DownloadError(f"Download failed: HTTP {resp.status}")

                # Check content length if provided
                content_length = resp.headers.get("Content-Length")
                if content_length:
                    verify_file_size(int(content_length), tool_name)

                # Read with size limit
                content: bytes = resp.read(MAX_DOWNLOAD_SIZE + 1)
                verify_file_size(len(content), tool_name)

                return content

        except urllib.error.HTTPError as e:
            raise DownloadError(f"HTTP error downloading {tool_name}: {e.code}") from e
        except urllib.error.URLError as e:
            raise DownloadError(f"URL error downloading {tool_name}: {e.reason}") from e
        except TimeoutError as e:
            raise DownloadError(f"Timeout downloading {tool_name}") from e

    def get_tool_path(self, name: str) -> Path | None:
        """Get path to an installed tool without downloading.

        Args:
            name: Tool name.

        Returns:
            Path if installed, None otherwise.
        """
        # Check our install directory first
        installed = self._find_installed(name)
        if installed:
            return installed

        # Check PATH
        path_tool = shutil.which(name)
        if path_tool:
            return Path(path_tool)

        return None


# Global installer instance
_installer: ToolInstaller | None = None


def get_installer() -> ToolInstaller:
    """Get the global installer instance."""
    global _installer
    if _installer is None:
        _installer = ToolInstaller()
    return _installer
