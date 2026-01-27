"""Integration tests for installer end-to-end workflow."""

from __future__ import annotations

import hashlib
import tarfile
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kekkai.installer import (
    DownloadError,
    SecurityError,
    ToolInstaller,
)
from kekkai.installer.manifest import ToolManifest


@pytest.mark.integration
class TestInstallerE2E:
    """End-to-end tests for tool installer."""

    def _create_mock_tarball(self, binary_name: str, binary_content: bytes) -> bytes:
        """Create a mock tar.gz archive with a binary."""
        buffer = BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            data = BytesIO(binary_content)
            info = tarfile.TarInfo(name=binary_name)
            info.size = len(binary_content)
            tar.addfile(info, data)
        return buffer.getvalue()

    def test_full_download_verify_extract_flow(self, tmp_path: Path) -> None:
        """Test complete installation flow with mocked download."""
        install_dir = tmp_path / "bin"
        installer = ToolInstaller(install_dir=install_dir)

        # Create mock binary and archive
        binary_content = b"#!/bin/sh\necho 'mock trivy'"
        archive_content = self._create_mock_tarball("trivy", binary_content)
        archive_hash = hashlib.sha256(archive_content).hexdigest()

        # Create mock manifest with correct hash
        mock_manifest = ToolManifest(
            name="trivy",
            version="0.58.1",
            url_template="https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy.tar.gz",
            sha256={"linux_amd64": archive_hash, "darwin_amd64": archive_hash},
            binary_name="trivy",
        )

        # Mock download and platform
        def mock_urlopen(*args: object, **kwargs: object) -> MagicMock:
            response = MagicMock()
            response.status = 200
            response.headers = {"Content-Length": str(len(archive_content))}
            response.read.return_value = archive_content
            response.__enter__ = lambda s: s
            response.__exit__ = MagicMock(return_value=False)
            return response

        with (
            patch("kekkai.installer.manifest.get_platform_key", return_value="linux_amd64"),
            patch("kekkai.installer.manager.get_manifest", return_value=mock_manifest),
            patch("urllib.request.urlopen", mock_urlopen),
            patch("shutil.which", return_value=None),
        ):
            result = installer.ensure_tool("trivy", auto_install=True)

        assert result.exists()
        assert result.name == "trivy"
        assert result.read_bytes() == binary_content
        assert result.stat().st_mode & 0o755

    def test_checksum_mismatch_blocks_install(self, tmp_path: Path) -> None:
        """Test that checksum mismatch prevents installation."""
        installer = ToolInstaller(install_dir=tmp_path)

        archive_content = b"tampered content"

        mock_manifest = ToolManifest(
            name="trivy",
            version="0.58.1",
            url_template="https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy.tar.gz",
            sha256={"linux_amd64": "wrong_hash_should_fail"},
            binary_name="trivy",
        )

        def mock_urlopen(*args: object, **kwargs: object) -> MagicMock:
            response = MagicMock()
            response.status = 200
            response.headers = {"Content-Length": str(len(archive_content))}
            response.read.return_value = archive_content
            response.__enter__ = lambda s: s
            response.__exit__ = MagicMock(return_value=False)
            return response

        with (
            patch("kekkai.installer.manifest.get_platform_key", return_value="linux_amd64"),
            patch("kekkai.installer.manager.get_manifest", return_value=mock_manifest),
            patch("urllib.request.urlopen", mock_urlopen),
            patch("shutil.which", return_value=None),
            pytest.raises(SecurityError, match="Checksum mismatch"),
        ):
            installer.ensure_tool("trivy", auto_install=True)

        # Verify no partial files left
        assert not (tmp_path / "trivy").exists()

    def test_offline_graceful_failure(self, tmp_path: Path) -> None:
        """Test graceful failure when offline."""
        import urllib.error

        installer = ToolInstaller(install_dir=tmp_path)

        def mock_urlopen_offline(*args: object, **kwargs: object) -> None:
            raise urllib.error.URLError("Network unreachable")

        with (
            patch("kekkai.installer.manifest.get_platform_key", return_value="linux_amd64"),
            patch("urllib.request.urlopen", mock_urlopen_offline),
            patch("shutil.which", return_value=None),
            pytest.raises(DownloadError, match="URL error"),
        ):
            installer.ensure_tool("trivy", auto_install=True)

    def test_tool_from_path_takes_precedence(self, tmp_path: Path) -> None:
        """Test that PATH tools are used without download."""
        installer = ToolInstaller(install_dir=tmp_path)

        with patch("shutil.which", return_value="/usr/local/bin/trivy"):
            result = installer.ensure_tool("trivy")

        assert result == Path("/usr/local/bin/trivy")

    def test_already_installed_skips_download(self, tmp_path: Path) -> None:
        """Test that already installed tools don't trigger download."""
        install_dir = tmp_path / "bin"
        install_dir.mkdir()

        # Pre-install the tool
        tool_path = install_dir / "trivy"
        tool_path.write_bytes(b"pre-installed binary")
        tool_path.chmod(0o755)

        installer = ToolInstaller(install_dir=install_dir)

        # Should return immediately without any network calls
        with patch("urllib.request.urlopen") as mock_url:
            result = installer.ensure_tool("trivy")
            mock_url.assert_not_called()

        assert result == tool_path


@pytest.mark.integration
class TestInstallerNativeIntegration:
    """Test installer integration with native backend."""

    def test_native_backend_finds_kekkai_bin(self, tmp_path: Path) -> None:
        """Test that native backend checks ~/.kekkai/bin/."""
        from kekkai.scanners.backends.native import detect_tool

        # Create mock installed tool
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        tool_path = bin_dir / "trivy"
        tool_path.write_text("#!/bin/sh\necho 'Version: 0.58.1'")
        tool_path.chmod(0o755)

        with (
            patch("shutil.which", return_value=None),
            patch("kekkai.paths.bin_dir", return_value=bin_dir),
        ):
            info = detect_tool("trivy", min_version=(0, 40, 0))

        assert info.name == "trivy"
        assert info.version == "0.58.1"

    def test_native_backend_prefers_path_tools(self, tmp_path: Path) -> None:
        """Test that PATH tools take precedence over kekkai bin."""
        from kekkai.scanners.backends.native import detect_tool

        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        kekkai_tool = bin_dir / "trivy"
        kekkai_tool.write_text("#!/bin/sh\necho 'Version: 0.50.0'")
        kekkai_tool.chmod(0o755)

        # Mock a PATH tool that takes precedence
        path_tool = tmp_path / "path_trivy"
        path_tool.write_text("#!/bin/sh\necho 'Version: 0.58.1'")
        path_tool.chmod(0o755)

        with (
            patch("shutil.which", return_value=str(path_tool)),
            patch("kekkai.paths.bin_dir", return_value=bin_dir),
        ):
            info = detect_tool("trivy", min_version=(0, 40, 0))

        # Should use PATH tool, not kekkai bin
        assert str(path_tool) in info.path
