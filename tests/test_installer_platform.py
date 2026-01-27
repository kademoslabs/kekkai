"""Unit tests for installer platform detection."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from kekkai.installer import UnsupportedPlatformError, get_platform_key
from kekkai.installer.manifest import ToolManifest, get_download_url


class TestGetPlatformKey:
    """Test platform key detection."""

    def test_linux_amd64(self) -> None:
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="x86_64"),
        ):
            assert get_platform_key() == "linux_amd64"

    def test_linux_arm64(self) -> None:
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="aarch64"),
        ):
            assert get_platform_key() == "linux_arm64"

    def test_darwin_amd64(self) -> None:
        with (
            patch("platform.system", return_value="Darwin"),
            patch("platform.machine", return_value="x86_64"),
        ):
            assert get_platform_key() == "darwin_amd64"

    def test_darwin_arm64(self) -> None:
        with (
            patch("platform.system", return_value="Darwin"),
            patch("platform.machine", return_value="arm64"),
        ):
            assert get_platform_key() == "darwin_arm64"

    def test_windows_amd64(self) -> None:
        with (
            patch("platform.system", return_value="Windows"),
            patch("platform.machine", return_value="AMD64"),
        ):
            assert get_platform_key() == "windows_amd64"

    def test_unsupported_architecture(self) -> None:
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="mips"),
            pytest.raises(UnsupportedPlatformError, match="Unsupported architecture"),
        ):
            get_platform_key()

    def test_unsupported_os(self) -> None:
        with (
            patch("platform.system", return_value="FreeBSD"),
            patch("platform.machine", return_value="x86_64"),
            pytest.raises(UnsupportedPlatformError, match="Unsupported OS"),
        ):
            get_platform_key()


class TestGetDownloadUrl:
    """Test download URL generation."""

    def test_trivy_url_linux(self) -> None:
        manifest = ToolManifest(
            name="trivy",
            version="0.58.1",
            url_template="https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_{os}-{arch}.tar.gz",
            sha256={"linux_amd64": "abc123"},
        )

        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="x86_64"),
        ):
            url = get_download_url(manifest)
            assert "trivy_0.58.1_Linux-64bit.tar.gz" in url
            assert "github.com/aquasecurity/trivy" in url

    def test_gitleaks_url_darwin(self) -> None:
        manifest = ToolManifest(
            name="gitleaks",
            version="8.21.2",
            url_template="https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_{os}_{arch}.tar.gz",
            sha256={"darwin_arm64": "abc123"},
        )

        with (
            patch("platform.system", return_value="Darwin"),
            patch("platform.machine", return_value="arm64"),
        ):
            url = get_download_url(manifest)
            assert "gitleaks_8.21.2_darwin_arm64.tar.gz" in url
