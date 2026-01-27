"""Unit tests for installer manager."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from kekkai.installer import InstallerError, ToolInstaller
from kekkai.installer.manager import get_installer


class TestToolInstaller:
    """Test ToolInstaller class."""

    def test_init_creates_install_dir(self, tmp_path: Path) -> None:
        install_dir = tmp_path / "bin"
        assert not install_dir.exists()

        ToolInstaller(install_dir=install_dir)

        assert install_dir.exists()

    def test_find_installed_finds_existing_tool(self, tmp_path: Path) -> None:
        install_dir = tmp_path / "bin"
        install_dir.mkdir()

        # Create a fake installed tool
        tool_path = install_dir / "trivy"
        tool_path.write_bytes(b"fake binary")
        tool_path.chmod(0o755)

        installer = ToolInstaller(install_dir=install_dir)
        found = installer._find_installed("trivy")

        assert found is not None
        assert found == tool_path

    def test_find_installed_returns_none_if_missing(self, tmp_path: Path) -> None:
        installer = ToolInstaller(install_dir=tmp_path)
        found = installer._find_installed("nonexistent")

        assert found is None

    def test_ensure_tool_uses_installed(self, tmp_path: Path) -> None:
        install_dir = tmp_path / "bin"
        install_dir.mkdir()

        tool_path = install_dir / "trivy"
        tool_path.write_bytes(b"fake binary")
        tool_path.chmod(0o755)

        installer = ToolInstaller(install_dir=install_dir)
        result = installer.ensure_tool("trivy")

        assert result == tool_path

    def test_ensure_tool_uses_path(self, tmp_path: Path) -> None:
        installer = ToolInstaller(install_dir=tmp_path)

        with patch("shutil.which", return_value="/usr/bin/trivy"):
            result = installer.ensure_tool("trivy")

        assert result == Path("/usr/bin/trivy")

    def test_ensure_tool_raises_for_unknown(self, tmp_path: Path) -> None:
        installer = ToolInstaller(install_dir=tmp_path)

        with (
            patch("shutil.which", return_value=None),
            pytest.raises(InstallerError, match="Unknown tool"),
        ):
            installer.ensure_tool("unknown_tool", auto_install=True)

    def test_ensure_tool_requires_auto_install(self, tmp_path: Path) -> None:
        installer = ToolInstaller(install_dir=tmp_path)

        with (
            patch("shutil.which", return_value=None),
            pytest.raises(InstallerError, match="auto-install"),
        ):
            installer.ensure_tool("trivy", auto_install=False)

    def test_ensure_tool_rejects_placeholder_hash(self, tmp_path: Path) -> None:
        installer = ToolInstaller(install_dir=tmp_path)

        # semgrep has placeholder hashes
        with (
            patch("shutil.which", return_value=None),
            pytest.raises(InstallerError, match="not yet configured"),
        ):
            installer.ensure_tool("semgrep", auto_install=True)

    def test_get_tool_path_returns_installed(self, tmp_path: Path) -> None:
        install_dir = tmp_path / "bin"
        install_dir.mkdir()

        tool_path = install_dir / "trivy"
        tool_path.write_bytes(b"binary")
        tool_path.chmod(0o755)

        installer = ToolInstaller(install_dir=install_dir)
        result = installer.get_tool_path("trivy")

        assert result == tool_path

    def test_get_tool_path_returns_path_tool(self, tmp_path: Path) -> None:
        installer = ToolInstaller(install_dir=tmp_path)

        with patch("shutil.which", return_value="/usr/bin/trivy"):
            result = installer.get_tool_path("trivy")

        assert result == Path("/usr/bin/trivy")

    def test_get_tool_path_returns_none_if_missing(self, tmp_path: Path) -> None:
        installer = ToolInstaller(install_dir=tmp_path)

        with patch("shutil.which", return_value=None):
            result = installer.get_tool_path("nonexistent")

        assert result is None


class TestGetInstaller:
    """Test global installer instance."""

    def test_get_installer_returns_instance(self) -> None:
        with (
            patch("kekkai.installer.manager._installer", None),
            patch("kekkai.paths.bin_dir", return_value=Path("/tmp/test")),
        ):
            installer = get_installer()
            assert isinstance(installer, ToolInstaller)

    def test_get_installer_returns_same_instance(self) -> None:
        with (
            patch("kekkai.installer.manager._installer", None),
            patch("kekkai.paths.bin_dir", return_value=Path("/tmp/test")),
        ):
            first = get_installer()
            second = get_installer()
            assert first is second
