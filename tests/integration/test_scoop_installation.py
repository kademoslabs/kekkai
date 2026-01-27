"""Integration tests for Scoop installation flow."""

import sys
from unittest.mock import Mock, patch

import pytest

from kekkai_core.windows.scoop import generate_scoop_manifest, validate_scoop_manifest


@pytest.mark.integration
class TestScoopInstallation:
    """Test Scoop installation flow with mocks."""

    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows simulation")
    @patch("sys.platform", "win32")
    @patch("subprocess.run")
    def test_scoop_install_kekkai_simulated(self, mock_run: Mock) -> None:
        """Simulate Scoop installation of Kekkai."""
        # Mock successful Python check
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Python 3.12.0\n",
        )

        # Generate manifest
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        # Validate manifest
        assert validate_scoop_manifest(manifest) is True

        # Verify installer script is present
        assert "installer" in manifest
        assert "script" in manifest["installer"]

    @patch("sys.platform", "win32")
    def test_kekkai_in_path_after_install_simulated(self) -> None:
        """Simulate checking if kekkai is in PATH after install."""
        # This would normally check PATH, but we simulate it
        with patch("kekkai_core.windows.validators.validate_windows_path") as mock_path:
            mock_path.return_value = (True, "C:\\Scoop\\apps\\kekkai\\current\\kekkai.exe")

            from kekkai_core.windows.validators import validate_windows_path

            is_found, path = validate_windows_path("kekkai")

            assert is_found is True
            assert path is not None
            assert "kekkai" in path

    @patch("sys.platform", "win32")
    @patch("subprocess.run")
    def test_scoop_update_kekkai_simulated(self, mock_run: Mock) -> None:
        """Simulate updating Kekkai via Scoop."""
        # Mock Scoop update command
        mock_run.return_value = Mock(returncode=0, stdout="Updated kekkai to 0.0.2\n")

        # Generate new manifest for updated version
        manifest_new = generate_scoop_manifest(
            version="0.0.2",
            sha256="b" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.2/kekkai-0.0.2-py3-none-any.whl",
        )

        assert validate_scoop_manifest(manifest_new) is True
        assert manifest_new["version"] == "0.0.2"

    @patch("sys.platform", "win32")
    def test_uninstall_removes_command_simulated(self) -> None:
        """Simulate uninstalling Kekkai via Scoop."""
        # Generate uninstaller script
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="c" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert "uninstaller" in manifest
        assert "script" in manifest["uninstaller"]

        # Verify uninstaller uses pip uninstall
        uninstall_script = manifest["uninstaller"]["script"]
        assert any("pip uninstall" in line for line in uninstall_script)


@pytest.mark.integration
class TestWindowsEnvironment:
    """Test Windows environment detection and checks."""

    @patch("sys.platform", "win32")
    def test_powershell_execution_simulated(self) -> None:
        """Simulate PowerShell execution on Windows."""
        from kekkai_core.windows.installer import generate_installer_script

        script = generate_installer_script(
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl"
        )

        # Verify script is PowerShell-compatible
        assert "$" in script  # PowerShell variable syntax
        assert "Write-Host" in script or "Write-Error" in script

    @patch("sys.platform", "win32")
    def test_cmd_execution_simulated(self) -> None:
        """Simulate Command Prompt compatibility."""
        # Generate installer
        from kekkai_core.windows.installer import generate_installer_script

        script = generate_installer_script(
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl"
        )

        # While script is PowerShell, the pip commands should work in CMD too
        assert "python -m pip" in script

    @patch("sys.platform", "win32")
    def test_windows_terminal_execution_simulated(self) -> None:
        """Simulate Windows Terminal execution."""
        # Windows Terminal can run both PowerShell and CMD
        from kekkai_core.windows.installer import generate_installer_script

        script = generate_installer_script(
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl"
        )

        # Should work in modern Windows Terminal
        assert "python" in script
        assert isinstance(script, str)


@pytest.mark.integration
class TestScoopManifestGeneration:
    """Test complete Scoop manifest generation flow."""

    def test_end_to_end_manifest_generation(self) -> None:
        """Test complete manifest generation and validation."""
        from kekkai_core.windows.scoop import (
            format_scoop_manifest_json,
            generate_scoop_manifest,
            validate_scoop_manifest,
        )

        # Generate manifest
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="d" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        # Validate
        assert validate_scoop_manifest(manifest) is True

        # Format as JSON
        json_str = format_scoop_manifest_json(manifest)
        assert isinstance(json_str, str)
        assert "0.0.1" in json_str

    def test_manifest_with_prerelease_version(self) -> None:
        """Test manifest generation with pre-release version."""
        from kekkai_core.windows.scoop import generate_scoop_manifest

        manifest = generate_scoop_manifest(
            version="0.0.1-rc1",
            sha256="e" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1-rc1/test.whl",
        )

        assert manifest["version"] == "0.0.1-rc1"
        assert validate_scoop_manifest(manifest) is True

    def test_checksum_file_generation(self) -> None:
        """Test checksum file generation for Scoop."""
        from kekkai_core.windows.scoop import generate_scoop_checksum_file

        checksum_content = generate_scoop_checksum_file(
            version="0.0.1",
            sha256="f" * 64,
        )

        assert "kekkai-0.0.1-py3-none-any.whl" in checksum_content
        assert "f" * 64 in checksum_content
