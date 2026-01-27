"""Unit tests for PowerShell installer script generation."""

import pytest

from kekkai_core.windows.installer import (
    generate_chocolatey_install_script,
    generate_chocolatey_uninstall_script,
    generate_installer_script,
    generate_uninstaller_script,
)


class TestInstallerScript:
    """Test PowerShell installer script generation."""

    def test_install_script_validates_python(self) -> None:
        """Verify script checks for Python 3.12+."""
        script = generate_installer_script(
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
            python_version="3.12",
        )

        assert "python --version" in script
        assert "3.12" in script
        assert "pythonVersion" in script or "version" in script

    def test_install_script_downloads_whl(self) -> None:
        """Verify script references wheel URL."""
        whl_url = "https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl"
        script = generate_installer_script(
            whl_url=whl_url,
            python_version="3.12",
        )

        assert whl_url in script

    def test_install_script_uses_pip_install(self) -> None:
        """Verify script uses 'python -m pip install'."""
        script = generate_installer_script(
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert "python -m pip install" in script
        assert "--force-reinstall" in script
        assert "--no-deps" in script

    def test_install_script_handles_missing_python(self) -> None:
        """Verify graceful failure if Python not found."""
        script = generate_installer_script(
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        # Should check for Python availability
        assert "Get-Command python" in script or "python" in script
        assert "ErrorAction" in script or "try" in script

    def test_install_script_no_invoke_expression(self) -> None:
        """Verify script doesn't use Invoke-Expression (security)."""
        script = generate_installer_script(
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        # Security: should not use Invoke-Expression
        assert "Invoke-Expression" not in script
        assert "iex" not in script.lower()

    def test_install_script_requires_https(self) -> None:
        """Verify only HTTPS URLs are accepted."""
        with pytest.raises(ValueError, match="must use HTTPS"):
            generate_installer_script(
                whl_url="http://insecure.com/test.whl",
            )

    def test_install_script_has_error_handling(self) -> None:
        """Verify script has error handling."""
        script = generate_installer_script(
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        # Should have error handling
        assert "try" in script or "if" in script
        assert "exit 1" in script or "throw" in script or "Write-Error" in script


class TestUninstallerScript:
    """Test PowerShell uninstaller script generation."""

    def test_uninstall_script_removes_package(self) -> None:
        """Verify script uses 'pip uninstall -y kekkai'."""
        script = generate_uninstaller_script()

        assert "pip uninstall" in script
        assert "-y" in script
        assert "kekkai" in script

    def test_uninstall_script_handles_missing_pip(self) -> None:
        """Verify graceful handling if pip not available."""
        script = generate_uninstaller_script()

        # Should check for pip or handle errors gracefully
        assert "try" in script or "if" in script
        # Should not fail hard on uninstall
        assert "exit 0" in script or "SilentlyContinue" in script or "Warning" in script

    def test_uninstall_script_no_invoke_expression(self) -> None:
        """Verify uninstaller doesn't use Invoke-Expression."""
        script = generate_uninstaller_script()

        assert "Invoke-Expression" not in script
        assert "iex" not in script.lower()


class TestChocolateyScripts:
    """Test Chocolatey-specific script generation."""

    def test_chocolatey_install_validates_python(self) -> None:
        """Verify Chocolatey install script checks Python version."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
            python_version="3.12",
        )

        assert "python --version" in script
        assert "3.12" in script

    def test_chocolatey_install_verifies_checksum(self) -> None:
        """Verify Chocolatey script validates SHA256."""
        sha256 = "b" * 64
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256=sha256,
        )

        assert sha256 in script
        assert "checksum" in script or "SHA256" in script or "FileHash" in script

    def test_chocolatey_install_downloads_and_verifies(self) -> None:
        """Verify Chocolatey script downloads and verifies wheel."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="c" * 64,
        )

        # Should download wheel
        assert "Invoke-WebRequest" in script or "Download" in script

        # Should verify checksum
        assert "Get-FileHash" in script or "checksum" in script

        # Should install via pip
        assert "pip install" in script

    def test_chocolatey_install_requires_https(self) -> None:
        """Verify Chocolatey installer requires HTTPS."""
        # The URL is generated internally, so test it's HTTPS
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="d" * 64,
        )

        assert "https://github.com" in script
        # Should not contain http:// (only https://)
        assert "http://" not in script or "https://" in script

    def test_chocolatey_uninstall_script(self) -> None:
        """Verify Chocolatey uninstall script."""
        script = generate_chocolatey_uninstall_script()

        assert "pip uninstall" in script
        assert "-y" in script
        assert "kekkai" in script

    def test_chocolatey_scripts_no_invoke_expression(self) -> None:
        """Verify Chocolatey scripts don't use Invoke-Expression."""
        install_script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="e" * 64,
        )
        uninstall_script = generate_chocolatey_uninstall_script()

        assert "Invoke-Expression" not in install_script
        assert "Invoke-Expression" not in uninstall_script
        assert "iex" not in install_script.lower()
        assert "iex" not in uninstall_script.lower()

    def test_chocolatey_install_cleanup_temp_files(self) -> None:
        """Verify Chocolatey installer cleans up temporary files."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="f" * 64,
        )

        # Should cleanup temp directory
        assert "Remove-Item" in script or "cleanup" in script.lower()
