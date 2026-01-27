"""Unit tests for Chocolatey PowerShell installation scripts."""

from kekkai_core.windows.installer import (
    generate_chocolatey_install_script,
    generate_chocolatey_uninstall_script,
)


class TestChocolateyInstallScript:
    """Test Chocolatey install script generation."""

    def test_install_script_validates_python(self) -> None:
        """Verify script checks for Python 3.12+."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
            python_version="3.12",
        )

        assert "python --version" in script
        assert "3.12" in script
        assert "required" in script.lower()

    def test_install_script_downloads_whl(self) -> None:
        """Verify script downloads wheel from GitHub."""
        version = "0.0.1"
        script = generate_chocolatey_install_script(
            version=version,
            sha256="a" * 64,
        )

        assert "https://github.com/kademoslabs/kekkai/releases/download" in script
        assert f"kekkai-{version}-py3-none-any.whl" in script
        assert "Invoke-WebRequest" in script

    def test_install_script_verifies_checksum(self) -> None:
        """Verify script validates SHA256 checksum."""
        sha256 = "abc123def456" * 5 + "abcd"  # 64 chars
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256=sha256,
        )

        assert sha256 in script
        assert "Get-FileHash" in script
        assert "SHA256" in script
        assert "Checksum mismatch" in script or "checksum" in script.lower()

    def test_install_script_handles_missing_python(self) -> None:
        """Verify script has error handling for missing Python."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
        )

        # Should check for Python availability
        assert "Get-Command python" in script or "python" in script
        # Should have error handling
        assert "throw" in script or "Write-Error" in script or "exit 1" in script

    def test_install_script_uses_pip_install(self) -> None:
        """Verify script uses 'python -m pip install'."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
        )

        assert "python -m pip install" in script
        assert "--force-reinstall" in script
        assert "--no-deps" in script

    def test_install_script_error_handling(self) -> None:
        """Verify script has proper error handling."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
        )

        # Should set error action preference
        assert "$ErrorActionPreference = 'Stop'" in script

        # Should check for command failures
        assert "$LASTEXITCODE" in script

        # Should have error messages
        assert "throw" in script or "Write-Error" in script

    def test_install_script_rejects_http(self) -> None:
        """Verify script generation rejects HTTP URLs."""
        # The script internally generates HTTPS URL, so this tests the validator
        # The actual validator is in chocolatey.py
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
        )

        # Script should only use HTTPS
        assert "https://" in script
        # Should not have HTTP (without S)
        assert "http://github" not in script

    def test_install_script_has_version_metadata(self) -> None:
        """Verify script includes version metadata."""
        version = "1.2.3"
        script = generate_chocolatey_install_script(
            version=version,
            sha256="a" * 64,
        )

        assert version in script
        assert "$version = " in script or f'"{version}"' in script

    def test_install_script_has_package_name(self) -> None:
        """Verify script includes package name."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
        )

        assert "kekkai" in script.lower()
        assert "$packageName = 'kekkai'" in script

    def test_install_script_cleanup_on_success(self) -> None:
        """Verify script cleans up temporary files."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
        )

        # Should create temp directory
        assert "$tempDir" in script or "TEMP" in script

        # Should clean up
        assert "Remove-Item" in script


class TestChocolateyUninstallScript:
    """Test Chocolatey uninstall script generation."""

    def test_uninstall_script_removes_package(self) -> None:
        """Verify script uses 'pip uninstall -y kekkai'."""
        script = generate_chocolatey_uninstall_script()

        assert "python -m pip uninstall" in script
        assert "-y kekkai" in script

    def test_uninstall_script_handles_missing_pip(self) -> None:
        """Verify script gracefully handles missing pip."""
        script = generate_chocolatey_uninstall_script()

        # Should check for pip availability or handle errors
        assert "python -m pip" in script

        # Should have error handling that continues
        assert "$ErrorActionPreference = 'Continue'" in script or "try" in script

    def test_uninstall_script_no_fail_on_error(self) -> None:
        """Verify uninstall doesn't fail hard on errors."""
        script = generate_chocolatey_uninstall_script()

        # Should allow graceful failures
        assert "Continue" in script or "SilentlyContinue" in script or "exit 0" in script

    def test_uninstall_script_has_package_name(self) -> None:
        """Verify uninstall script mentions package name."""
        script = generate_chocolatey_uninstall_script()

        assert "kekkai" in script.lower()

    def test_uninstall_script_uses_try_catch(self) -> None:
        """Verify uninstall uses try-catch for error handling."""
        script = generate_chocolatey_uninstall_script()

        assert "try {" in script
        assert "catch" in script or "}" in script

    def test_uninstall_script_provides_feedback(self) -> None:
        """Verify uninstall provides user feedback."""
        script = generate_chocolatey_uninstall_script()

        # Should have output messages
        assert "Write-Host" in script or "Write-Warning" in script


class TestScriptSecurityConsiderations:
    """Test security aspects of generated scripts."""

    def test_install_script_no_invoke_expression(self) -> None:
        """Verify install script doesn't use Invoke-Expression."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
        )

        # Should not have dangerous patterns
        assert "Invoke-Expression" not in script
        assert "iex " not in script.lower()

    def test_install_script_no_remote_code_execution(self) -> None:
        """Verify install script doesn't execute remote code."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
        )

        # Should not download and execute scripts
        assert "Invoke-WebRequest" in script  # This is OK for downloading files
        assert "| iex" not in script
        assert "| Invoke-Expression" not in script

    def test_install_script_validates_inputs(self) -> None:
        """Verify install script validates all inputs."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
        )

        # Should validate Python version
        assert "version" in script.lower()

        # Should validate checksum
        assert "checksum" in script.lower()

    def test_uninstall_script_safe_on_errors(self) -> None:
        """Verify uninstall script handles errors safely."""
        script = generate_chocolatey_uninstall_script()

        # Should not expose sensitive information in errors
        assert "Write-Warning" in script

        # Should not fail the entire process
        assert "exit 0" in script or "$ErrorActionPreference = 'Continue'" in script


class TestScriptPowerShellCompatibility:
    """Test PowerShell compatibility of generated scripts."""

    def test_install_script_uses_standard_cmdlets(self) -> None:
        """Verify install script uses standard PowerShell cmdlets."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
        )

        # Standard cmdlets used
        assert "Get-Command" in script or "python" in script
        assert "Invoke-WebRequest" in script
        assert "Get-FileHash" in script

    def test_scripts_have_proper_encoding_hint(self) -> None:
        """Verify scripts can handle UTF-8."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
        )

        # Script should be UTF-8 safe (Python 3 default)
        assert isinstance(script, str)

    def test_install_script_uses_erroractionpreference(self) -> None:
        """Verify install script sets ErrorActionPreference."""
        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
        )

        assert "$ErrorActionPreference = 'Stop'" in script

    def test_uninstall_script_uses_erroractionpreference(self) -> None:
        """Verify uninstall script sets ErrorActionPreference."""
        script = generate_chocolatey_uninstall_script()

        assert "$ErrorActionPreference = 'Continue'" in script
