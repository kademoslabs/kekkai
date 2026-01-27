"""Integration tests for Windows environment validation."""

from unittest.mock import Mock, patch

import pytest

from kekkai_core.windows.validators import (
    validate_pip_available,
    validate_python_version,
    validate_windows_path,
)


@pytest.mark.integration
class TestPythonEnvironmentIntegration:
    """Test Python environment validation integration."""

    def test_python_version_check_real(self) -> None:
        """Test real Python version check."""
        is_valid, message = validate_python_version("3.8")

        # Should pass for Python 3.12+
        assert is_valid is True
        assert "Python" in message
        assert "meets requirement" in message

    def test_pip_availability_real(self) -> None:
        """Test real pip availability check."""
        is_available, message = validate_pip_available()

        # Should have pip in test environment
        assert is_available is True
        assert "pip" in message.lower()

    def test_python_in_path_real(self) -> None:
        """Test that Python is in PATH."""
        is_found, path = validate_windows_path("python")

        # Should find python in PATH
        assert is_found is True
        assert path is not None
        assert "python" in path.lower()


@pytest.mark.integration
class TestWindowsPathIntegration:
    """Test Windows PATH integration."""

    def test_find_python_executable(self) -> None:
        """Test finding Python executable in PATH."""
        is_found, path = validate_windows_path("python")

        assert is_found is True
        assert path is not None

    def test_nonexistent_executable_not_found(self) -> None:
        """Test that nonexistent executables are not found."""
        is_found, path = validate_windows_path("this_command_does_not_exist_12345")

        assert is_found is False
        assert path is None

    @patch("subprocess.run")
    def test_windows_platform_detection(self, mock_run: Mock) -> None:
        """Test platform-specific command detection."""
        mock_run.return_value = Mock(returncode=0, stdout="/path/to/python\n")

        # Should work on any platform with mocking
        is_found, path = validate_windows_path("python")

        assert is_found is True
        assert mock_run.called


@pytest.mark.integration
class TestInstallerIntegration:
    """Test installer script integration."""

    def test_installer_script_generation_complete(self) -> None:
        """Test complete installer script generation."""
        from kekkai_core.windows.installer import generate_installer_script

        script = generate_installer_script(
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
            python_version="3.12",
        )

        # Verify script components
        assert "python" in script
        assert "pip" in script
        assert "3.12" in script
        assert "github.com" in script

    def test_uninstaller_script_generation_complete(self) -> None:
        """Test complete uninstaller script generation."""
        from kekkai_core.windows.installer import generate_uninstaller_script

        script = generate_uninstaller_script()

        assert "pip uninstall" in script
        assert "kekkai" in script


@pytest.mark.integration
class TestChocolateyIntegration:
    """Test Chocolatey integration."""

    def test_chocolatey_install_script_complete(self) -> None:
        """Test complete Chocolatey install script generation."""
        from kekkai_core.windows.installer import generate_chocolatey_install_script

        script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="a" * 64,
            python_version="3.12",
        )

        # Verify all components present
        assert "0.0.1" in script
        assert "a" * 64 in script
        assert "3.12" in script
        assert "python" in script
        assert "pip" in script
        assert "github.com" in script

    def test_chocolatey_uninstall_script_complete(self) -> None:
        """Test complete Chocolatey uninstall script generation."""
        from kekkai_core.windows.installer import generate_chocolatey_uninstall_script

        script = generate_chocolatey_uninstall_script()

        assert "pip uninstall" in script
        assert "kekkai" in script


@pytest.mark.integration
class TestEndToEndWindowsSupport:
    """Test end-to-end Windows support."""

    def test_complete_scoop_workflow(self) -> None:
        """Test complete Scoop workflow from manifest to validation."""
        from kekkai_core.windows.scoop import (
            format_scoop_manifest_json,
            generate_scoop_manifest,
            validate_scoop_manifest,
        )

        # Generate manifest
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="b" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        # Validate
        is_valid = validate_scoop_manifest(manifest)
        assert is_valid is True

        # Format
        json_str = format_scoop_manifest_json(manifest)
        assert "0.0.1" in json_str

    def test_complete_chocolatey_workflow(self) -> None:
        """Test complete Chocolatey workflow."""
        from kekkai_core.windows.installer import (
            generate_chocolatey_install_script,
            generate_chocolatey_uninstall_script,
        )

        # Generate install script
        install_script = generate_chocolatey_install_script(
            version="0.0.1",
            sha256="c" * 64,
        )
        assert "0.0.1" in install_script

        # Generate uninstall script
        uninstall_script = generate_chocolatey_uninstall_script()
        assert "kekkai" in uninstall_script

    def test_python_validation_workflow(self) -> None:
        """Test Python validation workflow."""
        # Check Python version
        is_valid, msg = validate_python_version("3.12")
        assert isinstance(is_valid, bool)

        # Check pip
        is_available, pip_msg = validate_pip_available()
        assert isinstance(is_available, bool)

        # Check Python in PATH
        is_found, path = validate_windows_path("python")
        assert isinstance(is_found, bool)
