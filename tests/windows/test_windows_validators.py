"""Unit tests for Windows-specific validators."""

from pathlib import Path
from unittest.mock import Mock, patch

from kekkai_core.windows.validators import (
    validate_chocolatey_nuspec,
    validate_pip_available,
    validate_python_version,
    validate_scoop_format,
    validate_windows_path,
)


class TestPythonVersionValidation:
    """Test Python version validation."""

    def test_current_version_meets_requirement(self) -> None:
        """Verify current Python version validation."""
        # Current Python should be 3.12+ based on pyproject.toml
        is_valid, message = validate_python_version("3.12")

        assert isinstance(is_valid, bool)
        assert isinstance(message, str)
        # Should either pass or give clear message
        assert "Python" in message

    def test_lower_requirement_passes(self) -> None:
        """Verify lower requirement than current version passes."""
        is_valid, message = validate_python_version("3.8")

        assert is_valid is True
        assert "meets requirement" in message

    def test_future_requirement_fails(self) -> None:
        """Verify future Python version requirement fails."""
        is_valid, message = validate_python_version("99.99")

        assert is_valid is False
        assert "required" in message

    def test_invalid_version_format(self) -> None:
        """Verify invalid version format handled gracefully."""
        is_valid, message = validate_python_version("invalid")

        assert is_valid is False
        assert "Invalid" in message or "Failed" in message


class TestWindowsPathValidation:
    """Test Windows PATH validation."""

    @patch("subprocess.run")
    def test_executable_found_in_path(self, mock_run: Mock) -> None:
        """Verify executable found in PATH."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="/usr/bin/python\n",
        )

        is_found, path = validate_windows_path("python")

        assert is_found is True
        assert path == "/usr/bin/python"

    @patch("subprocess.run")
    def test_executable_not_found(self, mock_run: Mock) -> None:
        """Verify executable not in PATH."""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
        )

        is_found, path = validate_windows_path("nonexistent")

        assert is_found is False
        assert path is None

    @patch("subprocess.run")
    def test_timeout_handled_gracefully(self, mock_run: Mock) -> None:
        """Verify timeout handled gracefully."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("where", 5)

        is_found, path = validate_windows_path("python")

        assert is_found is False
        assert path is None

    @patch("subprocess.run")
    def test_command_not_found(self, mock_run: Mock) -> None:
        """Verify FileNotFoundError handled gracefully."""
        mock_run.side_effect = FileNotFoundError()

        is_found, path = validate_windows_path("python")

        assert is_found is False
        assert path is None

    @patch("sys.platform", "win32")
    @patch("subprocess.run")
    def test_windows_uses_where_command(self, mock_run: Mock) -> None:
        """Verify Windows platform uses 'where' command."""
        mock_run.return_value = Mock(returncode=0, stdout="C:\\Python\\python.exe\n")

        validate_windows_path("python")

        # Verify 'where' was called on Windows
        assert mock_run.called
        args = mock_run.call_args[0][0]
        assert args[0] == "where"

    @patch("sys.platform", "linux")
    @patch("subprocess.run")
    def test_linux_uses_which_command(self, mock_run: Mock) -> None:
        """Verify Linux platform uses 'which' command."""
        mock_run.return_value = Mock(returncode=0, stdout="/usr/bin/python\n")

        validate_windows_path("python")

        # Verify 'which' was called on Linux
        assert mock_run.called
        args = mock_run.call_args[0][0]
        assert args[0] == "which"


class TestPipAvailability:
    """Test pip availability validation."""

    @patch("subprocess.run")
    def test_pip_available(self, mock_run: Mock) -> None:
        """Verify pip availability check."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="pip 24.0 from /path/to/pip\n",
        )

        is_available, message = validate_pip_available()

        assert is_available is True
        assert "pip is available" in message

    @patch("subprocess.run")
    def test_pip_not_available(self, mock_run: Mock) -> None:
        """Verify pip not available."""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
        )

        is_available, message = validate_pip_available()

        assert is_available is False
        assert "not available" in message

    @patch("subprocess.run")
    def test_pip_timeout(self, mock_run: Mock) -> None:
        """Verify timeout handled gracefully."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("pip", 10)

        is_available, message = validate_pip_available()

        assert is_available is False
        assert "Failed to check pip" in message


class TestScoopFormatValidation:
    """Test Scoop manifest format validation."""

    def test_valid_manifest_passes(self, tmp_path: Path) -> None:
        """Verify valid Scoop manifest passes validation."""
        manifest_file = tmp_path / "kekkai.json"
        manifest_file.write_text(
            """{
            "version": "0.0.1",
            "description": "Test",
            "homepage": "https://test.com",
            "license": "MIT",
            "url": "https://test.com/file.whl",
            "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }"""
        )

        is_valid, errors = validate_scoop_format(manifest_file)

        assert is_valid is True
        assert len(errors) == 0

    def test_missing_file_fails(self, tmp_path: Path) -> None:
        """Verify missing file fails validation."""
        manifest_file = tmp_path / "nonexistent.json"

        is_valid, errors = validate_scoop_format(manifest_file)

        assert is_valid is False
        assert len(errors) > 0
        assert any("not found" in error for error in errors)

    def test_invalid_json_fails(self, tmp_path: Path) -> None:
        """Verify invalid JSON fails validation."""
        manifest_file = tmp_path / "invalid.json"
        manifest_file.write_text("{ invalid json }")

        is_valid, errors = validate_scoop_format(manifest_file)

        assert is_valid is False
        assert len(errors) > 0
        assert any("JSON" in error for error in errors)

    def test_missing_required_fields_fails(self, tmp_path: Path) -> None:
        """Verify missing required fields fail validation."""
        manifest_file = tmp_path / "incomplete.json"
        manifest_file.write_text('{"version": "0.0.1"}')

        is_valid, errors = validate_scoop_format(manifest_file)

        assert is_valid is False
        assert len(errors) > 0
        assert any("Missing required field" in error for error in errors)

    def test_invalid_version_format_fails(self, tmp_path: Path) -> None:
        """Verify invalid version format fails."""
        manifest_file = tmp_path / "badversion.json"
        manifest_file.write_text(
            """{
            "version": "1.2",
            "description": "Test",
            "homepage": "https://test.com",
            "license": "MIT",
            "url": "https://test.com/file.whl",
            "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }"""
        )

        is_valid, errors = validate_scoop_format(manifest_file)

        assert is_valid is False
        assert any("Invalid version format" in error for error in errors)

    def test_non_https_url_fails(self, tmp_path: Path) -> None:
        """Verify non-HTTPS URL fails."""
        manifest_file = tmp_path / "http.json"
        manifest_file.write_text(
            """{
            "version": "0.0.1",
            "description": "Test",
            "homepage": "https://test.com",
            "license": "MIT",
            "url": "http://test.com/file.whl",
            "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }"""
        )

        is_valid, errors = validate_scoop_format(manifest_file)

        assert is_valid is False
        assert any("must use HTTPS" in error for error in errors)

    def test_invalid_sha256_fails(self, tmp_path: Path) -> None:
        """Verify invalid SHA256 format fails."""
        manifest_file = tmp_path / "badsha.json"
        manifest_file.write_text(
            """{
            "version": "0.0.1",
            "description": "Test",
            "homepage": "https://test.com",
            "license": "MIT",
            "url": "https://test.com/file.whl",
            "hash": "short"
        }"""
        )

        is_valid, errors = validate_scoop_format(manifest_file)

        assert is_valid is False
        assert any("Invalid SHA256 format" in error for error in errors)


class TestChocolateyNuspecValidation:
    """Test Chocolatey .nuspec validation."""

    def test_valid_nuspec_passes(self, tmp_path: Path) -> None:
        """Verify valid .nuspec passes validation."""
        nuspec_file = tmp_path / "kekkai.nuspec"
        nuspec_file.write_text(
            """<?xml version="1.0"?>
        <package>
            <metadata>
                <id>kekkai</id>
                <version>0.0.1</version>
                <authors>Kademos Labs</authors>
                <description>Test package</description>
            </metadata>
        </package>"""
        )

        is_valid, errors = validate_chocolatey_nuspec(nuspec_file)

        assert is_valid is True
        assert len(errors) == 0

    def test_missing_file_fails(self, tmp_path: Path) -> None:
        """Verify missing file fails validation."""
        nuspec_file = tmp_path / "nonexistent.nuspec"

        is_valid, errors = validate_chocolatey_nuspec(nuspec_file)

        assert is_valid is False
        assert len(errors) > 0

    def test_invalid_xml_fails(self, tmp_path: Path) -> None:
        """Verify invalid XML fails validation."""
        nuspec_file = tmp_path / "invalid.nuspec"
        nuspec_file.write_text("<invalid xml")

        is_valid, errors = validate_chocolatey_nuspec(nuspec_file)

        assert is_valid is False
        assert any("XML" in error for error in errors)

    def test_missing_metadata_fails(self, tmp_path: Path) -> None:
        """Verify missing metadata element fails."""
        nuspec_file = tmp_path / "nometadata.nuspec"
        nuspec_file.write_text('<?xml version="1.0"?><package></package>')

        is_valid, errors = validate_chocolatey_nuspec(nuspec_file)

        assert is_valid is False
        assert any("metadata" in error.lower() for error in errors)

    def test_missing_required_fields_fails(self, tmp_path: Path) -> None:
        """Verify missing required fields fail."""
        nuspec_file = tmp_path / "incomplete.nuspec"
        nuspec_file.write_text(
            """<?xml version="1.0"?>
        <package>
            <metadata>
                <id>kekkai</id>
            </metadata>
        </package>"""
        )

        is_valid, errors = validate_chocolatey_nuspec(nuspec_file)

        assert is_valid is False
        assert any("Missing required field" in error for error in errors)
