"""Unit tests for cross-platform compatibility."""

import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest


class TestCrossPlatformPathHandling:
    """Test path handling across different platforms."""

    def test_path_normalization_unix_style(self) -> None:
        """Verify Unix-style paths work on all platforms."""
        path = Path("src/kekkai/cli.py")
        assert path.parts[0] == "src"
        assert path.parts[1] == "kekkai"
        assert path.parts[2] == "cli.py"

    def test_path_normalization_absolute(self, tmp_path: Path) -> None:
        """Verify absolute paths work correctly."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        assert test_file.exists()
        assert test_file.is_absolute()

    def test_path_join_cross_platform(self) -> None:
        """Verify path joining works on all platforms."""
        base = Path("base")
        sub = base / "sub" / "file.txt"

        # Should work regardless of platform path separator
        assert str(sub).replace("\\", "/") == "base/sub/file.txt"

    def test_home_directory_expansion(self) -> None:
        """Verify home directory expansion works."""
        home = Path.home()
        assert home.exists()
        assert home.is_absolute()

    @pytest.mark.skipif(sys.platform.startswith("win"), reason="Unix path test")
    def test_unix_path_with_forward_slashes(self) -> None:
        """Verify forward slashes work on Unix."""
        path = Path("/usr/local/bin")
        assert path.parts[0] == "/"
        assert "usr" in path.parts

    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows path test")
    def test_windows_path_with_backslashes(self) -> None:
        """Verify backslashes work on Windows."""
        path = Path("C:\\Windows\\System32")
        assert path.parts[0] == "C:\\"


class TestLineEndingNormalization:
    """Test line ending handling across platforms."""

    def test_read_text_normalizes_line_endings(self, tmp_path: Path) -> None:
        """Verify text reading normalizes line endings."""
        test_file = tmp_path / "test.txt"

        # Write with CRLF (Windows style)
        test_file.write_bytes(b"line1\r\nline2\r\nline3")

        # Read as text - should normalize to \n
        content = test_file.read_text()
        lines = content.splitlines()

        assert len(lines) == 3
        assert lines[0] == "line1"
        assert lines[2] == "line3"

    def test_write_text_uses_platform_default(self, tmp_path: Path) -> None:
        """Verify text writing uses platform line endings."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("line1\nline2\nline3")

        # Content should be written successfully
        assert test_file.exists()
        content = test_file.read_text()
        assert "line1" in content
        assert "line3" in content


class TestPythonEnvironmentDetection:
    """Test Python environment detection across platforms."""

    def test_python_version_detection(self) -> None:
        """Verify Python version is detected correctly."""
        version_info = sys.version_info
        assert version_info.major == 3
        assert version_info.minor >= 12

    def test_python_executable_path(self) -> None:
        """Verify Python executable path is valid."""
        python_exe = sys.executable
        assert Path(python_exe).exists()
        assert Path(python_exe).is_file()

    def test_platform_detection(self) -> None:
        """Verify platform is detected correctly."""
        system = platform.system()
        assert system in ["Linux", "Darwin", "Windows"]

    def test_architecture_detection(self) -> None:
        """Verify architecture is detected correctly."""
        machine = platform.machine()
        assert machine in ["x86_64", "AMD64", "arm64", "aarch64"]

    def test_python_implementation(self) -> None:
        """Verify Python implementation."""
        impl = platform.python_implementation()
        assert impl == "CPython"


class TestPlatformSpecificCommands:
    """Test platform-specific command execution."""

    @pytest.mark.skipif(sys.platform.startswith("win"), reason="Unix command test")
    def test_unix_shell_command(self) -> None:
        """Verify Unix shell commands work."""
        result = subprocess.run(
            ["echo", "test"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == "test"
        assert result.returncode == 0

    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows command test")
    def test_windows_command(self) -> None:
        """Verify Windows commands work."""
        result = subprocess.run(
            ["cmd", "/c", "echo", "test"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "test" in result.stdout
        assert result.returncode == 0

    def test_python_version_command(self) -> None:
        """Verify python --version works on all platforms."""
        result = subprocess.run(
            [sys.executable, "--version"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "Python 3." in result.stdout or "Python 3." in result.stderr
        assert result.returncode == 0

    def test_subprocess_with_timeout(self) -> None:
        """Verify subprocess timeout works on all platforms."""
        try:
            subprocess.run(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                timeout=0.1,
                check=True,
            )
            pytest.fail("Should have timed out")
        except subprocess.TimeoutExpired:
            # Expected
            pass


class TestEnvironmentVariables:
    """Test environment variable handling across platforms."""

    def test_env_variable_set_and_get(self) -> None:
        """Verify environment variables work."""
        os.environ["KEKKAI_TEST_VAR"] = "test_value"
        assert os.environ.get("KEKKAI_TEST_VAR") == "test_value"

        # Cleanup
        del os.environ["KEKKAI_TEST_VAR"]

    def test_path_env_variable_exists(self) -> None:
        """Verify PATH environment variable exists."""
        path_var = os.environ.get("PATH")
        assert path_var is not None
        assert len(path_var) > 0

    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows env test")
    def test_windows_specific_env_vars(self) -> None:
        """Verify Windows-specific environment variables."""
        assert os.environ.get("USERPROFILE") is not None
        assert os.environ.get("TEMP") is not None

    @pytest.mark.skipif(sys.platform.startswith("win"), reason="Unix env test")
    def test_unix_specific_env_vars(self) -> None:
        """Verify Unix-specific environment variables."""
        assert os.environ.get("HOME") is not None


class TestFileSystemOperations:
    """Test file system operations across platforms."""

    def test_file_creation_and_deletion(self, tmp_path: Path) -> None:
        """Verify file operations work on all platforms."""
        test_file = tmp_path / "test.txt"

        # Create
        test_file.write_text("test content")
        assert test_file.exists()

        # Read
        content = test_file.read_text()
        assert content == "test content"

        # Delete
        test_file.unlink()
        assert not test_file.exists()

    def test_directory_creation(self, tmp_path: Path) -> None:
        """Verify directory operations work."""
        test_dir = tmp_path / "test_dir" / "nested"
        test_dir.mkdir(parents=True, exist_ok=True)

        assert test_dir.exists()
        assert test_dir.is_dir()

    def test_file_permissions_basic(self, tmp_path: Path) -> None:
        """Verify basic file permissions work."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        # Should be readable
        assert os.access(test_file, os.R_OK)

        # Should be writable
        assert os.access(test_file, os.W_OK)

    def test_symlink_creation(self, tmp_path: Path) -> None:
        """Verify symlink creation (may fail on Windows without admin)."""
        target = tmp_path / "target.txt"
        target.write_text("target content")

        link = tmp_path / "link.txt"

        try:
            link.symlink_to(target)
            if link.exists():
                # Symlinks work on this platform
                assert link.is_symlink()
                assert link.read_text() == "target content"
        except (OSError, NotImplementedError):
            # Symlinks not supported or insufficient permissions
            pytest.skip("Symlinks not supported on this platform/configuration")


class TestDockerDetection:
    """Test Docker availability detection across platforms."""

    def test_docker_command_exists(self) -> None:
        """Verify Docker command detection."""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            docker_available = result.returncode == 0
            if docker_available:
                assert "Docker" in result.stdout or "Docker" in result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Docker not available
            pytest.skip("Docker not installed")

    def test_docker_compose_command(self) -> None:
        """Verify docker-compose command detection."""
        try:
            result = subprocess.run(
                ["docker-compose", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                # Accept both v1 "docker-compose" and v2 "docker compose"
                assert "docker-compose" in output or "docker compose" in output
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Docker Compose not available
            pytest.skip("Docker Compose not installed")


class TestPlatformSpecificFeatures:
    """Test platform-specific feature detection."""

    def test_get_platform_name(self) -> None:
        """Verify platform name detection."""
        system = platform.system()
        assert system in ["Linux", "Darwin", "Windows"]

        # Verify lowercase helper
        assert system.lower() in ["linux", "darwin", "windows"]

    def test_is_windows(self) -> None:
        """Verify Windows platform detection."""
        is_windows = sys.platform.startswith("win")
        assert isinstance(is_windows, bool)

    def test_is_macos(self) -> None:
        """Verify macOS platform detection."""
        is_macos = sys.platform == "darwin"
        assert isinstance(is_macos, bool)

    def test_is_linux(self) -> None:
        """Verify Linux platform detection."""
        is_linux = sys.platform.startswith("linux")
        assert isinstance(is_linux, bool)

    def test_platform_one_is_true(self) -> None:
        """Verify exactly one platform is detected."""
        is_windows = sys.platform.startswith("win")
        is_macos = sys.platform == "darwin"
        is_linux = sys.platform.startswith("linux")

        # Exactly one should be True
        assert sum([is_windows, is_macos, is_linux]) == 1
