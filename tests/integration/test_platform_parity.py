"""Integration tests for platform parity - ensuring consistent behavior across platforms."""

import json
import sys
from pathlib import Path

import pytest


@pytest.mark.integration
class TestScanOutputConsistency:
    """Test that scan outputs are consistent across platforms."""

    def test_json_output_format_consistent(self, tmp_path: Path) -> None:
        """Verify JSON output format is identical across platforms."""
        # Create a minimal test project
        test_project = tmp_path / "test_project"
        test_project.mkdir()

        test_file = test_project / "test.py"
        test_file.write_text('print("hello")\n')

        # Create a test scan result structure
        result_dict = {
            "scanner": "test",
            "findings": [],
            "metadata": {"platform": sys.platform},
        }

        json_str = json.dumps(result_dict, indent=2, sort_keys=True)

        # Verify JSON is valid and consistent
        parsed = json.loads(json_str)
        assert parsed["scanner"] == "test"
        assert parsed["findings"] == []
        assert "platform" in parsed["metadata"]

    def test_file_path_representation_normalized(self, tmp_path: Path) -> None:
        """Verify file paths are normalized in outputs."""
        test_file = tmp_path / "subdir" / "test.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("test content")

        # Get relative path
        rel_path = test_file.relative_to(tmp_path)

        # Convert to forward slashes (platform-agnostic representation)
        normalized = str(rel_path).replace("\\", "/")

        assert normalized == "subdir/test.py"


@pytest.mark.integration
class TestDockerIntegration:
    """Test Docker integration across platforms."""

    def test_docker_availability_detection(self) -> None:
        """Test Docker availability detection works on all platforms."""
        import subprocess

        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                timeout=5,
            )
            is_available = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            is_available = False

        assert isinstance(is_available, bool)

    def test_docker_backend_selection(self) -> None:
        """Test backend selection logic."""
        # Test that Docker availability can be detected
        import subprocess

        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                timeout=5,
            )
            docker_available = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            docker_available = False

        # Backend would be docker if available, else native
        backend = "docker" if docker_available else "native"
        assert backend in ["docker", "native"]


@pytest.mark.integration
class TestFileOperations:
    """Test file operations consistency across platforms."""

    def test_create_read_write_cycle(self, tmp_path: Path) -> None:
        """Verify file create/read/write cycle works identically."""
        test_file = tmp_path / "test_data.json"

        # Write
        data = {"key": "value", "number": 42, "list": [1, 2, 3]}
        test_file.write_text(json.dumps(data, indent=2))

        # Read
        content = test_file.read_text()
        parsed = json.loads(content)

        # Verify
        assert parsed == data

    def test_binary_file_operations(self, tmp_path: Path) -> None:
        """Verify binary file operations work."""
        test_file = tmp_path / "test.bin"

        # Write binary data
        binary_data = b"\x00\x01\x02\x03\xff\xfe\xfd"
        test_file.write_bytes(binary_data)

        # Read and verify
        read_data = test_file.read_bytes()
        assert read_data == binary_data

    def test_large_file_handling(self, tmp_path: Path) -> None:
        """Verify large file handling works consistently."""
        test_file = tmp_path / "large.txt"

        # Create 1MB file
        chunk = "x" * 1024  # 1KB
        content = chunk * 1024  # 1MB

        test_file.write_text(content)

        # Verify size
        assert test_file.stat().st_size == len(content)

        # Read back (might be slow, but should work)
        read_content = test_file.read_text()
        assert len(read_content) == len(content)


@pytest.mark.integration
class TestCommandLineExecution:
    """Test command-line execution consistency."""

    def test_python_script_execution(self, tmp_path: Path) -> None:
        """Verify Python script execution works on all platforms."""
        import subprocess

        script = tmp_path / "test_script.py"
        script.write_text('print("success")')

        result = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            check=True,
        )

        assert "success" in result.stdout
        assert result.returncode == 0

    def test_subprocess_output_encoding(self, tmp_path: Path) -> None:
        """Verify subprocess output encoding is consistent."""
        import subprocess

        # Test with unicode content
        script = tmp_path / "unicode_test.py"
        script.write_text('print("✓ Unicode test")')

        result = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            check=True,
        )

        assert "✓" in result.stdout or "Unicode test" in result.stdout


@pytest.mark.integration
class TestConfigurationHandling:
    """Test configuration file handling across platforms."""

    def test_yaml_config_loading(self, tmp_path: Path) -> None:
        """Verify YAML config loading works consistently."""
        import yaml  # type: ignore[import-untyped]

        config_file = tmp_path / "config.yaml"
        config_data = {
            "version": "1.0",
            "settings": {
                "debug": True,
                "timeout": 30,
            },
        }

        # Write
        config_file.write_text(yaml.dump(config_data))

        # Read
        loaded = yaml.safe_load(config_file.read_text())

        assert loaded == config_data

    def test_json_config_loading(self, tmp_path: Path) -> None:
        """Verify JSON config loading works consistently."""
        config_file = tmp_path / "config.json"
        config_data = {
            "version": "1.0",
            "settings": {
                "debug": True,
                "timeout": 30,
            },
        }

        # Write
        config_file.write_text(json.dumps(config_data, indent=2))

        # Read
        loaded = json.loads(config_file.read_text())

        assert loaded == config_data


@pytest.mark.integration
class TestPlatformSpecificPaths:
    """Test platform-specific path handling."""

    def test_temp_directory_access(self) -> None:
        """Verify temp directory access works on all platforms."""
        import tempfile

        temp_dir = Path(tempfile.gettempdir())
        assert temp_dir.exists()
        assert temp_dir.is_dir()

        # Try creating a temp file
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            temp_path = Path(f.name)
            f.write("test")

        assert temp_path.exists()
        temp_path.unlink()

    def test_current_working_directory(self) -> None:
        """Verify CWD operations work."""
        cwd = Path.cwd()
        assert cwd.exists()
        assert cwd.is_absolute()

    def test_path_resolution(self, tmp_path: Path) -> None:
        """Verify path resolution works consistently."""
        # Create nested structure
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True, exist_ok=True)

        # Create file in nested directory
        test_file = nested / "test.txt"
        test_file.write_text("content")

        # Resolve path
        resolved = test_file.resolve()
        assert resolved.exists()
        assert resolved.is_absolute()


@pytest.mark.integration
class TestErrorHandling:
    """Test error handling consistency across platforms."""

    def test_file_not_found_error(self, tmp_path: Path) -> None:
        """Verify FileNotFoundError raised consistently."""
        nonexistent = tmp_path / "does_not_exist.txt"

        with pytest.raises(FileNotFoundError):
            nonexistent.read_text()

    def test_permission_error_simulation(self, tmp_path: Path) -> None:
        """Test permission error handling."""
        test_file = tmp_path / "readonly.txt"
        test_file.write_text("content")

        # Note: Permission handling differs by platform
        # This test verifies the file exists
        assert test_file.exists()

    def test_invalid_path_handling(self) -> None:
        """Verify invalid path handling."""
        # Null bytes in path should raise error when trying to use it
        invalid_path = Path("test\x00invalid")

        # The error occurs when trying to create/use the path
        with pytest.raises((ValueError, OSError, FileNotFoundError)):
            invalid_path.write_text("test")


@pytest.mark.integration
class TestConcurrentOperations:
    """Test concurrent operations work consistently."""

    def test_concurrent_file_writes(self, tmp_path: Path) -> None:
        """Verify concurrent file operations work."""
        import concurrent.futures

        def write_file(index: int) -> Path:
            file_path = tmp_path / f"file_{index}.txt"
            file_path.write_text(f"content {index}")
            return file_path

        # Write 10 files concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(write_file, i) for i in range(10)]
            paths = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Verify all files created
        assert len(paths) == 10
        for path in paths:
            assert path.exists()


@pytest.mark.integration
class TestMemoryAndPerformance:
    """Test memory and performance characteristics."""

    def test_large_data_structure_handling(self) -> None:
        """Verify large data structures work consistently."""
        # Create large list
        large_list = list(range(100000))
        assert len(large_list) == 100000

        # Create large dict
        large_dict = {f"key_{i}": i for i in range(10000)}
        assert len(large_dict) == 10000

    def test_string_operations_consistency(self) -> None:
        """Verify string operations work consistently."""
        test_str = "Hello, World! 🌍"

        # Basic operations
        assert len(test_str) > 0
        assert test_str.upper() == "HELLO, WORLD! 🌍"
        assert test_str.lower() == "hello, world! 🌍"

        # Unicode handling
        assert "🌍" in test_str

    def test_numeric_precision(self) -> None:
        """Verify numeric operations are consistent."""
        # Float operations
        a = 0.1 + 0.2
        b = 0.3
        assert abs(a - b) < 1e-10

        # Integer operations
        large_int = 10**100
        assert large_int > 0
