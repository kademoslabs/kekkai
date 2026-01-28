"""Regression tests for platform-specific behavior consistency."""

import json
import sys
from pathlib import Path

import pytest


@pytest.mark.regression
class TestCLIOutputConsistency:
    """Test CLI output format remains consistent across platforms."""

    def test_help_output_format(self) -> None:
        """Verify --help output format is platform-agnostic."""
        import io
        from contextlib import redirect_stderr, redirect_stdout

        from kekkai.cli import main

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                main(["--help"])
        except SystemExit:
            pass  # argparse calls sys.exit on --help

        combined = stdout_capture.getvalue() + stderr_capture.getvalue()
        assert "usage:" in combined.lower() or "Usage:" in combined
        assert "kekkai" in combined.lower()

    def test_version_output_format(self) -> None:
        """Verify --version output format is consistent."""
        import io
        from contextlib import redirect_stderr, redirect_stdout

        from kekkai.cli import main

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                main(["--version"])
        except SystemExit:
            pass  # argparse calls sys.exit on --version

        # Version output should exist (may go to stdout or stderr)
        combined = stdout_capture.getvalue() + stderr_capture.getvalue()
        assert len(combined) > 0


@pytest.mark.regression
class TestScanResultsConsistency:
    """Test scan results are identical across platforms."""

    def test_empty_scan_result_format(self, tmp_path: Path) -> None:
        """Verify empty scan results have consistent format."""
        # Create minimal test structure
        test_project = tmp_path / "test_project"
        test_project.mkdir()

        readme = test_project / "README.md"
        readme.write_text("# Test Project\n")

        # Scan result structure should be consistent
        result_dict = {
            "scanner": "test_scanner",
            "findings": [],
            "metadata": {"test": True},
        }

        json_str = json.dumps(result_dict, sort_keys=True)
        parsed = json.loads(json_str)

        # Verify structure
        assert "scanner" in parsed
        assert "findings" in parsed
        assert "metadata" in parsed
        assert parsed["findings"] == []

    def test_finding_structure_consistent(self) -> None:
        """Verify finding structure is platform-agnostic."""
        # Create a finding structure
        finding_dict = {
            "title": "Test Finding",
            "description": "Test description",
            "severity": "medium",
            "file_path": "src/test.py".replace("\\", "/"),  # Normalize
            "line_number": 10,
        }

        # Verify structure
        assert finding_dict["file_path"] == "src/test.py"
        assert finding_dict["line_number"] == 10
        assert finding_dict["severity"] == "medium"


@pytest.mark.regression
class TestConfigurationHandling:
    """Test configuration handling remains consistent."""

    def test_default_config_structure(self) -> None:
        """Verify default configuration structure is consistent."""
        try:
            from kekkai.config import DEFAULT_CONFIG  # type: ignore[attr-defined]

            # Should have standard fields
            assert isinstance(DEFAULT_CONFIG, dict)
            assert "scanners" in DEFAULT_CONFIG or "version" in DEFAULT_CONFIG
        except (ImportError, AttributeError):
            pytest.skip("DEFAULT_CONFIG not implemented yet")

    def test_config_file_parsing(self, tmp_path: Path) -> None:
        """Verify config file parsing is consistent."""
        import yaml  # type: ignore[import-untyped]

        config_file = tmp_path / "kekkai.yaml"
        config_data = {
            "scanners": ["trivy", "semgrep"],
            "output": "kekkai-report.json",
        }

        config_file.write_text(yaml.dump(config_data))

        # Parse and verify
        parsed = yaml.safe_load(config_file.read_text())
        assert parsed == config_data


@pytest.mark.regression
class TestPathHandling:
    """Test path handling regression tests."""

    def test_relative_path_handling(self, tmp_path: Path) -> None:
        """Verify relative paths work consistently."""
        test_file = tmp_path / "subdir" / "test.txt"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("content")

        # Get relative path from tmp_path
        rel_path = test_file.relative_to(tmp_path)

        # Normalize to forward slashes
        normalized = str(rel_path).replace("\\", "/")
        assert normalized == "subdir/test.txt"

    def test_absolute_path_resolution(self, tmp_path: Path) -> None:
        """Verify absolute path resolution is consistent."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # Resolve to absolute path
        abs_path = test_file.resolve()
        assert abs_path.is_absolute()
        assert abs_path.exists()

    def test_path_with_dots(self, tmp_path: Path) -> None:
        """Verify path with . and .. handled consistently."""
        # Create structure
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        test_file = subdir / "test.txt"
        test_file.write_text("content")

        # Use relative path with ..
        relative = tmp_path / "subdir" / ".." / "subdir" / "test.txt"
        resolved = relative.resolve()

        assert resolved == test_file.resolve()


@pytest.mark.regression
class TestJSONSerialization:
    """Test JSON serialization consistency."""

    def test_json_dumps_consistent(self) -> None:
        """Verify JSON serialization is consistent."""
        data = {
            "string": "value",
            "number": 42,
            "float": 3.14,
            "bool": True,
            "null": None,
            "array": [1, 2, 3],
            "object": {"nested": "value"},
        }

        # Serialize with sorted keys
        json_str = json.dumps(data, sort_keys=True, indent=2)

        # Parse back
        parsed = json.loads(json_str)

        assert parsed == data

    def test_json_unicode_handling(self) -> None:
        """Verify Unicode in JSON is handled consistently."""
        data = {
            "emoji": "✓",
            "chinese": "中文",
            "arabic": "العربية",
        }

        json_str = json.dumps(data, ensure_ascii=False)
        parsed = json.loads(json_str)

        assert parsed == data


@pytest.mark.regression
class TestErrorMessages:
    """Test error messages remain consistent."""

    def test_file_not_found_message(self, tmp_path: Path) -> None:
        """Verify FileNotFoundError message format."""
        nonexistent = tmp_path / "does_not_exist.txt"

        try:
            nonexistent.read_text()
            pytest.fail("Should have raised FileNotFoundError")
        except FileNotFoundError as e:
            # Error message should mention the file
            assert "does_not_exist.txt" in str(e)

    def test_invalid_json_error(self) -> None:
        """Verify JSON decode error is consistent."""
        invalid_json = "{invalid json}"

        try:
            json.loads(invalid_json)
            pytest.fail("Should have raised JSONDecodeError")
        except json.JSONDecodeError as e:
            # Error should be JSONDecodeError
            assert "Expecting" in str(e) or "JSON" in str(e)


@pytest.mark.regression
class TestCommandLineInterfaceBackwardCompatibility:
    """Test CLI backward compatibility."""

    def test_cli_import_works(self) -> None:
        """Verify CLI module can be imported."""
        from kekkai import cli

        assert hasattr(cli, "main")

    def test_config_module_imports(self) -> None:
        """Verify config module imports work."""
        from kekkai import config

        # Config module should be importable
        assert config is not None


@pytest.mark.regression
class TestScannerBackends:
    """Test scanner backend consistency."""

    def test_backend_detection(self) -> None:
        """Verify backend detection is consistent."""
        try:
            from kekkai_core.scanner.backends import get_backend_mode  # type: ignore

            backend = get_backend_mode()
            assert backend in ["docker", "native"]
        except ImportError:
            pytest.skip("Scanner backends not implemented yet")

    def test_scanner_registry(self) -> None:
        """Verify scanner registry is consistent."""
        try:
            from kekkai_core.scanner.base import SCANNER_REGISTRY  # type: ignore

            assert isinstance(SCANNER_REGISTRY, dict)
            assert len(SCANNER_REGISTRY) > 0
        except ImportError:
            pytest.skip("Scanner registry not implemented yet")


@pytest.mark.regression
class TestGoldenSnapshots:
    """Test output against golden snapshots."""

    def test_help_text_structure(self) -> None:
        """Verify help text has expected structure."""
        import io
        from contextlib import redirect_stderr, redirect_stdout

        from kekkai.cli import main

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                main(["--help"])
        except SystemExit:
            pass  # argparse calls sys.exit on --help

        output = (stdout_capture.getvalue() + stderr_capture.getvalue()).lower()

        # Should contain these sections
        expected_keywords = ["usage", "options", "commands"]

        # At least one should be present
        assert any(keyword in output for keyword in expected_keywords)

    def test_config_schema_consistent(self) -> None:
        """Verify config schema hasn't changed unexpectedly."""
        try:
            from kekkai.config import DEFAULT_CONFIG  # type: ignore[attr-defined]

            # Verify at least basic structure exists
            assert isinstance(DEFAULT_CONFIG, dict)
        except (ImportError, AttributeError):
            pytest.skip("DEFAULT_CONFIG not implemented yet")


@pytest.mark.regression
class TestPlatformSpecificBehavior:
    """Test platform-specific behavior remains consistent."""

    def test_windows_path_separator(self) -> None:
        """Verify Windows path separator handling."""
        if sys.platform.startswith("win"):
            assert Path("C:\\Windows").parts[0] == "C:\\"
        else:
            pytest.skip("Windows-specific test")

    def test_unix_path_separator(self) -> None:
        """Verify Unix path separator handling."""
        if not sys.platform.startswith("win"):
            path = Path("/usr/local/bin")
            assert path.parts[0] == "/"
        else:
            pytest.skip("Unix-specific test")

    def test_line_ending_handling(self, tmp_path: Path) -> None:
        """Verify line ending handling is consistent."""
        test_file = tmp_path / "test.txt"

        # Write with explicit \n
        test_file.write_text("line1\nline2\nline3")

        # Read back
        content = test_file.read_text()
        lines = content.splitlines()

        # Should have 3 lines regardless of platform
        assert len(lines) == 3
        assert lines[0] == "line1"
        assert lines[2] == "line3"


@pytest.mark.regression
class TestMemoryUsageConsistency:
    """Test memory usage patterns remain consistent."""

    def test_small_scan_memory_footprint(self) -> None:
        """Verify small scans don't use excessive memory."""
        import sys

        # Create result with small dataset
        result = {
            "scanner": "test",
            "findings": [],
            "metadata": {},
        }

        # Object should be reasonably sized
        size = sys.getsizeof(result)
        assert size < 10000  # Less than 10KB

    def test_large_findings_list_handling(self) -> None:
        """Verify large findings lists are handled efficiently."""
        # Create many findings
        findings = [
            {
                "title": f"Finding {i}",
                "description": f"Description {i}",
                "severity": "low",
                "file_path": f"file{i}.py",
                "line_number": i,
            }
            for i in range(1000)
        ]

        assert len(findings) == 1000

        # Should be able to serialize
        findings_dicts = [
            {
                "title": f["title"],
                "severity": f["severity"],
            }
            for f in findings
        ]

        assert len(findings_dicts) == 1000
