"""Integration tests for native mode scanner execution."""

from __future__ import annotations

import platform
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kekkai.scanners import BackendType, GitleaksScanner, ScanContext, SemgrepScanner, TrivyScanner
from kekkai.scanners.backends import docker_available


@pytest.mark.integration
@pytest.mark.skipif(
    platform.system() == "Windows",
    reason="Fake binaries use shebang which doesn't work on Windows",
)
class TestNativeModeIntegration:
    """Integration tests for native mode scanner execution.

    These tests use fake scanner binaries to verify the native execution path
    without requiring real scanner installations.
    """

    @pytest.fixture
    def fake_trivy(self, tmp_path: Path) -> Path:
        """Create a fake trivy binary that outputs valid JSON."""
        fake_bin = tmp_path / "bin" / "trivy"
        fake_bin.parent.mkdir(parents=True, exist_ok=True)

        script = f"""#!{sys.executable}
import sys
import json

output_file = None
for i, arg in enumerate(sys.argv):
    if arg == "--output" and i + 1 < len(sys.argv):
        output_file = sys.argv[i + 1]
        break

result = {{"Results": []}}
if output_file:
    with open(output_file, "w") as f:
        json.dump(result, f)

print("Version: 0.50.0", file=sys.stderr)
sys.exit(0)
"""
        fake_bin.write_text(script)
        fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)
        return fake_bin

    @pytest.fixture
    def fake_semgrep(self, tmp_path: Path) -> Path:
        """Create a fake semgrep binary that outputs valid JSON."""
        fake_bin = tmp_path / "bin" / "semgrep"
        fake_bin.parent.mkdir(parents=True, exist_ok=True)

        script = f"""#!{sys.executable}
import sys
import json

output_file = None
for i, arg in enumerate(sys.argv):
    if arg == "--output" and i + 1 < len(sys.argv):
        output_file = sys.argv[i + 1]
        break

result = {{"results": [], "errors": []}}
if output_file:
    with open(output_file, "w") as f:
        json.dump(result, f)

print("1.60.0")
sys.exit(0)
"""
        fake_bin.write_text(script)
        fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)
        return fake_bin

    @pytest.fixture
    def fake_gitleaks(self, tmp_path: Path) -> Path:
        """Create a fake gitleaks binary that outputs valid JSON."""
        fake_bin = tmp_path / "bin" / "gitleaks"
        fake_bin.parent.mkdir(parents=True, exist_ok=True)

        script = f"""#!{sys.executable}
import sys
import json

output_file = None
for i, arg in enumerate(sys.argv):
    if arg == "--report-path" and i + 1 < len(sys.argv):
        output_file = sys.argv[i + 1]
        break

result = []
if output_file:
    with open(output_file, "w") as f:
        json.dump(result, f)

print("v8.20.0")
sys.exit(0)
"""
        fake_bin.write_text(script)
        fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)
        return fake_bin

    def test_trivy_native_mode_with_fake_binary(self, tmp_path: Path, fake_trivy: Path) -> None:
        """Test Trivy scanner in native mode using a fake binary."""
        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ctx = ScanContext(
            repo_path=repo_path,
            output_dir=output_dir,
            run_id="test-native-trivy",
        )

        with (
            patch("shutil.which", return_value=str(fake_trivy)),
            patch("os.path.realpath", return_value=str(fake_trivy)),
        ):
            scanner = TrivyScanner(backend=BackendType.NATIVE)
            scanner._resolved_backend = BackendType.NATIVE
            result = scanner._run_native(ctx)

            assert result.success is True
            assert result.findings == []
            assert scanner.backend_used == BackendType.NATIVE

    def test_semgrep_native_mode_with_fake_binary(self, tmp_path: Path, fake_semgrep: Path) -> None:
        """Test Semgrep scanner in native mode using a fake binary."""
        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ctx = ScanContext(
            repo_path=repo_path,
            output_dir=output_dir,
            run_id="test-native-semgrep",
        )

        with (
            patch("shutil.which", return_value=str(fake_semgrep)),
            patch("os.path.realpath", return_value=str(fake_semgrep)),
        ):
            scanner = SemgrepScanner(backend=BackendType.NATIVE)
            scanner._resolved_backend = BackendType.NATIVE
            result = scanner._run_native(ctx)

            assert result.success is True
            assert result.findings == []
            assert scanner.backend_used == BackendType.NATIVE

    def test_gitleaks_native_mode_with_fake_binary(
        self, tmp_path: Path, fake_gitleaks: Path
    ) -> None:
        """Test Gitleaks scanner in native mode using a fake binary."""
        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ctx = ScanContext(
            repo_path=repo_path,
            output_dir=output_dir,
            run_id="test-native-gitleaks",
        )

        with (
            patch("shutil.which", return_value=str(fake_gitleaks)),
            patch("os.path.realpath", return_value=str(fake_gitleaks)),
        ):
            scanner = GitleaksScanner(backend=BackendType.NATIVE)
            scanner._resolved_backend = BackendType.NATIVE
            result = scanner._run_native(ctx)

            assert result.success is True
            assert result.findings == []
            assert scanner.backend_used == BackendType.NATIVE


@pytest.mark.integration
class TestBackendAutoSelection:
    """Test automatic backend selection based on environment."""

    def test_docker_availability_detection(self) -> None:
        """Test that docker_available correctly detects Docker status."""
        available, reason = docker_available(force_check=True)
        assert isinstance(available, bool)
        assert isinstance(reason, str)
        if available:
            assert "available" in reason.lower()
        else:
            assert "not" in reason.lower() or "error" in reason.lower()

    @patch("kekkai.scanners.trivy.docker_available")
    def test_scanner_selects_docker_when_available(self, mock_docker: MagicMock) -> None:
        """Test scanner prefers Docker when available."""
        mock_docker.return_value = (True, "Docker available")
        scanner = TrivyScanner()
        backend = scanner._select_backend()
        assert backend == BackendType.DOCKER
