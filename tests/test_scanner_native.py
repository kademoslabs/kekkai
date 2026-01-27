"""Unit tests for native scanner execution."""

from __future__ import annotations

import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kekkai.scanners import BackendType, GitleaksScanner, SemgrepScanner, TrivyScanner
from kekkai.scanners.backends import (
    ToolNotFoundError,
    ToolVersionError,
    detect_tool,
)

IS_WINDOWS = sys.platform == "win32"


class TestScannerBackendSelection:
    """Test that scanners select the correct backend."""

    def test_trivy_explicit_backend(self) -> None:
        scanner = TrivyScanner(backend=BackendType.NATIVE)
        assert scanner._backend == BackendType.NATIVE

    def test_semgrep_explicit_backend(self) -> None:
        scanner = SemgrepScanner(backend=BackendType.DOCKER)
        assert scanner._backend == BackendType.DOCKER

    def test_gitleaks_explicit_backend(self) -> None:
        scanner = GitleaksScanner(backend=BackendType.NATIVE)
        assert scanner._backend == BackendType.NATIVE

    @patch("kekkai.scanners.trivy.docker_available")
    def test_trivy_auto_selects_docker_when_available(self, mock_docker: MagicMock) -> None:
        mock_docker.return_value = (True, "Docker available")
        scanner = TrivyScanner()
        backend = scanner._select_backend()
        assert backend == BackendType.DOCKER

    @patch("kekkai.scanners.trivy.docker_available")
    @patch("kekkai.scanners.trivy.detect_tool")
    def test_trivy_auto_selects_native_when_docker_unavailable(
        self, mock_detect: MagicMock, mock_docker: MagicMock
    ) -> None:
        mock_docker.return_value = (False, "Docker not available")
        mock_detect.return_value = MagicMock(name="trivy", path="/usr/bin/trivy", version="0.50.0")
        scanner = TrivyScanner()
        backend = scanner._select_backend()
        assert backend == BackendType.NATIVE

    @patch("kekkai.scanners.trivy.docker_available")
    @patch("kekkai.scanners.trivy.detect_tool")
    def test_trivy_falls_back_to_docker_when_native_unavailable(
        self, mock_detect: MagicMock, mock_docker: MagicMock
    ) -> None:
        mock_docker.return_value = (False, "Docker not available")
        mock_detect.side_effect = ToolNotFoundError("trivy not found")
        scanner = TrivyScanner()
        backend = scanner._select_backend()
        assert backend == BackendType.DOCKER


class TestNativeScannerExecution:
    """Test native scanner execution with mock tools."""

    @patch("kekkai.scanners.trivy.detect_tool")
    def test_trivy_native_handles_tool_not_found(
        self, mock_detect: MagicMock, tmp_path: Path
    ) -> None:
        from kekkai.scanners import ScanContext

        mock_detect.side_effect = ToolNotFoundError("trivy not found in PATH")
        scanner = TrivyScanner(backend=BackendType.NATIVE)

        ctx = ScanContext(
            repo_path=tmp_path,
            output_dir=tmp_path / "output",
            run_id="test-run",
        )
        (tmp_path / "output").mkdir()

        result = scanner._run_native(ctx)
        assert result.success is False
        assert "not found" in (result.error or "").lower()

    @patch("kekkai.scanners.trivy.detect_tool")
    def test_trivy_native_handles_version_error(
        self, mock_detect: MagicMock, tmp_path: Path
    ) -> None:
        from kekkai.scanners import ScanContext

        mock_detect.side_effect = ToolVersionError("trivy version 0.30.0 is below minimum 0.40.0")
        scanner = TrivyScanner(backend=BackendType.NATIVE)

        ctx = ScanContext(
            repo_path=tmp_path,
            output_dir=tmp_path / "output",
            run_id="test-run",
        )
        (tmp_path / "output").mkdir()

        result = scanner._run_native(ctx)
        assert result.success is False
        assert "below minimum" in (result.error or "").lower()


@pytest.mark.skipif(IS_WINDOWS, reason="Shell scripts don't execute on Windows")
class TestFakeToolDetection:
    """Test tool detection with fake PATH binaries."""

    def test_detect_fake_tool_in_path(self, tmp_path: Path) -> None:
        fake_trivy = tmp_path / "trivy"
        fake_trivy.write_text(f"#!{sys.executable}\nprint('Version: 0.50.0')")
        fake_trivy.chmod(fake_trivy.stat().st_mode | stat.S_IEXEC)

        with (
            patch("shutil.which", return_value=str(fake_trivy)),
            patch("os.path.realpath", return_value=str(fake_trivy)),
        ):
            tool_info = detect_tool("trivy", min_version=(0, 40, 0))
            assert tool_info.version == "0.50.0"
            assert tool_info.version_tuple == (0, 50, 0)

    def test_reject_suspicious_version_output(self, tmp_path: Path) -> None:
        fake_tool = tmp_path / "fake_tool"
        fake_tool.write_text(f"#!{sys.executable}\nprint('no version here')")
        fake_tool.chmod(fake_tool.stat().st_mode | stat.S_IEXEC)

        with (
            patch("shutil.which", return_value=str(fake_tool)),
            patch("os.path.realpath", return_value=str(fake_tool)),
        ):
            with pytest.raises(ToolVersionError) as exc:
                detect_tool("fake_tool")
            assert "could not parse" in str(exc.value).lower()

    def test_reject_tool_that_is_not_executable(self, tmp_path: Path) -> None:
        fake_tool = tmp_path / "fake_tool"
        fake_tool.write_text("#!/bin/sh\necho '1.0.0'")
        fake_tool.chmod(0o644)

        with (
            patch("shutil.which", return_value=str(fake_tool)),
            patch("os.path.realpath", return_value=str(fake_tool)),
        ):
            with pytest.raises(ToolNotFoundError) as exc:
                detect_tool("fake_tool")
            assert "not executable" in str(exc.value).lower()

    def test_reject_tool_that_is_directory(self, tmp_path: Path) -> None:
        fake_dir = tmp_path / "fake_tool"
        fake_dir.mkdir()

        with (
            patch("shutil.which", return_value=str(fake_dir)),
            patch("os.path.realpath", return_value=str(fake_dir)),
        ):
            with pytest.raises(ToolNotFoundError) as exc:
                detect_tool("fake_tool")
            assert "not a file" in str(exc.value).lower()


class TestScannerBackendRecording:
    """Test that scanners record which backend was used."""

    def test_trivy_records_backend_used(self) -> None:
        scanner = TrivyScanner(backend=BackendType.NATIVE)
        assert scanner.backend_used is None
        scanner._resolved_backend = BackendType.NATIVE
        assert scanner.backend_used == BackendType.NATIVE

    def test_semgrep_records_backend_used(self) -> None:
        scanner = SemgrepScanner(backend=BackendType.DOCKER)
        assert scanner.backend_used is None
        scanner._resolved_backend = BackendType.DOCKER
        assert scanner.backend_used == BackendType.DOCKER

    def test_gitleaks_records_backend_used(self) -> None:
        scanner = GitleaksScanner(backend=BackendType.NATIVE)
        assert scanner.backend_used is None
        scanner._resolved_backend = BackendType.NATIVE
        assert scanner.backend_used == BackendType.NATIVE
