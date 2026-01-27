"""Regression tests for installer - ensure backends remain unchanged."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kekkai.scanners.backends import BackendType
from kekkai.scanners.backends.native import NativeBackend


@pytest.mark.regression
class TestNativeBackendUnchanged:
    """Verify native backend behavior remains unchanged with installer integration."""

    def test_native_backend_still_uses_path_tools(self, tmp_path: Path) -> None:
        """Native backend should use PATH tools when available."""
        backend = NativeBackend()

        # Create a mock repo and output
        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        output_path = tmp_path / "output"
        output_path.mkdir()

        with patch("shutil.which", return_value="/usr/bin/echo"):
            result = backend.execute(
                tool="echo",
                args=["hello"],
                repo_path=repo_path,
                output_path=output_path,
                timeout_seconds=10,
            )

        assert result.backend == BackendType.NATIVE

    def test_native_backend_returns_not_found_for_missing_tool(self, tmp_path: Path) -> None:
        """Native backend should return proper error for missing tools."""
        backend = NativeBackend()

        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        output_path = tmp_path / "output"
        output_path.mkdir()

        with (
            patch("shutil.which", return_value=None),
            patch("kekkai.paths.bin_dir", return_value=tmp_path / "bin"),
        ):
            result = backend.execute(
                tool="nonexistent_tool",
                args=["--version"],
                repo_path=repo_path,
                output_path=output_path,
                timeout_seconds=10,
            )

        assert result.exit_code == 127
        assert "not found" in result.stderr.lower()

    def test_native_backend_type_unchanged(self) -> None:
        """Backend type should remain NATIVE."""
        backend = NativeBackend()
        assert backend.backend_type == BackendType.NATIVE

    def test_native_backend_always_available(self) -> None:
        """Native backend should always report available."""
        backend = NativeBackend()
        available, message = backend.is_available()
        assert available is True


@pytest.mark.regression
class TestDockerBackendUnchanged:
    """Verify docker backend is unaffected by installer changes."""

    def test_docker_backend_type_unchanged(self) -> None:
        """Docker backend type should remain DOCKER."""
        from kekkai.scanners.backends.docker import DockerBackend

        backend = DockerBackend()
        assert backend.backend_type == BackendType.DOCKER

    def test_docker_backend_does_not_use_installer(self, tmp_path: Path) -> None:
        """Docker backend should not call installer."""
        from kekkai.scanners.backends.docker import DockerBackend

        backend = DockerBackend()

        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        output_path = tmp_path / "output"
        output_path.mkdir()

        # Mock docker execution
        with patch("kekkai.scanners.backends.docker.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="docker output",
                stderr="",
            )

            # Installer should not be called
            with patch("kekkai.installer.get_installer") as mock_installer:
                backend.execute(
                    tool="trivy",
                    args=["--version"],
                    repo_path=repo_path,
                    output_path=output_path,
                )

                mock_installer.assert_not_called()


@pytest.mark.regression
class TestScannerBackendSelection:
    """Verify scanner backend selection logic remains unchanged."""

    def test_explicit_backend_respected(self) -> None:
        """Explicit backend choice should be respected."""
        from kekkai.scanners import TrivyScanner

        scanner = TrivyScanner(backend=BackendType.DOCKER)
        assert scanner._backend == BackendType.DOCKER

        scanner2 = TrivyScanner(backend=BackendType.NATIVE)
        assert scanner2._backend == BackendType.NATIVE

    def test_auto_backend_prefers_docker(self) -> None:
        """Auto backend selection should prefer Docker when available."""
        from kekkai.scanners import TrivyScanner

        with patch("kekkai.scanners.trivy.docker_available", return_value=(True, "ok")):
            scanner = TrivyScanner()
            selected = scanner._select_backend()

        assert selected == BackendType.DOCKER
