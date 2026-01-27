"""Unit tests for scanner backend abstraction."""

from __future__ import annotations

import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kekkai.scanners.backends import (
    BackendType,
    DockerBackend,
    NativeBackend,
    ToolNotFoundError,
    ToolVersionError,
    detect_tool,
    docker_available,
)

IS_WINDOWS = sys.platform == "win32"


class TestDockerAvailable:
    def test_docker_available_returns_tuple(self) -> None:
        result = docker_available(force_check=True)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)

    def test_docker_available_cached(self) -> None:
        result1 = docker_available(force_check=True)
        result2 = docker_available(force_check=False)
        assert result1 == result2

    @patch("shutil.which")
    def test_docker_not_in_path(self, mock_which: MagicMock) -> None:
        mock_which.return_value = None
        available, reason = docker_available(force_check=True)
        assert available is False
        assert "not found" in reason.lower()


class TestDetectTool:
    def test_detect_nonexistent_tool(self) -> None:
        with pytest.raises(ToolNotFoundError) as exc:
            detect_tool("nonexistent_tool_xyz123")
        assert "not found" in str(exc.value).lower()

    @pytest.mark.skipif(IS_WINDOWS, reason="Shell scripts don't execute on Windows")
    def test_detect_tool_requires_minimum_version(self, tmp_path: Path) -> None:
        fake_tool = tmp_path / "fake_tool"
        fake_tool.write_text("#!/bin/sh\necho 'version 0.1.0'")
        fake_tool.chmod(fake_tool.stat().st_mode | stat.S_IEXEC)

        with patch("shutil.which", return_value=str(fake_tool)):
            with pytest.raises(ToolVersionError) as exc:
                detect_tool("fake_tool", min_version=(1, 0, 0))
            assert "below minimum" in str(exc.value).lower()

    @pytest.mark.skipif(IS_WINDOWS, reason="Shell scripts don't execute on Windows")
    def test_detect_tool_with_valid_version(self, tmp_path: Path) -> None:
        fake_tool = tmp_path / "fake_tool"
        fake_tool.write_text(f"#!{sys.executable}\nprint('version 2.0.0')")
        fake_tool.chmod(fake_tool.stat().st_mode | stat.S_IEXEC)

        with (
            patch("shutil.which", return_value=str(fake_tool)),
            patch("os.path.realpath", return_value=str(fake_tool)),
        ):
            tool_info = detect_tool("fake_tool", min_version=(1, 0, 0))
            assert tool_info.name == "fake_tool"
            assert tool_info.version == "2.0.0"
            assert tool_info.version_tuple >= (1, 0, 0)


class TestNativeBackend:
    def test_native_backend_always_available(self) -> None:
        backend = NativeBackend()
        available, reason = backend.is_available()
        assert available is True

    def test_native_backend_type(self) -> None:
        backend = NativeBackend()
        assert backend.backend_type == BackendType.NATIVE

    def test_native_backend_rejects_non_list_args(self, tmp_path: Path) -> None:
        backend = NativeBackend()
        result = backend.execute(
            tool="echo",
            args="hello",  # type: ignore[arg-type]
            repo_path=tmp_path,
            output_path=tmp_path,
            timeout_seconds=5,
        )
        assert result.exit_code == 1
        assert "must be a list" in result.stderr.lower()

    def test_native_backend_tool_not_found(self, tmp_path: Path) -> None:
        backend = NativeBackend()
        result = backend.execute(
            tool="nonexistent_tool_xyz123",
            args=["--help"],
            repo_path=tmp_path,
            output_path=tmp_path,
            timeout_seconds=5,
        )
        assert result.exit_code == 127
        assert "not found" in result.stderr.lower()

    def test_native_backend_env_allowlist(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ALLOWED_VAR", "yes")
        monkeypatch.setenv("BLOCKED_VAR", "no")

        backend = NativeBackend(env_allowlist=["ALLOWED_VAR"])
        result = backend.execute(
            tool=sys.executable,
            args=[
                "-c",
                "import os; print(os.environ.get('ALLOWED_VAR', ''), "
                "os.environ.get('BLOCKED_VAR', ''))",
            ],
            repo_path=tmp_path,
            output_path=tmp_path,
            timeout_seconds=5,
        )
        assert result.exit_code == 0
        assert "yes" in result.stdout
        assert "no" not in result.stdout


class TestDockerBackend:
    def test_docker_backend_type(self) -> None:
        backend = DockerBackend()
        assert backend.backend_type == BackendType.DOCKER

    def test_docker_backend_is_available(self) -> None:
        backend = DockerBackend()
        available, reason = backend.is_available()
        assert isinstance(available, bool)
        assert isinstance(reason, str)


class TestBackendType:
    def test_backend_type_values(self) -> None:
        assert BackendType.DOCKER.value == "docker"
        assert BackendType.NATIVE.value == "native"

    def test_backend_type_is_string_enum(self) -> None:
        assert isinstance(BackendType.DOCKER, str)
        assert BackendType.DOCKER.value == "docker"


class TestNativeBackendExecution:
    """Additional tests for native backend execution."""

    def test_native_backend_timeout(self, tmp_path: Path) -> None:
        backend = NativeBackend()
        result = backend.execute(
            tool=sys.executable,
            args=["-c", "import time; time.sleep(5)"],
            repo_path=tmp_path,
            output_path=tmp_path,
            timeout_seconds=0,
        )
        assert result.timed_out is True
        assert result.exit_code == 124

    def test_native_backend_successful_execution(self, tmp_path: Path) -> None:
        backend = NativeBackend()
        result = backend.execute(
            tool=sys.executable,
            args=["-c", "print('hello')"],
            repo_path=tmp_path,
            output_path=tmp_path,
            timeout_seconds=5,
        )
        assert result.exit_code == 0
        assert "hello" in result.stdout
        assert result.timed_out is False
        assert result.backend == BackendType.NATIVE

    def test_native_backend_with_additional_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        backend = NativeBackend()
        result = backend.execute(
            tool=sys.executable,
            args=["-c", "import os; print(os.environ.get('EXTRA_VAR', 'not_set'))"],
            repo_path=tmp_path,
            output_path=tmp_path,
            timeout_seconds=5,
            env={"EXTRA_VAR": "extra_value"},
        )
        assert result.exit_code == 0
        assert "extra_value" in result.stdout
