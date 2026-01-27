from __future__ import annotations

from unittest.mock import MagicMock, patch

from kekkai.scanners.container import (
    ContainerConfig,
    ContainerResult,
    docker_command,
)


class TestContainerConfig:
    def test_defaults(self) -> None:
        config = ContainerConfig(image="test/image")
        assert config.read_only is True
        assert config.network_disabled is True
        assert config.no_new_privileges is True
        assert config.memory_limit == "2g"
        assert config.cpu_limit == "2"

    def test_with_digest(self) -> None:
        config = ContainerConfig(
            image="test/image",
            image_digest="sha256:abc123",
        )
        assert config.image_digest == "sha256:abc123"


class TestContainerResult:
    def test_success_result(self) -> None:
        result = ContainerResult(
            exit_code=0,
            stdout="output",
            stderr="",
            duration_ms=1000,
            timed_out=False,
        )
        assert result.exit_code == 0
        assert not result.timed_out

    def test_timeout_result(self) -> None:
        result = ContainerResult(
            exit_code=124,
            stdout="",
            stderr="",
            duration_ms=60000,
            timed_out=True,
        )
        assert result.timed_out
        assert result.exit_code == 124


class TestDockerCommand:
    @patch("shutil.which")
    @patch("subprocess.run")
    def test_docker_compose_v2(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        mock_which.return_value = "/usr/bin/docker"
        mock_run.return_value = MagicMock(returncode=0)

        cmd = docker_command()
        assert cmd == "/usr/bin/docker"

    @patch("shutil.which")
    def test_docker_not_found(self, mock_which: MagicMock) -> None:
        import pytest

        mock_which.return_value = None
        with pytest.raises(RuntimeError, match="Docker not found"):
            docker_command()
