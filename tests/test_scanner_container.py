from __future__ import annotations

from unittest.mock import MagicMock, patch

from kekkai.scanners.container import (
    ContainerConfig,
    ContainerResult,
    _resolve_image_ref,
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


class TestResolveImageRef:
    """Tests for _resolve_image_ref function."""

    def test_with_digest(self) -> None:
        """Test image ref with digest uses @digest format."""
        ref = _resolve_image_ref("aquasec/trivy", "sha256:abc123")
        assert ref == "aquasec/trivy@sha256:abc123"

    def test_without_digest_or_tag_adds_latest(self) -> None:
        """Test image without tag gets :latest appended."""
        ref = _resolve_image_ref("returntocorp/semgrep", None)
        assert ref == "returntocorp/semgrep:latest"

    def test_with_existing_tag_preserved(self) -> None:
        """Test image with existing tag is preserved."""
        ref = _resolve_image_ref("aquasec/trivy:0.48.3", None)
        assert ref == "aquasec/trivy:0.48.3"

    def test_digest_takes_precedence_over_tag(self) -> None:
        """Test that digest is used even if image has a tag."""
        ref = _resolve_image_ref("aquasec/trivy:0.48.3", "sha256:xyz789")
        assert ref == "aquasec/trivy:0.48.3@sha256:xyz789"

    def test_simple_image_name(self) -> None:
        """Test simple image name without namespace."""
        ref = _resolve_image_ref("python", None)
        assert ref == "python:latest"

    def test_image_with_registry(self) -> None:
        """Test image with registry prefix."""
        ref = _resolve_image_ref("ghcr.io/user/image", None)
        assert ref == "ghcr.io/user/image:latest"

    def test_image_with_registry_and_tag(self) -> None:
        """Test image with registry and tag."""
        ref = _resolve_image_ref("ghcr.io/user/image:v1.0", None)
        assert ref == "ghcr.io/user/image:v1.0"
