"""Unit tests for Docker image metadata extraction."""

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from kekkai_core.docker.metadata import (
    DockerMetadataError,
    extract_image_metadata,
    get_oci_labels,
    get_supported_architectures,
    parse_manifest,
    verify_multi_arch_support,
)


class TestMetadataExtraction:
    """Test Docker image metadata extraction."""

    @patch("subprocess.run")
    def test_extract_image_metadata_success(self, mock_run: MagicMock) -> None:
        """Verify metadata extraction returns image config."""
        metadata = {
            "Id": "sha256:abc123",
            "Config": {"Labels": {"app": "kekkai"}},
        }

        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps([metadata]), stderr="")

        result = extract_image_metadata("test-image:latest")

        assert result == metadata
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "docker" in args
        assert "inspect" in args
        assert "test-image:latest" in args

    @patch("subprocess.run")
    def test_extract_metadata_failure_raises_error(self, mock_run: MagicMock) -> None:
        """Verify extraction failures raise error."""
        import subprocess

        mock_run.side_effect = subprocess.CalledProcessError(1, "docker", stderr="image not found")

        with pytest.raises(DockerMetadataError, match="Failed to extract metadata"):
            extract_image_metadata("nonexistent:latest")

    @patch("subprocess.run")
    def test_extract_metadata_invalid_json(self, mock_run: MagicMock) -> None:
        """Verify invalid JSON raises error."""
        mock_run.return_value = MagicMock(returncode=0, stdout="invalid json", stderr="")

        with pytest.raises(DockerMetadataError, match="Failed to parse"):
            extract_image_metadata("test-image:latest")

    @patch("subprocess.run")
    def test_extract_metadata_empty_response(self, mock_run: MagicMock) -> None:
        """Verify empty response raises error."""
        mock_run.return_value = MagicMock(returncode=0, stdout="[]", stderr="")

        with pytest.raises(DockerMetadataError, match="Invalid metadata format"):
            extract_image_metadata("test-image:latest")

    @patch("subprocess.run")
    def test_extract_metadata_timeout_handled(self, mock_run: MagicMock) -> None:
        """Verify timeout errors are handled."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("docker", 30)

        with pytest.raises(DockerMetadataError, match="timed out"):
            extract_image_metadata("test-image:latest")


class TestOCILabels:
    """Test OCI label extraction."""

    def test_get_oci_labels_present(self) -> None:
        """Verify OCI labels are extracted."""
        metadata: dict[str, Any] = {
            "Config": {
                "Labels": {
                    "org.opencontainers.image.title": "Kekkai CLI",
                    "org.opencontainers.image.version": "0.0.1",
                    "org.opencontainers.image.source": "https://github.com/kademoslabs/kekkai",
                    "custom.label": "value",
                }
            }
        }

        oci_labels = get_oci_labels(metadata)

        assert len(oci_labels) == 3
        assert oci_labels["org.opencontainers.image.title"] == "Kekkai CLI"
        assert oci_labels["org.opencontainers.image.version"] == "0.0.1"
        assert "custom.label" not in oci_labels

    def test_get_oci_labels_empty(self) -> None:
        """Verify empty labels handled."""
        metadata: dict[str, Any] = {"Config": {"Labels": {}}}

        oci_labels = get_oci_labels(metadata)

        assert len(oci_labels) == 0

    def test_get_oci_labels_missing_config(self) -> None:
        """Verify missing Config handled."""
        metadata: dict[str, Any] = {}

        oci_labels = get_oci_labels(metadata)

        assert len(oci_labels) == 0

    def test_get_oci_labels_none(self) -> None:
        """Verify None labels handled."""
        metadata = {"Config": {"Labels": None}}

        oci_labels = get_oci_labels(metadata)

        assert len(oci_labels) == 0


class TestManifestParsing:
    """Test Docker manifest parsing."""

    @patch("subprocess.run")
    def test_parse_manifest_success(self, mock_run: MagicMock) -> None:
        """Verify manifest parsing succeeds."""
        manifest = {
            "manifests": [
                {"platform": {"architecture": "amd64"}},
                {"platform": {"architecture": "arm64"}},
            ]
        }

        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(manifest), stderr="")

        result = parse_manifest("test-image:latest")

        assert result == manifest
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "docker" in args
        assert "manifest" in args
        assert "inspect" in args

    @patch("subprocess.run")
    def test_parse_manifest_failure_raises_error(self, mock_run: MagicMock) -> None:
        """Verify manifest parsing failures raise error."""
        import subprocess

        mock_run.side_effect = subprocess.CalledProcessError(
            1, "docker", stderr="manifest not found"
        )

        with pytest.raises(DockerMetadataError, match="Failed to parse manifest"):
            parse_manifest("nonexistent:latest")

    @patch("subprocess.run")
    def test_parse_manifest_invalid_json(self, mock_run: MagicMock) -> None:
        """Verify invalid JSON raises error."""
        mock_run.return_value = MagicMock(returncode=0, stdout="invalid json", stderr="")

        with pytest.raises(DockerMetadataError, match="Failed to parse manifest JSON"):
            parse_manifest("test-image:latest")

    @patch("subprocess.run")
    def test_parse_manifest_timeout_handled(self, mock_run: MagicMock) -> None:
        """Verify timeout errors are handled."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("docker", 30)

        with pytest.raises(DockerMetadataError, match="timed out"):
            parse_manifest("test-image:latest")


class TestArchitectureSupport:
    """Test architecture detection and validation."""

    def test_get_supported_architectures_multi_arch(self) -> None:
        """Verify architecture extraction from multi-arch manifest."""
        manifest: dict[str, Any] = {
            "manifests": [
                {"platform": {"architecture": "amd64", "os": "linux"}},
                {"platform": {"architecture": "arm64", "os": "linux"}},
                {"platform": {"architecture": "arm", "os": "linux", "variant": "v7"}},
            ]
        }

        archs = get_supported_architectures(manifest)

        assert len(archs) == 3
        assert "amd64" in archs
        assert "arm64" in archs
        assert "arm" in archs

    def test_get_supported_architectures_single_arch(self) -> None:
        """Verify architecture extraction from single-arch manifest."""
        manifest: dict[str, Any] = {"platform": {"architecture": "amd64", "os": "linux"}}

        archs = get_supported_architectures(manifest)

        assert len(archs) == 1
        assert "amd64" in archs

    def test_get_supported_architectures_empty(self) -> None:
        """Verify empty manifest handled."""
        manifest: dict[str, Any] = {}

        archs = get_supported_architectures(manifest)

        assert len(archs) == 0

    def test_get_supported_architectures_missing_platform(self) -> None:
        """Verify missing platform handled."""
        manifest: dict[str, Any] = {"manifests": [{}]}

        archs = get_supported_architectures(manifest)

        assert len(archs) == 0

    def test_verify_multi_arch_support_success(self) -> None:
        """Verify multi-arch support validation succeeds."""
        manifest = {
            "manifests": [
                {"platform": {"architecture": "amd64"}},
                {"platform": {"architecture": "arm64"}},
            ]
        }

        result = verify_multi_arch_support(manifest, ["amd64", "arm64"])

        assert result is True

    def test_verify_multi_arch_support_missing_arch(self) -> None:
        """Verify validation fails if required arch missing."""
        manifest = {"manifests": [{"platform": {"architecture": "amd64"}}]}

        result = verify_multi_arch_support(manifest, ["amd64", "arm64"])

        assert result is False

    def test_verify_multi_arch_support_partial(self) -> None:
        """Verify validation with partial arch support."""
        manifest = {
            "manifests": [
                {"platform": {"architecture": "amd64"}},
                {"platform": {"architecture": "arm64"}},
                {"platform": {"architecture": "arm"}},
            ]
        }

        # Only require amd64
        result = verify_multi_arch_support(manifest, ["amd64"])
        assert result is True

        # Require unsupported arch
        result = verify_multi_arch_support(manifest, ["s390x"])
        assert result is False

    def test_verify_multi_arch_support_empty_requirements(self) -> None:
        """Verify validation with no required archs."""
        manifest = {"manifests": [{"platform": {"architecture": "amd64"}}]}

        result = verify_multi_arch_support(manifest, [])

        assert result is True
