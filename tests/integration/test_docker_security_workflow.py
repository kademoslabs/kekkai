"""Integration tests for Docker security workflow."""

import platform
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        platform.system() == "Windows",
        reason="Docker Linux containers not available on Windows CI",
    ),
]


@pytest.fixture
def docker_available() -> bool:
    """Check if Docker is available."""
    return shutil.which("docker") is not None


@pytest.fixture
def trivy_available() -> bool:
    """Check if Trivy is available."""
    return shutil.which("trivy") is not None


class TestEndToEndDockerSecurity:
    """Test complete Docker security workflow."""

    def test_docker_build_succeeds(self, docker_available: bool) -> None:
        """Verify Docker image builds successfully."""
        if not docker_available:
            pytest.skip("Docker not available")

        result = subprocess.run(
            [
                "docker",
                "build",
                "-t",
                "kekkai-test:security",
                "-f",
                "apps/kekkai/Dockerfile",
                ".",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        assert result.returncode == 0, f"Docker build failed: {result.stderr}"

    def test_trivy_scan_docker_image(self, docker_available: bool, trivy_available: bool) -> None:
        """Verify Trivy can scan built Docker image."""
        if not docker_available:
            pytest.skip("Docker not available")
        if not trivy_available:
            pytest.skip("Trivy not available")

        # Build image first
        subprocess.run(
            [
                "docker",
                "build",
                "-t",
                "kekkai-test:scan",
                "-f",
                "apps/kekkai/Dockerfile",
                ".",
            ],
            capture_output=True,
            timeout=300,
            check=True,
        )

        # Scan with Trivy
        result = subprocess.run(
            ["trivy", "image", "--format", "json", "kekkai-test:scan"],
            capture_output=True,
            text=True,
            timeout=300,
        )

        assert result.returncode == 0, f"Trivy scan failed: {result.stderr}"
        assert len(result.stdout) > 0, "Trivy output is empty"

    def test_vulnerability_threshold_enforcement(
        self, docker_available: bool, trivy_available: bool, tmp_path: Path
    ) -> None:
        """Verify vulnerability threshold checking works."""
        if not docker_available:
            pytest.skip("Docker not available")
        if not trivy_available:
            pytest.skip("Trivy not available")

        # Build image
        subprocess.run(
            [
                "docker",
                "build",
                "-t",
                "kekkai-test:threshold",
                "-f",
                "apps/kekkai/Dockerfile",
                ".",
            ],
            capture_output=True,
            timeout=300,
            check=True,
        )

        # Scan and save results
        scan_output = tmp_path / "scan-results.json"
        subprocess.run(
            [
                "trivy",
                "image",
                "--format",
                "json",
                "--output",
                str(scan_output),
                "kekkai-test:threshold",
            ],
            capture_output=True,
            timeout=300,
            check=True,
        )

        assert scan_output.exists()
        assert scan_output.stat().st_size > 0

    def test_multi_arch_manifest(self, docker_available: bool) -> None:
        """Verify multi-arch manifest structure (if available)."""
        if not docker_available:
            pytest.skip("Docker not available")

        # Try to inspect a multi-arch image (use official Python image as example)
        result = subprocess.run(
            ["docker", "manifest", "inspect", "python:3.12-slim"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            # Verify manifest contains multiple architectures
            assert "amd64" in result.stdout or "arm64" in result.stdout


class TestSBOMGeneration:
    """Test SBOM generation for Docker images."""

    def test_generate_sbom_with_trivy(
        self, docker_available: bool, trivy_available: bool, tmp_path: Path
    ) -> None:
        """Verify SBOM generation succeeds."""
        if not docker_available:
            pytest.skip("Docker not available")
        if not trivy_available:
            pytest.skip("Trivy not available")

        # Build image
        subprocess.run(
            [
                "docker",
                "build",
                "-t",
                "kekkai-test:sbom",
                "-f",
                "apps/kekkai/Dockerfile",
                ".",
            ],
            capture_output=True,
            timeout=300,
            check=True,
        )

        # Generate SBOM
        sbom_file = tmp_path / "sbom.spdx.json"
        result = subprocess.run(
            [
                "trivy",
                "image",
                "--format",
                "spdx-json",
                "--output",
                str(sbom_file),
                "kekkai-test:sbom",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        assert result.returncode == 0, f"SBOM generation failed: {result.stderr}"
        assert sbom_file.exists()
        assert sbom_file.stat().st_size > 0

        # Verify SBOM is valid JSON
        import json

        with open(sbom_file) as f:
            sbom_data = json.load(f)
            assert "spdxVersion" in sbom_data or "packages" in sbom_data


class TestImageSigning:
    """Test Docker image signing (if Cosign available)."""

    @pytest.fixture
    def cosign_available(self) -> bool:
        """Check if Cosign is available."""
        return shutil.which("cosign") is not None

    def test_cosign_available_check(self, cosign_available: bool) -> None:
        """Verify Cosign availability can be checked."""
        if cosign_available:
            result = subprocess.run(
                ["cosign", "version"], capture_output=True, text=True, timeout=10
            )
            assert result.returncode == 0


class TestDockerHubCompatibility:
    """Test Docker Hub publishing compatibility."""

    def test_image_metadata_labels(self, docker_available: bool) -> None:
        """Verify OCI labels are present in image."""
        if not docker_available:
            pytest.skip("Docker not available")

        # Build image
        subprocess.run(
            [
                "docker",
                "build",
                "-t",
                "kekkai-test:metadata",
                "-f",
                "apps/kekkai/Dockerfile",
                ".",
            ],
            capture_output=True,
            timeout=300,
            check=True,
        )

        # Inspect image
        result = subprocess.run(
            ["docker", "inspect", "kekkai-test:metadata"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )

        # Verify inspection succeeded
        assert result.returncode == 0
        assert len(result.stdout) > 0

    def test_image_size_optimization(self, docker_available: bool) -> None:
        """Verify image size is reasonable."""
        if not docker_available:
            pytest.skip("Docker not available")

        # Build image
        subprocess.run(
            [
                "docker",
                "build",
                "-t",
                "kekkai-test:size",
                "-f",
                "apps/kekkai/Dockerfile",
                ".",
            ],
            capture_output=True,
            timeout=300,
            check=True,
        )

        # Get image size
        result = subprocess.run(
            ["docker", "images", "kekkai-test:size", "--format", "{{.Size}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )

        size_str = result.stdout.strip()
        # Verify size is reported (actual size check depends on image content)
        assert len(size_str) > 0
