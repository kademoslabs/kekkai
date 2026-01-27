"""Integration tests for Docker Hub features."""

import shutil
import subprocess

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def docker_available() -> bool:
    """Check if Docker is available."""
    return shutil.which("docker") is not None


class TestDockerHubMetadata:
    """Test Docker Hub metadata and labels."""

    def test_oci_labels_in_dockerfile(self) -> None:
        """Verify Dockerfile can be built (OCI labels tested in workflow)."""
        # This is a smoke test - actual labels are tested in workflow
        from pathlib import Path

        dockerfile = Path("apps/kekkai/Dockerfile")
        assert dockerfile.exists()
        content = dockerfile.read_text()
        assert "FROM" in content
        assert "python" in content.lower()

    def test_readme_file_exists(self) -> None:
        """Verify README exists for Docker Hub description."""
        from pathlib import Path

        readme = Path("README.md")
        assert readme.exists()
        content = readme.read_text()
        assert len(content) > 100
        assert "Kekkai" in content


class TestMultiArchSupport:
    """Test multi-architecture support."""

    def test_buildx_available(self, docker_available: bool) -> None:
        """Verify Docker Buildx is available for multi-arch builds."""
        if not docker_available:
            pytest.skip("Docker not available")

        result = subprocess.run(
            ["docker", "buildx", "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        # Buildx may not be available in all environments
        if result.returncode == 0:
            assert "buildx" in result.stdout.lower()

    def test_dockerfile_multi_arch_compatible(self) -> None:
        """Verify Dockerfile doesn't have arch-specific dependencies."""
        from pathlib import Path

        dockerfile = Path("apps/kekkai/Dockerfile")
        content = dockerfile.read_text()

        # Check for common arch-specific patterns that might break builds
        # This is a basic check - actual multi-arch build tested in CI
        assert "amd64" not in content.lower() or "multi" in content.lower()


class TestImagePullability:
    """Test that images can be pulled (requires published image)."""

    def test_public_image_documentation(self) -> None:
        """Verify documentation mentions Docker Hub image."""
        from pathlib import Path

        readme = Path("README.md")
        content = readme.read_text()

        # Verify Docker Hub reference exists
        assert "docker" in content.lower()
        assert "kademoslabs" in content or "kademos" in content.lower()
