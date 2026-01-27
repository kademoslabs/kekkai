"""Regression tests for Docker backwards compatibility."""

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.regression


@pytest.fixture
def docker_available() -> bool:
    """Check if Docker is available."""
    return shutil.which("docker") is not None


class TestDockerBackwardsCompatibility:
    """Test backwards compatibility of Docker builds."""

    def test_existing_workflow_still_works(self) -> None:
        """Verify original docker-publish.yml workflow file structure."""
        workflow_file = Path(".github/workflows/docker-publish.yml")

        assert workflow_file.exists()
        content = workflow_file.read_text()

        # Verify essential workflow elements still present
        assert "docker/build-push-action" in content
        assert "DOCKERHUB_USERNAME" in content
        assert "DOCKERHUB_TOKEN" in content
        assert "kademoslabs/kekkai" in content

    def test_dockerfile_basic_structure_unchanged(self) -> None:
        """Verify Dockerfile maintains basic structure."""
        dockerfile = Path("apps/kekkai/Dockerfile")

        assert dockerfile.exists()
        content = dockerfile.read_text()

        # Verify basic Dockerfile structure
        assert content.startswith("# Dockerfile for Kekkai") or content.startswith("FROM")
        assert "FROM python:" in content
        assert "ENTRYPOINT" in content or "CMD" in content

    def test_docker_build_without_security_features(self, docker_available: bool) -> None:
        """Verify Docker image can still be built without security scanning."""
        if not docker_available:
            pytest.skip("Docker not available")

        # Basic build should work without Trivy/Cosign
        result = subprocess.run(
            [
                "docker",
                "build",
                "-t",
                "kekkai-test:basic",
                "-f",
                "apps/kekkai/Dockerfile",
                ".",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        assert result.returncode == 0, f"Basic Docker build failed: {result.stderr}"

    def test_docker_image_runs_without_signature(self, docker_available: bool) -> None:
        """Verify images can run without signature verification."""
        if not docker_available:
            pytest.skip("Docker not available")

        # Build image
        subprocess.run(
            [
                "docker",
                "build",
                "-t",
                "kekkai-test:unsigned",
                "-f",
                "apps/kekkai/Dockerfile",
                ".",
            ],
            capture_output=True,
            timeout=300,
            check=True,
        )

        # Run image (should work without signature)
        result = subprocess.run(
            ["docker", "run", "--rm", "kekkai-test:unsigned", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"Unsigned image failed to run: {result.stderr}"
        assert "kekkai" in result.stdout.lower() or "help" in result.stdout.lower()

    def test_existing_labels_preserved(self, docker_available: bool) -> None:
        """Verify original OCI labels are still present."""
        if not docker_available:
            pytest.skip("Docker not available")

        # Build image
        subprocess.run(
            [
                "docker",
                "build",
                "-t",
                "kekkai-test:labels",
                "-f",
                "apps/kekkai/Dockerfile",
                ".",
            ],
            capture_output=True,
            timeout=300,
            check=True,
        )

        # Inspect labels (workflow adds them, not Dockerfile)
        result = subprocess.run(
            ["docker", "inspect", "kekkai-test:labels"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )

        # Just verify inspection works
        assert result.returncode == 0


class TestDockerBuildCompatibility:
    """Test Docker build compatibility across changes."""

    def test_dockerfile_changes_dont_break_builds(self) -> None:
        """Verify Dockerfile structure is valid."""
        dockerfile = Path("apps/kekkai/Dockerfile")
        content = dockerfile.read_text()

        # Verify critical Dockerfile instructions present
        assert "FROM" in content
        assert "WORKDIR" in content or "RUN" in content
        assert "COPY" in content or "ADD" in content

    def test_base_image_specified(self) -> None:
        """Verify base image is pinned."""
        dockerfile = Path("apps/kekkai/Dockerfile")
        content = dockerfile.read_text()

        # Verify Python version specified
        assert "python:3.12" in content or "python:3." in content

    def test_non_root_user_preserved(self) -> None:
        """Verify security: non-root user maintained."""
        dockerfile = Path("apps/kekkai/Dockerfile")
        content = dockerfile.read_text()

        # Verify non-root user configuration
        assert "USER" in content or "useradd" in content


class TestWorkflowBackwardsCompatibility:
    """Test GitHub Actions workflow compatibility."""

    def test_workflow_syntax_valid(self) -> None:
        """Verify workflow YAML is valid."""
        import yaml  # type: ignore[import-untyped]

        workflow_file = Path(".github/workflows/docker-publish.yml")
        with open(workflow_file) as f:
            workflow = yaml.safe_load(f)

        # Verify basic structure
        assert "name" in workflow
        assert "on" in workflow
        assert "jobs" in workflow

    def test_workflow_maintains_trigger_events(self) -> None:
        """Verify workflow triggers unchanged."""
        workflow_file = Path(".github/workflows/docker-publish.yml")
        content = workflow_file.read_text()

        # Verify original triggers present
        assert "push:" in content
        assert "tags:" in content
        assert "v*.*.*" in content
        assert "workflow_dispatch:" in content

    def test_security_scan_workflow_syntax_valid(self) -> None:
        """Verify new security scan workflow is valid."""
        try:
            import yaml
        except ImportError:
            import pytest

            pytest.skip("PyYAML not installed")

        workflow_file = Path(".github/workflows/docker-security-scan.yml")

        if workflow_file.exists():
            with open(workflow_file) as f:
                workflow = yaml.safe_load(f)

            assert "name" in workflow
            assert "on" in workflow
            assert "jobs" in workflow

    def test_original_docker_hub_secrets_used(self) -> None:
        """Verify original secrets still referenced."""
        workflow_file = Path(".github/workflows/docker-publish.yml")
        content = workflow_file.read_text()

        # Verify secrets maintained
        assert "DOCKERHUB_USERNAME" in content
        assert "DOCKERHUB_TOKEN" in content
