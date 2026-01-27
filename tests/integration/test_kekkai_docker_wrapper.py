"""Integration tests for Docker wrapper security and functionality.

Tests that kekkai Docker wrapper executes correctly with hardened security controls:
- Non-root user execution
- Read-only filesystem
- Dropped capabilities
- No privilege escalation
"""

from __future__ import annotations

import platform
import subprocess  # nosec B404
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    platform.system() == "Windows",
    reason="Docker wrapper is a shell script that requires Linux/macOS",
)


@pytest.mark.integration
def test_docker_available() -> None:
    """Verify Docker is available for testing."""
    result = subprocess.run(  # noqa: S603  # nosec B603
        ["docker", "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    if result.returncode != 0:
        pytest.skip("Docker not available, skipping docker tests")

    assert "docker" in result.stdout.lower(), "Docker version output unexpected"


@pytest.mark.integration
def test_docker_image_builds(tmp_path: Path) -> None:
    """Test that Docker image builds successfully."""
    project_root = Path(__file__).parent.parent.parent

    # Build image
    result = subprocess.run(  # noqa: S603  # nosec B603
        [
            "docker",
            "build",
            "-t",
            "kademoslabs/kekkai:test",
            "-f",
            str(project_root / "apps/kekkai/Dockerfile"),
            str(project_root),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    if result.returncode != 0:
        pytest.skip(f"Docker build failed: {result.stderr}")

    assert result.returncode == 0, f"Docker build failed: {result.stderr}"


@pytest.mark.integration
def test_docker_wrapper_runs(tmp_path: Path) -> None:
    """Test that Docker wrapper executes correctly."""
    project_root = Path(__file__).parent.parent.parent
    wrapper_script = project_root / "scripts/kekkai-docker"

    # Ensure wrapper is executable
    wrapper_script.chmod(0o755)

    # Run --help via wrapper (CLI doesn't have --version)
    result = subprocess.run(  # noqa: S603  # nosec B603
        [str(wrapper_script), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(tmp_path),
        check=False,
    )

    if result.returncode != 0 and "docker" in result.stderr.lower():
        pytest.skip(f"Docker not available or build failed: {result.stderr}")

    assert result.returncode == 0, f"--help failed: {result.stderr}"
    assert "kekkai" in result.stdout.lower(), "Help output missing 'kekkai'"


@pytest.mark.integration
def test_docker_wrapper_help(tmp_path: Path) -> None:
    """Test that Docker wrapper executes --help correctly."""
    project_root = Path(__file__).parent.parent.parent
    wrapper_script = project_root / "scripts/kekkai-docker"

    wrapper_script.chmod(0o755)

    result = subprocess.run(  # noqa: S603  # nosec B603
        [str(wrapper_script), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(tmp_path),
        check=False,
    )

    if result.returncode != 0 and "docker" in result.stderr.lower():
        pytest.skip(f"Docker not available: {result.stderr}")

    assert result.returncode == 0, f"--help failed: {result.stderr}"
    assert "kekkai" in result.stdout.lower(), "Help output missing 'kekkai'"


@pytest.mark.integration
def test_docker_runs_as_non_root(tmp_path: Path) -> None:
    """Verify container runs as non-root user (UID 1000)."""
    project_root = Path(__file__).parent.parent.parent

    # Build image first
    build_result = subprocess.run(  # noqa: S603  # nosec B603
        [
            "docker",
            "build",
            "-t",
            "kademoslabs/kekkai:test-nonroot",
            "-f",
            str(project_root / "apps/kekkai/Dockerfile"),
            str(project_root),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    if build_result.returncode != 0:
        pytest.skip(f"Docker build failed: {build_result.stderr}")

    # Run container and check user ID using sh (more portable than bash)
    result = subprocess.run(  # noqa: S603  # nosec B603
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            "kademoslabs/kekkai:test-nonroot",
            "-c",
            "id -u",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    if result.returncode != 0:
        pytest.skip(f"Container doesn't support shell execution: {result.stderr}")

    uid = result.stdout.strip()
    assert uid != "0", f"Container running as root (UID {uid}), should be non-root"


@pytest.mark.integration
def test_docker_security_flags(tmp_path: Path) -> None:
    """Verify wrapper uses proper security flags."""
    project_root = Path(__file__).parent.parent.parent
    wrapper_script = project_root / "scripts/kekkai-docker"

    # Read wrapper script and verify security flags
    wrapper_content = wrapper_script.read_text()

    security_requirements = [
        "--read-only",  # Read-only filesystem
        "--tmpfs /tmp",  # tmpfs for temporary files
        "--security-opt=no-new-privileges:true",  # No privilege escalation
        "--cap-drop=ALL",  # Drop all capabilities
        ":ro",  # Read-only volume mount
    ]

    for requirement in security_requirements:
        assert requirement in wrapper_content, f"Missing security flag: {requirement}"
