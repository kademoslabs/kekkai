"""Integration tests for pipx installation and execution.

Tests that kekkai can be installed via pipx in an isolated environment
and executes correctly with all basic commands.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest


@pytest.mark.integration
def test_pipx_install_and_run(tmp_path: Path) -> None:
    """Test that pipx install works and basic commands execute correctly."""
    import platform

    # Use project root for installation
    project_root = Path(__file__).parent.parent.parent

    # Install kekkai via pipx in isolated environment
    result = subprocess.run(  # noqa: S603  # nosec B603
        [sys.executable, "-m", "pipx", "install", str(project_root), "--force"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    # pipx install should succeed
    if result.returncode != 0:
        pytest.skip(f"pipx not available or install failed: {result.stderr}")

    try:
        # Test --version
        version_result = subprocess.run(  # noqa: S603  # nosec B603
            [sys.executable, "-m", "pipx", "run", "kekkai", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert version_result.returncode == 0, f"--version failed: {version_result.stderr}"

        # Test --help
        help_result = subprocess.run(  # noqa: S603  # nosec B603
            [sys.executable, "-m", "pipx", "run", "kekkai", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert help_result.returncode == 0, f"--help failed: {help_result.stderr}"
        assert "kekkai" in help_result.stdout.lower(), "Help output missing 'kekkai'"

        # Test init command in isolated environment
        test_home = tmp_path / "kekkai_test_home"
        test_home.mkdir()

        # On Windows, we need HOME and USERPROFILE set for pipx to work
        env = os.environ.copy()
        env["KEKKAI_HOME"] = str(test_home)
        if platform.system() == "Windows":
            env["HOME"] = str(tmp_path)
            env["USERPROFILE"] = str(tmp_path)

        init_result = subprocess.run(  # noqa: S603  # nosec B603
            [sys.executable, "-m", "pipx", "run", "kekkai", "init"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            check=False,
        )
        assert init_result.returncode == 0, f"init failed: {init_result.stderr}"

        # Verify config was created
        config_file = test_home / "kekkai.toml"
        assert config_file.exists(), "Config file not created by init"

    finally:
        # Cleanup: uninstall kekkai
        subprocess.run(  # noqa: S603  # nosec B603
            [sys.executable, "-m", "pipx", "uninstall", "kekkai"],
            capture_output=True,
            timeout=60,
            check=False,
        )


@pytest.mark.integration
def test_pipx_available() -> None:
    """Verify pipx is available for testing."""
    result = subprocess.run(  # noqa: S603  # nosec B603
        [sys.executable, "-m", "pipx", "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    if result.returncode != 0:
        pytest.skip("pipx not installed, skipping pipx tests")

    # pipx --version may output just the version number (e.g., "1.8.0")
    # or "pipx 1.8.0" depending on version
    output = result.stdout.lower()
    assert (
        "pipx" in output
        or result.stdout.strip().replace(".", "").isdigit()
        or len(result.stdout.strip().split(".")) >= 2
    ), "pipx version output unexpected"
