import shutil
import subprocess

import pytest

pytestmark = pytest.mark.integration


def test_docker_cli_available_and_working() -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("docker CLI not installed in this environment")

    assert docker is not None  # mypy: narrow Optional[str] -> str

    proc = subprocess.run([docker, "version"], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
