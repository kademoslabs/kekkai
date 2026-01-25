from __future__ import annotations

import json
import shutil
import socket
import urllib.request
import uuid
from pathlib import Path

import pytest

from kekkai import cli
from kekkai.dojo import compose_command, load_env_file

pytestmark = pytest.mark.integration


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def _docker_available() -> bool:
    if shutil.which("docker") is None and shutil.which("docker-compose") is None:
        return False
    try:
        compose_command()
    except RuntimeError:
        return False
    return True


def test_dojo_up_status_and_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not _docker_available():
        pytest.skip("docker compose not available")

    compose_root = tmp_path / "dojo"
    project_name = f"kekkai-dojo-{uuid.uuid4().hex[:6]}"
    port = _get_free_port()
    tls_port = _get_free_port()

    monkeypatch.setenv("KEKKAI_HOME", str(tmp_path / "kekkai_home"))

    exit_code = cli.main(
        [
            "dojo",
            "up",
            "--compose-dir",
            str(compose_root),
            "--project-name",
            project_name,
            "--port",
            str(port),
            "--tls-port",
            str(tls_port),
            "--wait",
        ]
    )
    assert exit_code == 0

    try:
        status_code = cli.main(
            [
                "dojo",
                "status",
                "--compose-dir",
                str(compose_root),
                "--project-name",
                project_name,
            ]
        )
        assert status_code == 0

        env = load_env_file(compose_root / ".env")
        payload = json.dumps(
            {
                "username": env.get("DD_ADMIN_USER", "admin"),
                "password": env.get("DD_ADMIN_PASSWORD", "admin"),
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"http://localhost:{port}/api/v2/api-token-auth/",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert "token" in data
    finally:
        cli.main(
            [
                "dojo",
                "down",
                "--compose-dir",
                str(compose_root),
                "--project-name",
                project_name,
            ]
        )
