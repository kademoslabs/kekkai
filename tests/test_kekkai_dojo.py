from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from kekkai.dojo import (
    build_compose_yaml,
    check_port_available,
    compose_command,
    compose_down,
    compose_status,
    compose_up,
    ensure_env,
    load_env_file,
    open_ui,
    parse_compose_ps,
    wait_for_ui,
    write_env_file,
)


def test_compose_yaml_contains_profile_and_no_privileged() -> None:
    output = build_compose_yaml()
    assert 'profiles: ["dojo"]' in output
    assert "privileged" not in output


def test_port_collision_detection() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        assert check_port_available(port) is False


def test_parse_compose_ps() -> None:
    sample = json.dumps(
        [
            {
                "Service": "nginx",
                "State": "running",
                "Health": "healthy",
                "ExitCode": 0,
                "Publishers": "0.0.0.0:8080->8080/tcp",
            }
        ]
    )
    statuses = parse_compose_ps(sample)
    assert statuses[0].name == "nginx"
    assert statuses[0].state == "running"
    assert statuses[0].health == "healthy"


def test_env_round_trip(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    write_env_file(env_path, {"DD_ADMIN_USER": "root"})
    loaded = load_env_file(env_path)
    assert loaded["DD_ADMIN_USER"] == "root"


def test_ensure_env_defaults(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("DD_ADMIN_USER=custom\n")
    env = ensure_env(env_path, port=8080, tls_port=8443)
    assert env["DD_ADMIN_USER"] == "custom"
    assert env["DD_PORT"] == "8080"
    assert env["DD_TLS_PORT"] == "8443"


def test_compose_command_prefers_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_which(name: str) -> str | None:
        return "/usr/bin/docker" if name == "docker" else None

    class FakeProc:
        returncode = 0

    def fake_run(*_args: object, **_kwargs: object) -> FakeProc:
        return FakeProc()

    monkeypatch.setattr("kekkai.dojo.shutil.which", fake_which)
    monkeypatch.setattr("kekkai.dojo.subprocess.run", fake_run)
    assert compose_command() == ["/usr/bin/docker", "compose"]


def test_compose_command_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_which(name: str) -> str | None:
        if name == "docker-compose":
            return "/usr/bin/docker-compose"
        return None

    monkeypatch.setattr("kekkai.dojo.shutil.which", fake_which)
    assert compose_command() == ["/usr/bin/docker-compose"]


def test_compose_up_down_status(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class FakeProc:
        def __init__(self, stdout: str = "[]") -> None:
            self.returncode = 0
            self.stderr = ""
            self.stdout = stdout

    def fake_run(_args: object, **_kwargs: object) -> FakeProc:
        return FakeProc(stdout='[{"Service":"nginx","State":"running"}]')

    monkeypatch.setattr("kekkai.dojo.check_port_available", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("kekkai.dojo.compose_command", lambda: ["docker"])
    monkeypatch.setattr("kekkai.dojo.subprocess.run", fake_run)
    monkeypatch.setattr("kekkai.dojo.wait_for_ui", lambda *_args, **_kwargs: None)

    compose_root = tmp_path / "dojo"
    env = compose_up(
        compose_root=compose_root,
        project_name="kekkai",
        port=8080,
        tls_port=8443,
        wait=True,
        open_browser=False,
    )
    assert env["DD_ADMIN_USER"] == "admin"
    assert (compose_root / "docker-compose.yml").exists()

    statuses = compose_status(compose_root=compose_root, project_name="kekkai")
    assert statuses[0].name == "nginx"

    compose_down(compose_root=compose_root, project_name="kekkai")


def test_wait_for_ui_success(monkeypatch: pytest.MonkeyPatch) -> None:
    class DummyResponse:
        status = 200

        def __enter__(self) -> DummyResponse:
            return self

        def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
            return None

    monkeypatch.setattr("kekkai.dojo.urlopen", lambda *_args, **_kwargs: DummyResponse())
    wait_for_ui(8080, timeout=1)


def test_open_ui_calls_browser(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, bool] = {"opened": False}

    def fake_open(_url: str) -> bool:
        called["opened"] = True
        return True

    monkeypatch.setattr("kekkai.dojo.webbrowser.open", fake_open)
    open_ui(8080)
    assert called["opened"] is True
