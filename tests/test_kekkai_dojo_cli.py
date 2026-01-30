from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from kekkai import cli
from kekkai.dojo import ServiceStatus


def test_cli_dojo_up(monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]) -> None:
    def fake_compose_up(**kwargs: Any) -> tuple[dict[str, str], int, int]:
        return (
            {"DD_ADMIN_USER": "admin", "DD_ADMIN_PASSWORD": "test123"},
            kwargs.get("port", 8080),
            kwargs.get("tls_port", 8443),
        )

    monkeypatch.setattr("kekkai.cli.dojo.compose_up", fake_compose_up)
    exit_code = cli.main(["dojo", "up", "--port", "8081", "--tls-port", "8444"])
    assert exit_code == 0
    out = capfd.readouterr().out
    assert "DefectDojo is ready" in out
    assert "Username: admin" in out
    assert "Password:" in out


def test_cli_dojo_status(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    statuses = [
        ServiceStatus(name="nginx", state="running", health="healthy", exit_code=0, ports=None)
    ]

    def fake_status(**_kwargs: Any) -> list[ServiceStatus]:
        return statuses

    monkeypatch.setattr("kekkai.cli.dojo.compose_status", fake_status)
    exit_code = cli.main(["dojo", "status"])
    assert exit_code == 0
    out = capfd.readouterr().out
    assert "nginx: running" in out


def test_cli_dojo_open(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, int] = {}

    def fake_open_ui(port: int) -> None:
        called["port"] = port

    monkeypatch.setattr("kekkai.cli.dojo.open_ui", fake_open_ui)
    exit_code = cli.main(["dojo", "open", "--port", "8082"])
    assert exit_code == 0
    assert called["port"] == 8082


def test_cli_dojo_down(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_down(**_kwargs: Any) -> None:
        return None

    monkeypatch.setattr("kekkai.cli.dojo.compose_down", fake_down)
    exit_code = cli.main(["dojo", "down"])
    assert exit_code == 0


def test_cli_dojo_up_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_compose_up(**_kwargs: Any) -> dict[str, str]:
        raise RuntimeError("boom")

    monkeypatch.setattr("kekkai.cli.dojo.compose_up", fake_compose_up)
    exit_code = cli.main(["dojo", "up"])
    assert exit_code == 1


def test_cli_dojo_down_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_down(**_kwargs: Any) -> None:
        raise RuntimeError("down failed")

    monkeypatch.setattr("kekkai.cli.dojo.compose_down", fake_down)
    exit_code = cli.main(["dojo", "down"])
    assert exit_code == 1


def test_cli_dojo_status_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_status(**_kwargs: Any) -> list[ServiceStatus]:
        return []

    monkeypatch.setattr("kekkai.cli.dojo.compose_status", fake_status)
    exit_code = cli.main(["dojo", "status"])
    assert exit_code == 0


def test_cli_dojo_open_uses_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    compose_root = tmp_path / "dojo"
    compose_root.mkdir()
    env_file = compose_root / ".env"
    env_file.write_text("DD_PORT=9091\n")

    called: dict[str, int] = {}

    def fake_open_ui(port: int) -> None:
        called["port"] = port

    monkeypatch.setattr("kekkai.cli.dojo.open_ui", fake_open_ui)
    exit_code = cli.main(["dojo", "open", "--compose-dir", str(compose_root)])
    assert exit_code == 0
    assert called["port"] == 9091
