from __future__ import annotations

from pathlib import Path

import pytest

from kekkai import cli
from kekkai.cli import main


def test_main_no_args_initializes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / "kekkai_home"
    monkeypatch.setenv("KEKKAI_HOME", str(base_dir))

    assert main([]) == 0
    assert (base_dir / "kekkai.toml").exists()


def test_main_no_args_with_existing_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / "kekkai_home"
    monkeypatch.setenv("KEKKAI_HOME", str(base_dir))

    assert main(["init"]) == 0
    config_path = base_dir / "kekkai.toml"
    original = config_path.read_text()

    assert main([]) == 0
    assert config_path.read_text() == original


def test_resolve_run_id_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEKKAI_RUN_ID", "fixed-run")
    assert cli._resolve_run_id(None) == "fixed-run"


def test_resolve_run_dir_within_base(tmp_path: Path) -> None:
    base_dir = tmp_path / "base"
    run_base = base_dir / "runs"
    run_base.mkdir(parents=True)

    run_dir = cli._resolve_run_dir(base_dir, run_base, "run-1", None)
    assert run_dir == run_base / "run-1"


def test_scan_invalid_run_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / "kekkai_home"
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    monkeypatch.setenv("KEKKAI_HOME", str(base_dir))
    assert main(["init"]) == 0

    exit_code = main(["scan", "--repo", str(repo_dir), "--run-id", "!!"])
    assert exit_code == 1
