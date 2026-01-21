from __future__ import annotations

import json
from pathlib import Path

import pytest

from kekkai.cli import main


@pytest.mark.integration
def test_kekkai_init_and_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / "kekkai_home"
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "README.md").write_text("demo")

    monkeypatch.setenv("KEKKAI_HOME", str(base_dir))

    assert main(["init"]) == 0
    config_file = base_dir / "kekkai.toml"
    assert config_file.exists()

    assert main(["scan", "--repo", str(repo_dir), "--run-id", "fixed-run"]) == 0
    run_manifest = base_dir / "runs" / "fixed-run" / "run.json"
    assert run_manifest.exists()

    data = json.loads(run_manifest.read_text())
    assert data["run_id"] == "fixed-run"
    assert data["repo_path"] == str(repo_dir.resolve())
    assert data["status"] == "success"
