"""Regression tests for CLI output to ensure backwards compatibility."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kekkai.cli import main


@pytest.mark.regression
class TestExitCodesUnchanged:
    """Ensure exit codes remain unchanged after rich output changes."""

    def test_exit_code_0_on_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Success should return exit code 0."""
        monkeypatch.setenv("KEKKAI_HOME", str(tmp_path))

        result = main(["init"])
        assert result == 0

    def test_exit_code_0_no_args_with_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No args with existing config should return 0."""
        monkeypatch.setenv("KEKKAI_HOME", str(tmp_path))

        main(["init"])
        result = main([])
        assert result == 0

    def test_exit_code_1_config_exists_no_force(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Init without force on existing config returns 1."""
        monkeypatch.setenv("KEKKAI_HOME", str(tmp_path))

        main(["init"])
        result = main(["init"])
        assert result == 1

    def test_exit_code_1_invalid_run_id(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Invalid run-id should return exit code 1."""
        monkeypatch.setenv("KEKKAI_HOME", str(tmp_path))

        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()

        main(["init"])
        result = main(["scan", "--repo", str(repo_dir), "--run-id", "!!"])
        assert result == 1


@pytest.mark.regression
class TestJsonOutputUnchanged:
    """Ensure JSON output format remains unchanged."""

    def test_policy_result_json_structure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Policy result JSON should have expected structure."""
        monkeypatch.setenv("KEKKAI_HOME", str(tmp_path))

        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / "test.py").write_text("x = 1")

        output_file = tmp_path / "result.json"

        main(["init"])
        main(
            [
                "scan",
                "--repo",
                str(repo_dir),
                "--ci",
                "--scanners",
                "",
                "--output",
                str(output_file),
            ]
        )

        if output_file.exists():
            data = json.loads(output_file.read_text())
            # Verify expected keys exist
            assert "passed" in data
            assert "exit_code" in data
            assert "counts" in data


@pytest.mark.regression
class TestCliOutputContent:
    """Ensure CLI output still contains expected content."""

    def test_init_mentions_config_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Init should mention where config was created."""
        monkeypatch.setenv("KEKKAI_HOME", str(tmp_path))

        main(["init"])
        captured = capsys.readouterr()

        # Should mention config file
        assert "kekkai.toml" in captured.out or "config" in captured.out.lower()

    def test_scan_mentions_run_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Scan should indicate completion."""
        monkeypatch.setenv("KEKKAI_HOME", str(tmp_path))

        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()

        main(["init"])
        main(["scan", "--repo", str(repo_dir), "--scanners", ""])
        captured = capsys.readouterr()

        assert "Run complete" in captured.out or "complete" in captured.out.lower()
