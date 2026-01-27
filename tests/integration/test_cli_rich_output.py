"""Integration tests for Rich CLI output."""

from __future__ import annotations

from pathlib import Path

import pytest

from kekkai.cli import main


@pytest.mark.integration
class TestCliRichOutput:
    """Integration tests for CLI rich output rendering."""

    def test_init_shows_banner(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that kekkai init shows branded banner."""
        monkeypatch.setenv("KEKKAI_HOME", str(tmp_path))

        result = main(["init"])

        assert result == 0
        captured = capsys.readouterr()
        # Should contain Kekkai branding
        assert "Kekkai" in captured.out

    def test_init_shows_quick_start(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that kekkai init shows Quick Start guide."""
        monkeypatch.setenv("KEKKAI_HOME", str(tmp_path))

        result = main(["init"])

        assert result == 0
        captured = capsys.readouterr()
        # Should contain Quick Start commands
        assert "scan" in captured.out.lower()

    def test_no_args_shows_banner(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that running kekkai with no args shows banner."""
        monkeypatch.setenv("KEKKAI_HOME", str(tmp_path))

        # First init
        main(["init"])
        capsys.readouterr()  # Clear output

        # Then run without args
        result = main([])

        assert result == 0
        captured = capsys.readouterr()
        assert "Kekkai" in captured.out

    def test_ci_mode_produces_parseable_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that CI mode produces parseable plain text output."""
        monkeypatch.setenv("KEKKAI_HOME", str(tmp_path))

        # Init first
        main(["init"])
        capsys.readouterr()

        # Create a test repo
        repo_dir = tmp_path / "test_repo"
        repo_dir.mkdir()
        (repo_dir / "test.py").write_text("print('hello')")

        result = main(["scan", "--repo", str(repo_dir), "--scanners", ""])

        captured = capsys.readouterr()
        # Output should be readable text
        assert "Run complete" in captured.out or result == 0

    def test_scan_with_invalid_run_id_shows_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that invalid run-id shows proper error message."""
        monkeypatch.setenv("KEKKAI_HOME", str(tmp_path))

        # Init first
        main(["init"])
        capsys.readouterr()

        repo_dir = tmp_path / "test_repo"
        repo_dir.mkdir()

        result = main(["scan", "--repo", str(repo_dir), "--run-id", "!!invalid!!"])

        assert result == 1
        captured = capsys.readouterr()
        assert "Run id must be" in captured.out


@pytest.mark.integration
class TestCliNonTtyMode:
    """Tests for CLI behavior in non-TTY (CI) environments."""

    def test_output_contains_expected_content(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that output contains expected content."""
        monkeypatch.setenv("KEKKAI_HOME", str(tmp_path))

        result = main(["init"])

        assert result == 0
        captured = capsys.readouterr()
        # Output should be present
        assert len(captured.out) > 0
        # Should contain config path info
        assert "kekkai.toml" in captured.out
