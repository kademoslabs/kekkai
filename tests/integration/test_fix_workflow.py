"""Integration tests for the fix workflow."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kekkai.fix import FixConfig, FixEngine, create_fix_engine
from kekkai.scanners.base import Finding, Severity


@pytest.mark.integration
class TestFixWorkflowIntegration:
    """Integration tests for full fix workflow."""

    def test_fix_dry_run_e2e(self, tmp_path: Path) -> None:
        """Test end-to-end fix workflow in dry-run mode."""
        # Create test repository structure
        repo_path = tmp_path / "repo"
        repo_path.mkdir()

        # Create vulnerable file
        vulnerable_file = repo_path / "app.py"
        vulnerable_file.write_text(
            "import os\n"
            "\n"
            "def run_command(cmd):\n"
            "    os.system(cmd)  # vulnerable\n"
            "    return True\n"
        )

        # Create scan results
        results_path = tmp_path / "results.json"
        results_path.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "check_id": "python.lang.security.audit.dangerous-system-call",
                            "path": "app.py",
                            "start": {"line": 4, "col": 5},
                            "extra": {
                                "severity": "ERROR",
                                "message": "os.system() is dangerous",
                                "metadata": {
                                    "message": "Use subprocess.run instead",
                                    "cwe": ["CWE-78"],
                                },
                            },
                        }
                    ]
                }
            )
        )

        # Run fix engine with mock model
        engine = create_fix_engine(model_mode="mock", dry_run=True)
        result = engine.fix_from_scan_results(results_path, repo_path)

        assert result.success
        assert result.findings_processed == 1
        # File should be unchanged in dry-run
        assert "os.system(cmd)" in vulnerable_file.read_text()

    def test_fix_apply_e2e(self, tmp_path: Path) -> None:
        """Test end-to-end fix workflow with apply."""
        # Create test repository structure
        repo_path = tmp_path / "repo"
        repo_path.mkdir()

        # Create vulnerable file
        vulnerable_file = repo_path / "app.py"
        original_content = "bad_code\n"
        vulnerable_file.write_text(original_content)

        # Create findings directly
        findings = [
            Finding(
                scanner="semgrep",
                title="Bad code pattern",
                severity=Severity.HIGH,
                description="This code is bad",
                file_path="app.py",
                line=1,
                rule_id="test.bad-code",
            )
        ]

        # Create engine with mock that returns valid diff
        from unittest.mock import MagicMock, patch

        config = FixConfig(model_mode="mock", dry_run=False, create_backups=True)
        engine = FixEngine(config)

        with patch.object(engine, "_get_model") as mock_get_model:
            mock_model = MagicMock()
            mock_model.name = "mock"
            mock_model.generate.return_value = MagicMock(
                success=True,
                content="--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-bad_code\n+good_code\n",
            )
            mock_get_model.return_value = mock_model

            output_dir = tmp_path / "output"
            result = engine.fix(findings, repo_path, output_dir)

        assert result.success
        assert result.fixes_generated == 1

        # Check audit log was created
        assert result.audit_log_path is not None
        assert result.audit_log_path.exists()

    def test_fix_mock_llm_integration(self, tmp_path: Path) -> None:
        """Test integration with mock LLM adapter."""
        repo_path = tmp_path / "repo"
        repo_path.mkdir()

        test_file = repo_path / "test.py"
        test_file.write_text("vulnerable_code\n")

        findings = [
            Finding(
                scanner="semgrep",
                title="Test finding",
                severity=Severity.MEDIUM,
                description="Test",
                file_path="test.py",
                line=1,
                rule_id="test.rule",
            )
        ]

        # Mock model mode should work without actual LLM
        engine = create_fix_engine(model_mode="mock", dry_run=True)
        result = engine.fix(findings, repo_path)

        assert result.success
        assert result.findings_processed == 1


@pytest.mark.integration
class TestFixCliIntegration:
    """Integration tests for fix CLI command."""

    def test_fix_command_help(self) -> None:
        """Test fix command help output."""
        from kekkai.cli import main

        # Running with --help raises SystemExit(0)
        with pytest.raises(SystemExit) as exc_info:
            main(["fix", "--help"])
        assert exc_info.value.code == 0

    def test_fix_command_missing_input(self) -> None:
        """Test fix command fails gracefully without input."""
        from kekkai.cli import main

        exit_code = main(["fix"])
        assert exit_code == 1  # Should fail

    def test_fix_command_with_mock(self, tmp_path: Path) -> None:
        """Test fix command with mock model."""
        # Create test files
        repo_path = tmp_path / "repo"
        repo_path.mkdir()

        test_file = repo_path / "app.py"
        test_file.write_text("os.system(cmd)\n")

        results_path = tmp_path / "results.json"
        results_path.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "check_id": "test-rule",
                            "path": "app.py",
                            "start": {"line": 1},
                            "extra": {
                                "severity": "ERROR",
                                "message": "Test",
                                "metadata": {"message": "Fix it"},
                            },
                        }
                    ]
                }
            )
        )

        from kekkai.cli import main

        exit_code = main(
            [
                "fix",
                "--input",
                str(results_path),
                "--repo",
                str(repo_path),
                "--model-mode",
                "mock",
                "--dry-run",
            ]
        )

        # Should succeed even with mock (dry run)
        assert exit_code == 0
