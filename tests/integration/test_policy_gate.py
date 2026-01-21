"""Integration tests for policy gate in CI mode."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from kekkai import cli
from kekkai.policy import EXIT_POLICY_VIOLATION, EXIT_SUCCESS


@pytest.mark.integration
class TestPolicyGateIntegration:
    """Integration tests for --ci mode policy enforcement."""

    @pytest.fixture
    def temp_repo(self, tmp_path: Path) -> Path:
        """Create a temporary repository directory."""
        repo = tmp_path / "test_repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        return repo

    @pytest.fixture
    def temp_config(self, tmp_path: Path, temp_repo: Path) -> Path:
        """Create a temporary config file."""
        config = tmp_path / "kekkai.toml"
        config.write_text(
            f"""
repo_path = "{temp_repo}"
run_base_dir = "{tmp_path / "runs"}"
timeout_seconds = 60
env_allowlist = ["PATH", "HOME"]
"""
        )
        return config

    def test_ci_mode_passes_with_no_findings(
        self,
        temp_config: Path,
        temp_repo: Path,
        tmp_path: Path,
    ) -> None:
        """Test that --ci passes when there are no findings."""
        run_dir = tmp_path / "runs" / "test-run"
        run_dir.mkdir(parents=True)

        # Mock scanner to return no findings
        with mock.patch("kekkai.cli._create_scanner") as mock_scanner:
            mock_instance = mock.MagicMock()
            mock_instance.run.return_value = mock.MagicMock(
                success=True,
                findings=[],
                scanner="trivy",
                error=None,
            )
            mock_scanner.return_value = mock_instance

            exit_code = cli.main(
                [
                    "scan",
                    "--config",
                    str(temp_config),
                    "--ci",
                    "--scanners",
                    "trivy",
                    "--run-dir",
                    str(run_dir),
                    "--run-id",
                    "test-run",
                ]
            )

        assert exit_code == EXIT_SUCCESS

        # Verify policy result JSON was written
        result_path = run_dir / "policy-result.json"
        assert result_path.exists()
        result = json.loads(result_path.read_text())
        assert result["passed"] is True

    def test_ci_mode_fails_on_critical_finding(
        self,
        temp_config: Path,
        temp_repo: Path,
        tmp_path: Path,
    ) -> None:
        """Test that --ci fails when there are critical findings."""
        from kekkai.scanners.base import Finding, Severity

        run_dir = tmp_path / "runs" / "test-run"
        run_dir.mkdir(parents=True)

        critical_finding = Finding(
            scanner="trivy",
            title="Critical CVE",
            severity=Severity.CRITICAL,
            description="A critical vulnerability",
        )

        with mock.patch("kekkai.cli._create_scanner") as mock_scanner:
            mock_instance = mock.MagicMock()
            mock_instance.run.return_value = mock.MagicMock(
                success=True,
                findings=[critical_finding],
                scanner="trivy",
                error=None,
            )
            mock_scanner.return_value = mock_instance

            exit_code = cli.main(
                [
                    "scan",
                    "--config",
                    str(temp_config),
                    "--ci",
                    "--scanners",
                    "trivy",
                    "--run-dir",
                    str(run_dir),
                    "--run-id",
                    "test-run",
                ]
            )

        assert exit_code == EXIT_POLICY_VIOLATION

        # Verify policy result JSON
        result_path = run_dir / "policy-result.json"
        assert result_path.exists()
        result = json.loads(result_path.read_text())
        assert result["passed"] is False
        assert result["counts"]["critical"] == 1

    def test_fail_on_medium_includes_cascade(
        self,
        temp_config: Path,
        temp_repo: Path,
        tmp_path: Path,
    ) -> None:
        """Test that --fail-on=medium also fails on high and critical."""
        from kekkai.scanners.base import Finding, Severity

        run_dir = tmp_path / "runs" / "test-run"
        run_dir.mkdir(parents=True)

        high_finding = Finding(
            scanner="trivy",
            title="High CVE",
            severity=Severity.HIGH,
            description="A high severity vulnerability",
        )

        with mock.patch("kekkai.cli._create_scanner") as mock_scanner:
            mock_instance = mock.MagicMock()
            mock_instance.run.return_value = mock.MagicMock(
                success=True,
                findings=[high_finding],
                scanner="trivy",
                error=None,
            )
            mock_scanner.return_value = mock_instance

            exit_code = cli.main(
                [
                    "scan",
                    "--config",
                    str(temp_config),
                    "--fail-on",
                    "medium",
                    "--scanners",
                    "trivy",
                    "--run-dir",
                    str(run_dir),
                    "--run-id",
                    "test-run",
                ]
            )

        # Should fail because high is included when medium is specified
        assert exit_code == EXIT_POLICY_VIOLATION

    def test_custom_output_path(
        self,
        temp_config: Path,
        temp_repo: Path,
        tmp_path: Path,
    ) -> None:
        """Test that --output writes to custom path."""
        run_dir = tmp_path / "runs" / "test-run"
        run_dir.mkdir(parents=True)
        custom_output = tmp_path / "custom-result.json"

        with mock.patch("kekkai.cli._create_scanner") as mock_scanner:
            mock_instance = mock.MagicMock()
            mock_instance.run.return_value = mock.MagicMock(
                success=True,
                findings=[],
                scanner="trivy",
                error=None,
            )
            mock_scanner.return_value = mock_instance

            exit_code = cli.main(
                [
                    "scan",
                    "--config",
                    str(temp_config),
                    "--ci",
                    "--scanners",
                    "trivy",
                    "--run-dir",
                    str(run_dir),
                    "--run-id",
                    "test-run",
                    "--output",
                    str(custom_output),
                ]
            )

        assert exit_code == EXIT_SUCCESS
        assert custom_output.exists()
        result = json.loads(custom_output.read_text())
        assert result["passed"] is True

    def test_medium_findings_pass_with_default_policy(
        self,
        temp_config: Path,
        temp_repo: Path,
        tmp_path: Path,
    ) -> None:
        """Test that medium findings pass with default CI policy."""
        from kekkai.scanners.base import Finding, Severity

        run_dir = tmp_path / "runs" / "test-run"
        run_dir.mkdir(parents=True)

        medium_finding = Finding(
            scanner="trivy",
            title="Medium CVE",
            severity=Severity.MEDIUM,
            description="A medium severity vulnerability",
        )

        with mock.patch("kekkai.cli._create_scanner") as mock_scanner:
            mock_instance = mock.MagicMock()
            mock_instance.run.return_value = mock.MagicMock(
                success=True,
                findings=[medium_finding],
                scanner="trivy",
                error=None,
            )
            mock_scanner.return_value = mock_instance

            exit_code = cli.main(
                [
                    "scan",
                    "--config",
                    str(temp_config),
                    "--ci",
                    "--scanners",
                    "trivy",
                    "--run-dir",
                    str(run_dir),
                    "--run-id",
                    "test-run",
                ]
            )

        # Should pass - default CI policy only fails on critical/high
        assert exit_code == EXIT_SUCCESS
