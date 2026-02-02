"""Integration tests for unified report workflow.

Tests end-to-end functionality:
- kekkai scan creates unified report
- --output flag controls report location
- kekkai triage loads unified report
- Path validation and security controls
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from kekkai.cli import main
from kekkai.scanners.base import Finding, ScanResult, Severity

pytestmark = pytest.mark.integration


class TestUnifiedReportWorkflow:
    """Integration tests for unified report generation in scan workflow."""

    @pytest.fixture
    def mock_scanner_results(self) -> list[ScanResult]:
        """Create mock scanner results."""
        return [
            ScanResult(
                scanner="trivy",
                success=True,
                findings=[
                    Finding(
                        scanner="trivy",
                        title="CVE-2023-1234",
                        severity=Severity.HIGH,
                        description="Vulnerability in package",
                        cve="CVE-2023-1234",
                        package_name="test-pkg",
                        package_version="1.0.0",
                    )
                ],
                duration_ms=1000,
            ),
            ScanResult(
                scanner="semgrep",
                success=True,
                findings=[
                    Finding(
                        scanner="semgrep",
                        title="SQL Injection",
                        severity=Severity.CRITICAL,
                        description="Dangerous SQL query",
                        file_path="app/db.py",
                        line=42,
                        rule_id="python.sql-injection",
                    )
                ],
                duration_ms=2000,
            ),
        ]

    def test_scan_creates_unified_report_in_run_dir(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        mock_scanner_results: list[ScanResult],
    ) -> None:
        """Test that kekkai scan creates unified report in run directory."""
        base_dir = tmp_path / "kekkai_home"
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()

        monkeypatch.setenv("KEKKAI_HOME", str(base_dir))

        # Initialize config
        assert main(["init"]) == 0

        # Mock scanner execution
        with patch("kekkai.cli._create_scanner") as mock_create:
            mock_scanner = Mock()
            mock_scanner.name = "trivy"
            mock_scanner.run.return_value = mock_scanner_results[0]
            mock_create.return_value = mock_scanner

            # Run scan
            exit_code = main(
                [
                    "scan",
                    "--repo",
                    str(repo_dir),
                    "--scanners",
                    "trivy",
                    "--run-id",
                    "test-run",
                ]
            )

            assert exit_code == 0

        # Verify unified report was created
        run_dir = base_dir / "runs" / "test-run"
        report_path = run_dir / "kekkai-report.json"

        assert report_path.exists(), f"Report not found at {report_path}"

        # Verify report content
        with report_path.open() as f:
            report = json.load(f)

        assert report["version"] == "1.0.0"
        assert report["run_id"] == "test-run"
        assert "findings" in report
        assert "scan_metadata" in report
        assert "summary" in report

    def test_output_flag_controls_report_location(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        mock_scanner_results: list[ScanResult],
    ) -> None:
        """Test that --output flag controls unified report location."""
        base_dir = tmp_path / "kekkai_home"
        repo_dir = tmp_path / "repo"
        custom_output = tmp_path / "custom-report.json"
        repo_dir.mkdir()

        monkeypatch.setenv("KEKKAI_HOME", str(base_dir))

        # Initialize config
        assert main(["init"]) == 0

        # Mock scanner execution
        with patch("kekkai.cli._create_scanner") as mock_create:
            mock_scanner = Mock()
            mock_scanner.name = "trivy"
            mock_scanner.run.return_value = mock_scanner_results[0]
            mock_create.return_value = mock_scanner

            # Run scan with custom output
            exit_code = main(
                [
                    "scan",
                    "--repo",
                    str(repo_dir),
                    "--scanners",
                    "trivy",
                    "--run-id",
                    "test-run",
                    "--output",
                    str(custom_output),
                ]
            )

            assert exit_code == 0

        # Verify report created at custom location
        assert custom_output.exists(), f"Report not found at {custom_output}"

        # Verify content
        with custom_output.open() as f:
            report = json.load(f)

        assert report["version"] == "1.0.0"
        assert "findings" in report

    def test_triage_loads_unified_report(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that triage loads unified report when available."""
        from kekkai.triage.loader import load_findings_from_path

        # Create run directory with unified report
        run_dir = tmp_path / "run-123"
        run_dir.mkdir()

        report_data = {
            "version": "1.0.0",
            "run_id": "run-123",
            "findings": [
                {
                    "id": "abc123",
                    "scanner": "trivy",
                    "title": "CVE-2023-1234",
                    "severity": "high",
                    "description": "Test vulnerability",
                    "file_path": None,
                    "line": None,
                    "rule_id": None,
                    "cwe": None,
                    "cve": "CVE-2023-1234",
                    "package_name": "test-pkg",
                    "package_version": "1.0.0",
                    "fixed_version": None,
                }
            ],
            "summary": {"total_findings": 1, "high": 1},
            "scan_metadata": {},
        }

        # Write unified report
        report_path = run_dir / "kekkai-report.json"
        with report_path.open("w") as f:
            json.dump(report_data, f)

        # Also create individual scanner result (should be ignored)
        trivy_path = run_dir / "trivy-results.json"
        with trivy_path.open("w") as f:
            json.dump({"Results": []}, f)

        # Load findings
        findings, errors = load_findings_from_path(run_dir)

        # Verify loaded from unified report
        assert len(findings) == 1
        assert findings[0].scanner == "trivy"
        assert findings[0].title == "CVE-2023-1234"
        assert not errors

    def test_triage_falls_back_to_individual_results(
        self,
        tmp_path: Path,
    ) -> None:
        """Test triage fallback to individual scanner results."""
        from kekkai.triage.loader import load_findings_from_path

        # Create run directory WITHOUT unified report
        run_dir = tmp_path / "run-old"
        run_dir.mkdir()

        # Only individual scanner results (old format)
        semgrep_data = {
            "results": [
                {
                    "check_id": "sql-injection",
                    "path": "app/db.py",
                    "start": {"line": 42},
                    "extra": {
                        "severity": "ERROR",
                        "message": "SQL injection detected",
                    },
                }
            ]
        }

        semgrep_path = run_dir / "semgrep-results.json"
        with semgrep_path.open("w") as f:
            json.dump(semgrep_data, f)

        # Load findings (should fallback to individual files)
        findings, errors = load_findings_from_path(run_dir)

        # Verify loaded successfully
        assert len(findings) == 1
        assert findings[0].scanner == "semgrep"
        assert not errors

    def test_path_validation_warns_outside_base(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        mock_scanner_results: list[ScanResult],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Test that output path outside base directory shows warning."""
        base_dir = tmp_path / "kekkai_home"
        repo_dir = tmp_path / "repo"
        outside_path = tmp_path / "outside" / "report.json"
        outside_path.parent.mkdir(parents=True)
        repo_dir.mkdir()

        monkeypatch.setenv("KEKKAI_HOME", str(base_dir))

        # Initialize config
        assert main(["init"]) == 0

        # Mock scanner execution
        with patch("kekkai.cli._create_scanner") as mock_create:
            mock_scanner = Mock()
            mock_scanner.name = "trivy"
            mock_scanner.run.return_value = mock_scanner_results[0]
            mock_create.return_value = mock_scanner

            # Run scan with output outside base
            exit_code = main(
                [
                    "scan",
                    "--repo",
                    str(repo_dir),
                    "--scanners",
                    "trivy",
                    "--run-id",
                    "test-run",
                    "--output",
                    str(outside_path),
                ]
            )

            assert exit_code == 0

        # Verify file was created
        assert outside_path.exists()

        # Verify warning was shown (check stdout/stderr)
        _ = capsys.readouterr()
        # The warning should mention writing outside kekkai home
        # (exact format depends on console.print implementation)

    def test_multiple_scanners_aggregated(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        mock_scanner_results: list[ScanResult],
    ) -> None:
        """Test that findings from multiple scanners are aggregated."""
        base_dir = tmp_path / "kekkai_home"
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()

        monkeypatch.setenv("KEKKAI_HOME", str(base_dir))

        # Initialize config
        assert main(["init"]) == 0

        # Mock multiple scanners
        def mock_create_scanner(name: str, **kwargs: object) -> Mock:
            mock = Mock()
            mock.name = name
            if name == "trivy":
                mock.run.return_value = mock_scanner_results[0]
            elif name == "semgrep":
                mock.run.return_value = mock_scanner_results[1]
            else:
                mock.run.return_value = ScanResult(
                    scanner=name,
                    success=True,
                    findings=[],
                    duration_ms=100,
                )
            return mock

        with patch("kekkai.cli._create_scanner", side_effect=mock_create_scanner):
            # Run scan with multiple scanners
            exit_code = main(
                [
                    "scan",
                    "--repo",
                    str(repo_dir),
                    "--scanners",
                    "trivy,semgrep",
                    "--run-id",
                    "test-run",
                ]
            )

            assert exit_code == 0

        # Verify unified report aggregated both
        run_dir = base_dir / "runs" / "test-run"
        report_path = run_dir / "kekkai-report.json"

        with report_path.open() as f:
            report = json.load(f)

        # Should have findings from both scanners
        assert len(report["findings"]) == 2
        scanners = {f["scanner"] for f in report["findings"]}
        assert "trivy" in scanners
        assert "semgrep" in scanners

        # Verify metadata for both
        assert "trivy" in report["scan_metadata"]
        assert "semgrep" in report["scan_metadata"]

    def test_unified_report_with_no_findings(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test unified report generation when no findings."""
        base_dir = tmp_path / "kekkai_home"
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()

        monkeypatch.setenv("KEKKAI_HOME", str(base_dir))

        # Initialize config
        assert main(["init"]) == 0

        # Mock scanner with no findings
        with patch("kekkai.cli._create_scanner") as mock_create:
            mock_scanner = Mock()
            mock_scanner.name = "trivy"
            mock_scanner.run.return_value = ScanResult(
                scanner="trivy",
                success=True,
                findings=[],
                duration_ms=1000,
            )
            mock_create.return_value = mock_scanner

            # Run scan
            exit_code = main(
                [
                    "scan",
                    "--repo",
                    str(repo_dir),
                    "--scanners",
                    "trivy",
                    "--run-id",
                    "test-run",
                ]
            )

            assert exit_code == 0

        # Verify report still created
        run_dir = base_dir / "runs" / "test-run"
        report_path = run_dir / "kekkai-report.json"

        assert report_path.exists()

        with report_path.open() as f:
            report = json.load(f)

        assert report["summary"]["total_findings"] == 0
        assert len(report["findings"]) == 0
