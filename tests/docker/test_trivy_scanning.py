"""Unit tests for Trivy security scanning."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from kekkai_core.docker.security import (
    TrivyScanError,
    count_vulnerabilities_by_severity,
    filter_vulnerabilities,
    has_critical_vulnerabilities,
    run_trivy_scan,
)


class TestTrivyScanning:
    """Test Trivy scan execution and result parsing."""

    @patch("subprocess.run")
    def test_trivy_scan_json_format(self, mock_run: MagicMock) -> None:
        """Verify Trivy scan returns JSON results."""
        scan_results = {
            "Results": [
                {"Vulnerabilities": [{"VulnerabilityID": "CVE-2023-1234", "Severity": "HIGH"}]}
            ]
        }

        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(scan_results), stderr="")

        result = run_trivy_scan("test-image:latest", output_format="json")

        assert result == scan_results
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "trivy" in args
        assert "image" in args
        assert "--format" in args
        assert "json" in args

    @patch("subprocess.run")
    def test_trivy_scan_sarif_format(self, mock_run: MagicMock) -> None:
        """Verify Trivy can output SARIF format."""
        sarif_results = {"version": "2.1.0", "runs": []}

        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(sarif_results), stderr="")

        result = run_trivy_scan("test-image:latest", output_format="sarif")

        assert result == sarif_results
        args = mock_run.call_args[0][0]
        assert "sarif" in args

    @patch("subprocess.run")
    def test_trivy_scan_with_severity_filter(self, mock_run: MagicMock) -> None:
        """Verify severity filtering in scan command."""
        mock_run.return_value = MagicMock(returncode=0, stdout="{}", stderr="")

        run_trivy_scan("test-image:latest", severity=["CRITICAL", "HIGH"])

        args = mock_run.call_args[0][0]
        assert "--severity" in args
        severity_index = args.index("--severity")
        assert args[severity_index + 1] == "CRITICAL,HIGH"

    @patch("subprocess.run")
    def test_trivy_scan_with_output_file(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify scan results can be written to file."""
        output_file = tmp_path / "scan-results.json"
        mock_run.return_value = MagicMock(returncode=0, stdout="{}", stderr="")

        run_trivy_scan("test-image:latest", output_file=output_file)

        args = mock_run.call_args[0][0]
        assert "--output" in args
        output_index = args.index("--output")
        assert args[output_index + 1] == str(output_file)

    @patch("subprocess.run")
    def test_trivy_scan_table_format(self, mock_run: MagicMock) -> None:
        """Verify table format output."""
        table_output = "CVE-2023-1234  HIGH  vulnerability description"
        mock_run.return_value = MagicMock(returncode=0, stdout=table_output, stderr="")

        result = run_trivy_scan("test-image:latest", output_format="table")

        assert result["output"] == table_output

    @patch("subprocess.run")
    def test_trivy_scan_failure_raises_error(self, mock_run: MagicMock) -> None:
        """Verify scan failures raise TrivyScanError."""
        mock_run.side_effect = Exception("Trivy command failed")

        with pytest.raises(TrivyScanError, match="Trivy scan failed"):
            run_trivy_scan("test-image:latest")

    @patch("subprocess.run")
    def test_trivy_scan_timeout_handled(self, mock_run: MagicMock) -> None:
        """Verify timeout errors are handled."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("trivy", 300)

        with pytest.raises(TrivyScanError, match="timed out"):
            run_trivy_scan("test-image:latest")

    @patch("subprocess.run")
    def test_trivy_scan_invalid_json_raises_error(self, mock_run: MagicMock) -> None:
        """Verify invalid JSON output raises error."""
        mock_run.return_value = MagicMock(returncode=0, stdout="invalid json", stderr="")

        with pytest.raises(TrivyScanError, match="Failed to parse"):
            run_trivy_scan("test-image:latest", output_format="json")


class TestVulnerabilityFiltering:
    """Test vulnerability filtering and counting."""

    def test_filter_vulnerabilities_by_severity(self) -> None:
        """Verify vulnerabilities filtered by severity threshold."""
        scan_results: dict[str, Any] = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-1", "Severity": "CRITICAL"},
                        {"VulnerabilityID": "CVE-2", "Severity": "HIGH"},
                        {"VulnerabilityID": "CVE-3", "Severity": "MEDIUM"},
                        {"VulnerabilityID": "CVE-4", "Severity": "LOW"},
                    ]
                }
            ]
        }

        filtered = filter_vulnerabilities(scan_results, "HIGH")

        assert len(filtered) == 2
        assert filtered[0]["VulnerabilityID"] == "CVE-1"
        assert filtered[1]["VulnerabilityID"] == "CVE-2"

    def test_filter_vulnerabilities_critical_only(self) -> None:
        """Verify filtering for CRITICAL only."""
        scan_results: dict[str, Any] = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-1", "Severity": "CRITICAL"},
                        {"VulnerabilityID": "CVE-2", "Severity": "HIGH"},
                    ]
                }
            ]
        }

        filtered = filter_vulnerabilities(scan_results, "CRITICAL")

        assert len(filtered) == 1
        assert filtered[0]["Severity"] == "CRITICAL"

    def test_filter_vulnerabilities_empty_results(self) -> None:
        """Verify filtering handles empty results."""
        scan_results: dict[str, Any] = {"Results": []}

        filtered = filter_vulnerabilities(scan_results, "HIGH")

        assert len(filtered) == 0

    def test_count_vulnerabilities_by_severity(self) -> None:
        """Verify vulnerability counting by severity."""
        scan_results: dict[str, Any] = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"Severity": "CRITICAL"},
                        {"Severity": "CRITICAL"},
                        {"Severity": "HIGH"},
                        {"Severity": "MEDIUM"},
                        {"Severity": "LOW"},
                    ]
                }
            ]
        }

        counts = count_vulnerabilities_by_severity(scan_results)

        assert counts["CRITICAL"] == 2
        assert counts["HIGH"] == 1
        assert counts["MEDIUM"] == 1
        assert counts["LOW"] == 1
        assert counts["UNKNOWN"] == 0

    def test_count_vulnerabilities_multiple_results(self) -> None:
        """Verify counting across multiple scan results."""
        scan_results: dict[str, Any] = {
            "Results": [
                {"Vulnerabilities": [{"Severity": "HIGH"}, {"Severity": "MEDIUM"}]},
                {"Vulnerabilities": [{"Severity": "HIGH"}, {"Severity": "LOW"}]},
            ]
        }

        counts = count_vulnerabilities_by_severity(scan_results)

        assert counts["HIGH"] == 2
        assert counts["MEDIUM"] == 1
        assert counts["LOW"] == 1

    def test_has_critical_vulnerabilities_true(self) -> None:
        """Verify detection of critical vulnerabilities."""
        scan_results = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"Severity": "CRITICAL"},
                        {"Severity": "MEDIUM"},
                    ]
                }
            ]
        }

        assert has_critical_vulnerabilities(scan_results, "CRITICAL") is True
        assert has_critical_vulnerabilities(scan_results, "HIGH") is True

    def test_has_critical_vulnerabilities_false(self) -> None:
        """Verify returns False when no critical vulnerabilities."""
        scan_results: dict[str, Any] = {
            "Results": [{"Vulnerabilities": [{"Severity": "MEDIUM"}, {"Severity": "LOW"}]}]
        }

        assert has_critical_vulnerabilities(scan_results, "CRITICAL") is False
        assert has_critical_vulnerabilities(scan_results, "HIGH") is False

    def test_has_critical_vulnerabilities_empty(self) -> None:
        """Verify handles empty scan results."""
        scan_results: dict[str, Any] = {"Results": []}

        assert has_critical_vulnerabilities(scan_results, "HIGH") is False


class TestScanCaching:
    """Test scan result caching behavior."""

    @patch("subprocess.run")
    def test_scan_results_cacheable(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify scan results can be cached to file."""
        cache_file = tmp_path / "trivy-cache.json"
        scan_results = {"Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}]}

        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(scan_results), stderr="")

        # Run scan with output file
        run_trivy_scan("test-image:latest", output_file=cache_file)

        # Verify file specified in command
        args = mock_run.call_args[0][0]
        assert str(cache_file) in args
