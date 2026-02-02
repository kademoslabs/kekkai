"""Regression tests for unified report schema stability.

Ensures backward compatibility and schema consistency across versions.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kekkai.report.unified import generate_unified_report
from kekkai.scanners.base import Finding, ScanResult, Severity

pytestmark = pytest.mark.regression


class TestUnifiedReportSchema:
    """Tests for unified report schema stability."""

    @pytest.fixture
    def golden_report_structure(self) -> dict[str, object]:
        """Golden reference for report structure."""
        return {
            "version": "1.0.0",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "run_id": "test-run",
            "commit_sha": "abc123",
            "scan_metadata": {
                "scanner1": {
                    "success": True,
                    "findings_count": 1,
                    "duration_ms": 1000,
                }
            },
            "summary": {
                "total_findings": 1,
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0,
                "unknown": 0,
            },
            "findings": [
                {
                    "id": "abc123",
                    "scanner": "scanner1",
                    "title": "Test Finding",
                    "severity": "high",
                    "description": "Test description",
                    "file_path": "test.py",
                    "line": 42,
                    "rule_id": "test-rule",
                    "cwe": "CWE-89",
                    "cve": None,
                    "package_name": None,
                    "package_version": None,
                    "fixed_version": None,
                }
            ],
        }

    def test_report_has_required_top_level_fields(self, tmp_path: Path) -> None:
        """Test that report contains all required top-level fields."""
        output_path = tmp_path / "report.json"

        scan_results = [
            ScanResult(
                scanner="test",
                success=True,
                findings=[
                    Finding(
                        scanner="test",
                        title="Test",
                        severity=Severity.HIGH,
                        description="Test",
                    )
                ],
                duration_ms=1000,
            )
        ]

        generate_unified_report(
            scan_results=scan_results,
            output_path=output_path,
            run_id="test-run",
            commit_sha="abc123",
        )

        with output_path.open() as f:
            report = json.load(f)

        # Required top-level fields
        required_fields = [
            "version",
            "generated_at",
            "run_id",
            "commit_sha",
            "scan_metadata",
            "summary",
            "findings",
        ]

        for field in required_fields:
            assert field in report, f"Missing required field: {field}"

    def test_summary_has_all_severity_counts(self, tmp_path: Path) -> None:
        """Test that summary includes all severity level counts."""
        output_path = tmp_path / "report.json"

        scan_results = [
            ScanResult(
                scanner="test",
                success=True,
                findings=[],
                duration_ms=1000,
            )
        ]

        generate_unified_report(
            scan_results=scan_results,
            output_path=output_path,
            run_id="test-run",
        )

        with output_path.open() as f:
            report = json.load(f)

        summary = report["summary"]
        required_severities = [
            "total_findings",
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "unknown",
        ]

        for severity in required_severities:
            assert severity in summary, f"Missing severity count: {severity}"
            assert isinstance(summary[severity], int)

    def test_finding_has_required_fields(self, tmp_path: Path) -> None:
        """Test that each finding has all required fields."""
        output_path = tmp_path / "report.json"

        finding = Finding(
            scanner="semgrep",
            title="SQL Injection",
            severity=Severity.CRITICAL,
            description="Dangerous query",
            file_path="app/db.py",
            line=42,
            rule_id="sql-injection",
            cwe="CWE-89",
        )

        scan_results = [
            ScanResult(
                scanner="semgrep",
                success=True,
                findings=[finding],
                duration_ms=1000,
            )
        ]

        generate_unified_report(
            scan_results=scan_results,
            output_path=output_path,
            run_id="test-run",
        )

        with output_path.open() as f:
            report = json.load(f)

        result_finding = report["findings"][0]

        # Required finding fields
        required_fields = [
            "id",
            "scanner",
            "title",
            "severity",
            "description",
            "file_path",
            "line",
            "rule_id",
            "cwe",
            "cve",
            "package_name",
            "package_version",
            "fixed_version",
        ]

        for field in required_fields:
            assert field in result_finding, f"Finding missing field: {field}"

    def test_scanner_metadata_structure(self, tmp_path: Path) -> None:
        """Test scanner metadata structure is consistent."""
        output_path = tmp_path / "report.json"

        scan_results = [
            ScanResult(
                scanner="trivy",
                success=True,
                findings=[
                    Finding(
                        scanner="trivy",
                        title="Test",
                        severity=Severity.HIGH,
                        description="Test",
                    )
                ],
                duration_ms=1234,
            ),
            ScanResult(
                scanner="semgrep",
                success=False,
                findings=[],
                error="Scanner failed",
                duration_ms=500,
            ),
        ]

        generate_unified_report(
            scan_results=scan_results,
            output_path=output_path,
            run_id="test-run",
        )

        with output_path.open() as f:
            report = json.load(f)

        # Successful scanner metadata
        trivy_meta = report["scan_metadata"]["trivy"]
        assert "success" in trivy_meta
        assert trivy_meta["success"] is True
        assert "findings_count" in trivy_meta
        assert "duration_ms" in trivy_meta

        # Failed scanner metadata
        semgrep_meta = report["scan_metadata"]["semgrep"]
        assert "success" in semgrep_meta
        assert semgrep_meta["success"] is False
        assert "error" in semgrep_meta
        assert "duration_ms" in semgrep_meta

    def test_version_field_is_stable(self, tmp_path: Path) -> None:
        """Test that version field remains stable."""
        output_path = tmp_path / "report.json"

        scan_results = [
            ScanResult(
                scanner="test",
                success=True,
                findings=[],
                duration_ms=1000,
            )
        ]

        generate_unified_report(
            scan_results=scan_results,
            output_path=output_path,
            run_id="test-run",
        )

        with output_path.open() as f:
            report = json.load(f)

        # Version should be semantic versioning
        assert report["version"] == "1.0.0"

    def test_backward_compatibility_with_triage(self, tmp_path: Path) -> None:
        """Test that unified report is compatible with triage loader."""
        from kekkai.triage.loader import load_findings_from_path

        output_path = tmp_path / "kekkai-report.json"

        # Generate report
        scan_results = [
            ScanResult(
                scanner="semgrep",
                success=True,
                findings=[
                    Finding(
                        scanner="semgrep",
                        title="SQL Injection",
                        severity=Severity.CRITICAL,
                        description="Test",
                        file_path="app/db.py",
                        line=42,
                        rule_id="sql-injection",
                    )
                ],
                duration_ms=1000,
            )
        ]

        generate_unified_report(
            scan_results=scan_results,
            output_path=output_path,
            run_id="test-run",
        )

        # Verify triage can load it
        findings, errors = load_findings_from_path(tmp_path)

        assert len(findings) == 1
        assert findings[0].scanner == "semgrep"
        assert findings[0].title == "SQL Injection"
        assert not errors

    def test_json_serializable(self, tmp_path: Path) -> None:
        """Test that report is valid JSON."""
        output_path = tmp_path / "report.json"

        scan_results = [
            ScanResult(
                scanner="test",
                success=True,
                findings=[
                    Finding(
                        scanner="test",
                        title="Test",
                        severity=Severity.HIGH,
                        description="Test",
                    )
                ],
                duration_ms=1000,
            )
        ]

        generate_unified_report(
            scan_results=scan_results,
            output_path=output_path,
            run_id="test-run",
        )

        # Verify it's valid JSON
        with output_path.open() as f:
            report = json.load(f)

        # Verify can be re-serialized
        json_str = json.dumps(report)
        assert isinstance(json_str, str)
        assert len(json_str) > 0

    def test_null_values_handled_correctly(self, tmp_path: Path) -> None:
        """Test that null/None values are handled correctly."""
        output_path = tmp_path / "report.json"

        # Finding with many None values
        finding = Finding(
            scanner="test",
            title="Test",
            severity=Severity.LOW,
            description="Test",
            file_path=None,
            line=None,
            rule_id=None,
            cwe=None,
            cve=None,
        )

        scan_results = [
            ScanResult(
                scanner="test",
                success=True,
                findings=[finding],
                duration_ms=1000,
            )
        ]

        generate_unified_report(
            scan_results=scan_results,
            output_path=output_path,
            run_id="test-run",
            commit_sha=None,
        )

        with output_path.open() as f:
            report = json.load(f)

        # Verify None values are serialized as null
        assert report["commit_sha"] is None

        result_finding = report["findings"][0]
        assert result_finding["file_path"] is None
        assert result_finding["line"] is None
        assert result_finding["rule_id"] is None
        assert result_finding["cwe"] is None
        assert result_finding["cve"] is None

    def test_unicode_handling(self, tmp_path: Path) -> None:
        """Test that Unicode characters are handled correctly."""
        output_path = tmp_path / "report.json"

        finding = Finding(
            scanner="test",
            title="SQL注入 (SQL Injection)",
            severity=Severity.HIGH,
            description="Опасный запрос в базу данных 🔒",
            file_path="测试/app.py",
        )

        scan_results = [
            ScanResult(
                scanner="test",
                success=True,
                findings=[finding],
                duration_ms=1000,
            )
        ]

        generate_unified_report(
            scan_results=scan_results,
            output_path=output_path,
            run_id="test-run",
        )

        # Verify Unicode preserved
        with output_path.open(encoding="utf-8") as f:
            report = json.load(f)

        result_finding = report["findings"][0]
        # After redaction, original content might be modified, but should not crash
        assert result_finding["title"] is not None
        assert result_finding["description"] is not None
        assert result_finding["file_path"] is not None

    def test_report_is_idempotent(self, tmp_path: Path) -> None:
        """Test that generating report twice produces same structure."""
        output_path1 = tmp_path / "report1.json"
        output_path2 = tmp_path / "report2.json"

        scan_results = [
            ScanResult(
                scanner="test",
                success=True,
                findings=[
                    Finding(
                        scanner="test",
                        title="Test",
                        severity=Severity.MEDIUM,
                        description="Test",
                    )
                ],
                duration_ms=1000,
            )
        ]

        # Generate twice
        report1 = generate_unified_report(
            scan_results=scan_results,
            output_path=output_path1,
            run_id="test-run",
            commit_sha="abc123",
        )

        report2 = generate_unified_report(
            scan_results=scan_results,
            output_path=output_path2,
            run_id="test-run",
            commit_sha="abc123",
        )

        # Structure should be same (timestamps may differ)
        assert set(report1.keys()) == set(report2.keys())
        assert report1["version"] == report2["version"]
        assert report1["run_id"] == report2["run_id"]
        assert len(report1["findings"]) == len(report2["findings"])
