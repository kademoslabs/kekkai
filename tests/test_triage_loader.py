"""Unit tests for triage findings loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kekkai.triage.loader import load_findings_from_path
from kekkai.triage.models import Severity


class TestLoadFindingsFromPath:
    """Tests for load_findings_from_path function."""

    def test_load_native_triage_list(self, tmp_path: Path) -> None:
        """Test loading native triage JSON list format."""
        data: list[dict[str, Any]] = [
            {
                "id": "test-1",
                "title": "Test Finding",
                "severity": "high",
                "scanner": "trivy",
                "file_path": "test.py",
                "line": 10,
                "rule_id": "CVE-2024-1234",
                "description": "Test",
            }
        ]
        file_path = tmp_path / "findings.json"
        file_path.write_text(json.dumps(data))

        findings, errors = load_findings_from_path(file_path)

        assert len(findings) == 1
        assert findings[0].title == "Test Finding"
        assert findings[0].severity == Severity.HIGH
        assert not errors

    def test_load_native_triage_dict(self, tmp_path: Path) -> None:
        """Test loading native triage JSON with findings wrapper."""
        data = {
            "findings": [
                {
                    "id": "test-1",
                    "title": "Test Finding",
                    "severity": "medium",
                    "scanner": "semgrep",
                }
            ]
        }
        file_path = tmp_path / "findings.json"
        file_path.write_text(json.dumps(data))

        findings, errors = load_findings_from_path(file_path)

        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert not errors

    def test_load_semgrep_raw(self, tmp_path: Path) -> None:
        """Test loading raw Semgrep JSON output."""
        data = {
            "results": [
                {
                    "check_id": "python.security.eval",
                    "path": "app.py",
                    "start": {"line": 42},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Dangerous eval usage",
                        "metadata": {"cwe": ["CWE-95"]},
                    },
                }
            ],
            "errors": [],
        }
        file_path = tmp_path / "semgrep-results.json"
        file_path.write_text(json.dumps(data))

        findings, errors = load_findings_from_path(file_path)

        assert len(findings) == 1
        assert findings[0].scanner == "semgrep"
        assert findings[0].severity == Severity.HIGH  # ERROR maps to HIGH
        assert findings[0].line == 42
        assert not errors

    def test_load_trivy_raw(self, tmp_path: Path) -> None:
        """Test loading raw Trivy JSON output."""
        data = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Type": "pip",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-5678",
                            "PkgName": "requests",
                            "InstalledVersion": "2.28.0",
                            "FixedVersion": "2.32.0",
                            "Severity": "HIGH",
                            "Title": "Request smuggling vulnerability",
                            "Description": "Test description",
                        }
                    ],
                }
            ]
        }
        file_path = tmp_path / "trivy-results.json"
        file_path.write_text(json.dumps(data))

        findings, errors = load_findings_from_path(file_path)

        assert len(findings) == 1
        assert findings[0].scanner == "trivy"
        assert findings[0].severity == Severity.HIGH
        # Trivy uses Title field for the main title, not VulnerabilityID
        assert findings[0].title == "Request smuggling vulnerability"
        assert not errors

    def test_load_gitleaks_raw(self, tmp_path: Path) -> None:
        """Test loading raw Gitleaks JSON output."""
        data = [
            {
                "RuleID": "github-pat",
                "Match": "ghp_secret123",
                "File": "config.py",
                "StartLine": 5,
                "Commit": "abc123",
                "Author": "test@example.com",
            }
        ]
        file_path = tmp_path / "gitleaks-results.json"
        file_path.write_text(json.dumps(data))

        findings, errors = load_findings_from_path(file_path)

        assert len(findings) == 1
        assert findings[0].scanner == "gitleaks"
        assert findings[0].severity == Severity.HIGH  # Secrets are high
        assert findings[0].line == 5
        assert not errors

    def test_load_directory_aggregates_results(self, tmp_path: Path) -> None:
        """Test loading directory aggregates all *-results.json files."""
        # Create multiple scanner outputs
        semgrep_data = {
            "results": [
                {
                    "check_id": "test-rule",
                    "path": "test.py",
                    "start": {"line": 1},
                    "extra": {"severity": "WARNING", "message": "Test"},
                }
            ]
        }
        (tmp_path / "semgrep-results.json").write_text(json.dumps(semgrep_data))

        trivy_data = {"Results": [{"Target": "test", "Vulnerabilities": []}]}
        (tmp_path / "trivy-results.json").write_text(json.dumps(trivy_data))

        # Should ignore these
        (tmp_path / "run.json").write_text('{"run_id": "test"}')
        (tmp_path / "policy-result.json").write_text('{"status": "pass"}')

        findings, errors = load_findings_from_path(tmp_path)

        # Should load findings from semgrep only (trivy has no vulns)
        assert len(findings) == 1
        assert findings[0].scanner == "semgrep"

    def test_deduplication(self, tmp_path: Path) -> None:
        """Test that duplicate findings are removed."""
        data = {
            "findings": [
                {
                    "id": "dup",
                    "title": "Test",
                    "severity": "high",
                    "scanner": "test",
                    "rule_id": "R1",
                    "file_path": "test.py",
                    "line": 10,
                },
                {
                    "id": "dup2",  # Different ID but same content
                    "title": "Test",
                    "severity": "high",
                    "scanner": "test",
                    "rule_id": "R1",
                    "file_path": "test.py",
                    "line": 10,
                },
            ]
        }
        file_path = tmp_path / "findings.json"
        file_path.write_text(json.dumps(data))

        findings, errors = load_findings_from_path(file_path)

        # Should deduplicate based on scanner:rule_id:file_path:line
        assert len(findings) == 1

    def test_empty_file_skipped(self, tmp_path: Path) -> None:
        """Test that empty files are skipped without error."""
        file_path = tmp_path / "empty.json"
        file_path.write_text("")

        findings, errors = load_findings_from_path(file_path)

        assert len(findings) == 0
        assert not errors

    def test_invalid_json_error(self, tmp_path: Path) -> None:
        """Test that invalid JSON produces error message."""
        file_path = tmp_path / "invalid.json"
        file_path.write_text("{invalid json")

        findings, errors = load_findings_from_path(file_path)

        assert len(findings) == 0
        assert len(errors) == 1
        assert "invalid.json" in errors[0]
        assert "JSONDecodeError" in errors[0]

    def test_oversized_file_rejected(self, tmp_path: Path) -> None:
        """Test that files >200MB are rejected."""
        file_path = tmp_path / "huge.json"
        # Create a file that appears to be >200MB
        # (We'll mock the stat to avoid actually creating a huge file)
        file_path.write_text('{"test": "data"}')

        # Mock the file size
        import os
        from unittest.mock import patch

        with patch.object(Path, "stat") as mock_stat:
            mock_stat.return_value = os.stat_result(
                (0, 0, 0, 0, 0, 0, 250 * 1024 * 1024, 0, 0, 0)  # 250 MB
            )
            findings, errors = load_findings_from_path(file_path)

        assert len(findings) == 0
        assert len(errors) == 1
        assert "too large" in errors[0]
        assert "250" in errors[0]

    def test_unknown_scanner_error(self, tmp_path: Path) -> None:
        """Test that unknown scanner produces error."""
        data = {"some": "unknown format"}
        file_path = tmp_path / "unknown-scanner-results.json"
        file_path.write_text(json.dumps(data))

        findings, errors = load_findings_from_path(file_path)

        assert len(findings) == 0
        assert len(errors) == 1
        assert "unknown-scanner" in errors[0].lower() or "unsupported format" in errors[0].lower()

    def test_load_nonexistent_file(self, tmp_path: Path) -> None:
        """Test loading nonexistent file produces error."""
        file_path = tmp_path / "nonexistent.json"

        findings, errors = load_findings_from_path(file_path)

        assert len(findings) == 0
        assert len(errors) == 1
        assert "OSError" in errors[0]


class TestNormalizeScannerName:
    """Tests for scanner name normalization."""

    def test_normalize_scanner_name(self) -> None:
        """Test _normalize_scanner_name via upload command logic."""
        from kekkai.cli import _normalize_scanner_name

        assert _normalize_scanner_name("gitleaks-results") == "gitleaks"
        assert _normalize_scanner_name("trivy-results") == "trivy"
        assert _normalize_scanner_name("semgrep-results") == "semgrep"
        assert _normalize_scanner_name("custom-scanner") == "custom-scanner"
        assert _normalize_scanner_name("trivy") == "trivy"  # No suffix to strip
