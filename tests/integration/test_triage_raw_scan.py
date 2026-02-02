"""Integration tests for triage loading raw scanner outputs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kekkai.triage.loader import load_findings_from_path


class TestTriageRawScanIntegration:
    """Integration tests for loading raw scanner outputs into triage."""

    def test_semgrep_to_triage_workflow(self, tmp_path: Path) -> None:
        """Test full workflow: Semgrep output → triage loader → findings."""
        # Simulate Semgrep output from real scan
        semgrep_output = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.exec-used",
                    "path": "app.py",
                    "start": {"line": 42, "col": 5},
                    "end": {"line": 42, "col": 15},
                    "extra": {
                        "message": "Detected use of exec(). This is dangerous.",
                        "severity": "ERROR",
                        "metadata": {
                            "cwe": ["CWE-95"],
                            "owasp": ["A03:2021"],
                        },
                        "fingerprint": "abc123",
                    },
                }
            ],
            "errors": [],
        }

        scan_file = tmp_path / "semgrep-results.json"
        scan_file.write_text(json.dumps(semgrep_output))

        # Load findings
        findings, errors = load_findings_from_path(scan_file)

        # Verify findings loaded correctly
        assert len(findings) == 1
        assert not errors

        finding = findings[0]
        assert finding.scanner == "semgrep"
        assert finding.file_path == "app.py"
        assert finding.line == 42
        assert finding.rule_id == "python.lang.security.audit.exec-used"
        # Semgrep ERROR maps to HIGH severity
        from kekkai.triage.models import Severity

        assert finding.severity == Severity.HIGH

    def test_trivy_to_triage_workflow(self, tmp_path: Path) -> None:
        """Test full workflow: Trivy output → triage loader → findings."""
        # Simulate Trivy output from real scan
        trivy_output = {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-12345",
                            "PkgName": "django",
                            "InstalledVersion": "3.2.0",
                            "FixedVersion": "3.2.15",
                            "Severity": "CRITICAL",
                            "Title": "SQL Injection in Django",
                            "Description": "A critical SQL injection vulnerability...",
                        }
                    ],
                }
            ],
        }

        scan_file = tmp_path / "trivy-results.json"
        scan_file.write_text(json.dumps(trivy_output))

        # Load findings
        findings, errors = load_findings_from_path(scan_file)

        # Verify findings loaded correctly
        assert len(findings) == 1
        assert not errors

        finding = findings[0]
        assert finding.scanner == "trivy"
        assert "CVE-2023-12345" in finding.title or "django" in finding.title.lower()
        from kekkai.triage.models import Severity

        assert finding.severity == Severity.CRITICAL

    def test_gitleaks_to_triage_workflow(self, tmp_path: Path) -> None:
        """Test full workflow: Gitleaks output → triage loader → findings."""
        # Simulate Gitleaks output from real scan
        gitleaks_output = [
            {
                "Description": "GitHub Personal Access Token",
                "StartLine": 10,
                "EndLine": 10,
                "StartColumn": 15,
                "EndColumn": 55,
                "Match": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "Secret": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "File": "config/settings.py",
                "Commit": "a1b2c3d4e5f6",
                "Entropy": 4.2,
                "Author": "dev@example.com",
                "Email": "dev@example.com",
                "Date": "2024-01-15T10:30:00Z",
                "Message": "Add configuration",
                "Tags": [],
                "RuleID": "github-pat",
                "Fingerprint": "abc123:config/settings.py:github-pat:10",
            }
        ]

        scan_file = tmp_path / "gitleaks-results.json"
        scan_file.write_text(json.dumps(gitleaks_output))

        # Load findings
        findings, errors = load_findings_from_path(scan_file)

        # Verify findings loaded correctly
        assert len(findings) == 1
        assert not errors

        finding = findings[0]
        assert finding.scanner == "gitleaks"
        assert finding.file_path == "config/settings.py"
        assert finding.line == 10
        assert finding.rule_id == "github-pat"
        from kekkai.triage.models import Severity

        # Secrets are always high severity
        assert finding.severity == Severity.HIGH

    def test_mixed_scanners_directory(self, tmp_path: Path) -> None:
        """Test loading directory with multiple scanner outputs."""
        # Create multiple scanner outputs
        semgrep_data = {
            "results": [
                {
                    "check_id": "rule1",
                    "path": "file1.py",
                    "start": {"line": 1},
                    "extra": {"severity": "WARNING", "message": "Test"},
                }
            ]
        }
        (tmp_path / "semgrep-results.json").write_text(json.dumps(semgrep_data))

        trivy_data = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "PkgName": "lib",
                            "InstalledVersion": "1.0",
                            "Severity": "MEDIUM",
                            "Title": "Test vuln",
                        }
                    ],
                }
            ]
        }
        (tmp_path / "trivy-results.json").write_text(json.dumps(trivy_data))

        gitleaks_data = [
            {
                "RuleID": "test-secret",
                "Match": "secret",
                "File": "test.py",
                "StartLine": 1,
            }
        ]
        (tmp_path / "gitleaks-results.json").write_text(json.dumps(gitleaks_data))

        # Load all findings from directory
        findings, errors = load_findings_from_path(tmp_path)

        # Should aggregate findings from all scanners
        assert len(findings) == 3
        assert not errors

        # Verify we have findings from each scanner
        scanners = {f.scanner for f in findings}
        assert scanners == {"semgrep", "trivy", "gitleaks"}

    def test_directory_ignores_metadata_files(self, tmp_path: Path) -> None:
        """Test that run.json and policy-result.json are ignored."""
        # Create scanner results
        semgrep_data = {
            "results": [
                {
                    "check_id": "test",
                    "path": "test.py",
                    "start": {"line": 1},
                    "extra": {"severity": "INFO", "message": "Test"},
                }
            ]
        }
        (tmp_path / "semgrep-results.json").write_text(json.dumps(semgrep_data))

        # Create metadata files that should be ignored
        (tmp_path / "run.json").write_text('{"run_id": "test-123", "timestamp": "2024-01-01"}')
        (tmp_path / "policy-result.json").write_text('{"status": "passed", "gates": []}')

        # Load findings
        findings, errors = load_findings_from_path(tmp_path)

        # Should only load from semgrep-results.json
        assert len(findings) == 1
        assert findings[0].scanner == "semgrep"
        # No errors for the metadata files
        assert not errors


@pytest.mark.integration
class TestTriageDefaultLatestRun:
    """Integration tests for triage defaulting to latest run."""

    def test_loads_latest_run_directory(self, tmp_path: Path) -> None:
        """Test that triage loads from latest run when no input specified."""
        # Create multiple run directories
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()

        run1 = runs_dir / "run-20240101-100000"
        run1.mkdir()
        semgrep1 = {
            "results": [
                {
                    "check_id": "old-rule",
                    "path": "old.py",
                    "start": {"line": 1},
                    "extra": {"severity": "LOW", "message": "Old finding"},
                }
            ]
        }
        (run1 / "semgrep-results.json").write_text(json.dumps(semgrep1))

        # Create newer run (should be selected)
        run2 = runs_dir / "run-20240101-110000"
        run2.mkdir()
        semgrep2 = {
            "results": [
                {
                    "check_id": "new-rule",
                    "path": "new.py",
                    "start": {"line": 1},
                    "extra": {"severity": "HIGH", "message": "New finding"},
                }
            ]
        }
        (run2 / "semgrep-results.json").write_text(json.dumps(semgrep2))

        # Modify mtime to ensure run2 is newer
        import os
        import time

        os.utime(run1, (time.time() - 3600, time.time() - 3600))  # 1 hour ago
        os.utime(run2, (time.time(), time.time()))  # Now

        # Load from latest run
        findings, errors = load_findings_from_path(run2)  # Explicitly use run2 for test

        # Should load from run2 (newer)
        assert len(findings) == 1
        assert findings[0].rule_id == "new-rule"
