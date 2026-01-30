"""Integration tests for the report generation workflow."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kekkai.report import ReportConfig, ReportFormat, generate_report
from kekkai.scanners.base import Finding, Severity


@pytest.fixture
def realistic_findings() -> list[Finding]:
    """Create realistic findings simulating actual scan output."""
    return [
        # Semgrep SAST findings
        Finding(
            scanner="semgrep",
            title="Dangerous os.system call with user input",
            severity=Severity.HIGH,
            description="User input is passed to os.system() which can lead to command injection",
            file_path="app/handlers.py",
            line=156,
            rule_id="python.lang.security.audit.dangerous-system-call",
            cwe="CWE-78",
        ),
        Finding(
            scanner="semgrep",
            title="SQL query built using string formatting",
            severity=Severity.HIGH,
            description="SQL query is constructed using string formatting with user input",
            file_path="app/database.py",
            line=89,
            rule_id="python.lang.security.audit.formatted-sql-query",
            cwe="CWE-89",
        ),
        Finding(
            scanner="semgrep",
            title="JWT token validation disabled",
            severity=Severity.CRITICAL,
            description="JWT verification is disabled, allowing forged tokens",
            file_path="app/auth.py",
            line=45,
            rule_id="python.jwt.security.jwt-decode-without-verification",
            cwe="CWE-287",
        ),
        Finding(
            scanner="semgrep",
            title="Hardcoded password in configuration",
            severity=Severity.HIGH,
            description="Password is hardcoded in source code",
            file_path="config/settings.py",
            line=23,
            rule_id="python.lang.security.audit.hardcoded-password",
            cwe="CWE-798",
        ),
        # Trivy SCA findings
        Finding(
            scanner="trivy",
            title="CVE-2023-32681: Requests Session Object Vulnerability",
            severity=Severity.MEDIUM,
            description="The requests library before 2.31.0 can leak auth credentials",
            cve="CVE-2023-32681",
            package_name="requests",
            package_version="2.28.0",
            fixed_version="2.31.0",
        ),
        Finding(
            scanner="trivy",
            title="CVE-2022-42969: ReDoS in py library",
            severity=Severity.HIGH,
            description="The py library before 1.11.0 allows ReDoS",
            cve="CVE-2022-42969",
            package_name="py",
            package_version="1.10.0",
            fixed_version="1.11.0",
        ),
        # Gitleaks secrets
        Finding(
            scanner="gitleaks",
            title="AWS Access Key ID",
            severity=Severity.HIGH,
            description="AWS access key found in source code",
            file_path=".env.example",
            line=3,
            rule_id="aws-access-key-id",
        ),
        Finding(
            scanner="gitleaks",
            title="GitHub Personal Access Token",
            severity=Severity.HIGH,
            description="GitHub PAT found in configuration",
            file_path="scripts/deploy.sh",
            line=12,
            rule_id="github-pat",
        ),
    ]


@pytest.mark.integration
class TestReportGenerationWorkflow:
    """Integration tests for full report generation workflow."""

    def test_full_html_report_workflow(
        self, realistic_findings: list[Finding], tmp_path: Path
    ) -> None:
        """Test complete HTML report generation workflow."""
        config = ReportConfig(
            formats=[ReportFormat.HTML],
            title="Security Assessment Report",
            organization="Acme Corp",
            project_name="payment-service",
        )

        result = generate_report(realistic_findings, tmp_path, config)

        assert result.success
        assert result.generation_time_ms > 0
        assert len(result.output_files) == 1

        html_path = result.output_files[0]
        assert html_path.exists()

        content = html_path.read_text()

        # Verify structure
        assert "<!DOCTYPE html>" in content
        assert "Security Assessment Report" in content
        assert "Acme Corp" in content
        assert "payment-service" in content

        # Verify findings are included
        assert "Dangerous os.system" in content
        assert "CVE-2023-32681" in content
        assert "AWS Access Key" in content

        # Verify compliance frameworks
        assert "PCI-DSS" in content
        assert "OWASP" in content

        # Verify severity badges (case-insensitive check)
        assert "critical" in content.lower()
        assert "high" in content.lower()

    def test_compliance_matrix_workflow(
        self, realistic_findings: list[Finding], tmp_path: Path
    ) -> None:
        """Test compliance matrix report generation."""
        config = ReportConfig(
            formats=[ReportFormat.COMPLIANCE],
            frameworks=["PCI-DSS", "OWASP"],
        )

        result = generate_report(realistic_findings, tmp_path, config)

        assert result.success

        matrix_path = [p for p in result.output_files if "compliance" in p.name][0]
        content = matrix_path.read_text()

        # Verify framework sections
        assert "PCI-DSS" in content
        assert "OWASP" in content

        # Verify control IDs are shown
        assert "6.2.4" in content or "6.3.1" in content  # PCI-DSS controls
        assert "A05:2025" in content or "A07:2025" in content  # OWASP 2025 categories

        # Verify status indicators
        assert "Non-Compliant" in content or "At Risk" in content

    def test_json_report_structure(self, realistic_findings: list[Finding], tmp_path: Path) -> None:
        """Test JSON report structure and content."""
        config = ReportConfig(formats=[ReportFormat.JSON])

        result = generate_report(realistic_findings, tmp_path, config)

        assert result.success

        json_path = result.output_files[0]
        data = json.loads(json_path.read_text())

        # Verify top-level structure
        assert "metadata" in data
        assert "executive_summary" in data
        assert "remediation_timeline" in data
        assert "severity_counts" in data
        assert "compliance_summary" in data
        assert "findings" in data

        # Verify metadata
        assert data["metadata"]["findings_count"] == 8
        assert data["metadata"]["generator_version"]
        assert data["metadata"]["content_hash"]

        # Verify severity counts
        assert data["severity_counts"]["critical"] == 1
        assert data["severity_counts"]["high"] == 6
        assert data["severity_counts"]["medium"] == 1

        # Verify findings structure
        assert len(data["findings"]) == 8
        finding = data["findings"][0]
        assert "title" in finding
        assert "severity" in finding
        assert "scanner" in finding

    def test_multi_format_generation(
        self, realistic_findings: list[Finding], tmp_path: Path
    ) -> None:
        """Test generating multiple report formats at once."""
        config = ReportConfig(
            formats=[ReportFormat.HTML, ReportFormat.COMPLIANCE, ReportFormat.JSON]
        )

        result = generate_report(realistic_findings, tmp_path, config)

        assert result.success
        assert len(result.output_files) >= 3

        # Verify each format exists
        extensions = {p.suffix for p in result.output_files}
        assert ".html" in extensions
        assert ".json" in extensions

        # Verify compliance matrix HTML
        compliance_files = [p for p in result.output_files if "compliance" in p.name]
        assert len(compliance_files) == 1

    def test_severity_filtering(self, realistic_findings: list[Finding], tmp_path: Path) -> None:
        """Test severity filtering in reports."""
        config = ReportConfig(
            formats=[ReportFormat.JSON],
            min_severity="high",
        )

        result = generate_report(realistic_findings, tmp_path, config)

        assert result.success

        data = json.loads(result.output_files[0].read_text())

        # Should only include critical and high
        assert data["metadata"]["findings_count"] == 7  # 1 critical + 6 high
        for finding in data["findings"]:
            assert finding["severity"] in ["critical", "high"]

    def test_executive_summary_accuracy(
        self, realistic_findings: list[Finding], tmp_path: Path
    ) -> None:
        """Test executive summary calculations."""
        config = ReportConfig(formats=[ReportFormat.JSON])

        result = generate_report(realistic_findings, tmp_path, config)

        data = json.loads(result.output_files[0].read_text())
        summary = data["executive_summary"]

        assert summary["total_findings"] == 8
        assert summary["severity_counts"]["critical"] == 1
        assert summary["severity_counts"]["high"] == 6
        assert summary["severity_counts"]["medium"] == 1
        assert summary["risk_level"] in ["Critical", "High", "Medium", "Low", "None"]
        assert 0 <= summary["risk_percentage"] <= 100

    def test_remediation_timeline(self, realistic_findings: list[Finding], tmp_path: Path) -> None:
        """Test remediation timeline recommendations."""
        config = ReportConfig(formats=[ReportFormat.JSON])

        result = generate_report(realistic_findings, tmp_path, config)

        data = json.loads(result.output_files[0].read_text())
        timeline = data["remediation_timeline"]

        # Verify timeline structure
        assert timeline["immediate"]["count"] == 1  # Critical
        assert timeline["urgent"]["count"] == 6  # High
        assert timeline["standard"]["count"] == 1  # Medium

        # Verify descriptions
        assert "24 hours" in timeline["immediate"]["description"]
        assert "7 days" in timeline["urgent"]["description"]
        assert "30 days" in timeline["standard"]["description"]


@pytest.mark.integration
class TestReportFromScanResults:
    """Integration tests for generating reports from scan result files."""

    def test_report_from_semgrep_json(self, tmp_path: Path) -> None:
        """Test generating report from Semgrep JSON format."""
        # Create sample Semgrep output
        semgrep_results = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.dangerous-system-call",
                    "path": "app/main.py",
                    "start": {"line": 42, "col": 1},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Dangerous system call detected",
                        "metadata": {"cwe": ["CWE-78"]},
                    },
                },
                {
                    "check_id": "python.jwt.security.jwt-decode-without-verification",
                    "path": "app/auth.py",
                    "start": {"line": 15, "col": 1},
                    "extra": {
                        "severity": "ERROR",
                        "message": "JWT verification disabled",
                        "metadata": {"cwe": ["CWE-287"]},
                    },
                },
            ]
        }

        input_file = tmp_path / "semgrep-results.json"
        input_file.write_text(json.dumps(semgrep_results))

        # Parse findings using CLI helper (simulating CLI flow)
        from kekkai.cli import _parse_findings_from_json

        data = json.loads(input_file.read_text())
        findings = _parse_findings_from_json(data)

        assert len(findings) == 2
        assert findings[0].scanner == "semgrep"
        assert findings[0].cwe == "CWE-78"

        # Generate report
        result = generate_report(
            findings,
            tmp_path / "output",
            ReportConfig(formats=[ReportFormat.HTML]),
        )

        assert result.success

    def test_report_from_trivy_json(self, tmp_path: Path) -> None:
        """Test generating report from Trivy JSON format."""
        trivy_results = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-32681",
                            "PkgName": "requests",
                            "InstalledVersion": "2.28.0",
                            "FixedVersion": "2.31.0",
                            "Severity": "MEDIUM",
                            "Title": "Requests Session vulnerability",
                            "Description": "Auth credentials leak",
                        },
                    ],
                }
            ]
        }

        input_file = tmp_path / "trivy-results.json"
        input_file.write_text(json.dumps(trivy_results))

        from kekkai.cli import _parse_findings_from_json

        data = json.loads(input_file.read_text())
        findings = _parse_findings_from_json(data)

        assert len(findings) == 1
        assert findings[0].scanner == "trivy"
        assert findings[0].cve == "CVE-2023-32681"

        result = generate_report(
            findings,
            tmp_path / "output",
            ReportConfig(formats=[ReportFormat.JSON]),
        )

        assert result.success


@pytest.mark.integration
class TestReportEdgeCases:
    """Integration tests for edge cases."""

    def test_empty_findings_report(self, tmp_path: Path) -> None:
        """Test report generation with no findings."""
        result = generate_report(
            [],
            tmp_path,
            ReportConfig(formats=[ReportFormat.HTML, ReportFormat.JSON]),
        )

        assert result.success

        # JSON should show 0 findings
        json_file = [p for p in result.output_files if p.suffix == ".json"][0]
        data = json.loads(json_file.read_text())
        assert data["metadata"]["findings_count"] == 0
        assert data["executive_summary"]["risk_level"] == "None"

    def test_single_finding_report(self, tmp_path: Path) -> None:
        """Test report generation with single finding."""
        findings = [
            Finding(
                scanner="test",
                title="Single Finding",
                severity=Severity.HIGH,
                description="Test finding",
            )
        ]

        result = generate_report(
            findings,
            tmp_path,
            ReportConfig(formats=[ReportFormat.HTML]),
        )

        assert result.success
        content = result.output_files[0].read_text()
        assert "Single Finding" in content

    def test_special_characters_in_findings(self, tmp_path: Path) -> None:
        """Test handling of special characters in findings."""
        findings = [
            Finding(
                scanner="test",
                title="Finding with <special> & 'characters' \"quoted\"",
                severity=Severity.HIGH,
                description="Description with <script>alert('xss')</script>",
                file_path="/path/with spaces/file.py",
            )
        ]

        result = generate_report(
            findings,
            tmp_path,
            ReportConfig(formats=[ReportFormat.HTML]),
        )

        assert result.success
        content = result.output_files[0].read_text()

        # Verify escaping
        assert "<script>alert" not in content
        assert "&lt;script&gt;" in content or "alert" not in content
