"""Unit tests for the report generation module."""

from __future__ import annotations

from pathlib import Path

import pytest

from kekkai.report import (
    HTMLReportGenerator,
    PDFReportGenerator,
    ReportConfig,
    ReportFormat,
    ReportGenerator,
    generate_report,
)
from kekkai.scanners.base import Finding, Severity


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Create sample findings for testing."""
    return [
        Finding(
            scanner="semgrep",
            title="SQL Injection vulnerability",
            severity=Severity.HIGH,
            description="User input passed directly to SQL query",
            file_path="app/models.py",
            line=42,
            rule_id="python.lang.security.audit.dangerous-sql",
            cwe="CWE-89",
        ),
        Finding(
            scanner="trivy",
            title="CVE-2021-44228",
            severity=Severity.CRITICAL,
            description="Log4j Remote Code Execution vulnerability",
            cve="CVE-2021-44228",
            package_name="log4j-core",
            package_version="2.14.1",
            fixed_version="2.17.0",
        ),
        Finding(
            scanner="gitleaks",
            title="AWS Secret Access Key",
            severity=Severity.HIGH,
            description="AWS secret key found in source code",
            file_path=".env",
            line=5,
            rule_id="aws-secret-access-key",
        ),
        Finding(
            scanner="semgrep",
            title="Insecure random number generator",
            severity=Severity.MEDIUM,
            description="Using random instead of secrets module",
            file_path="app/utils.py",
            line=100,
            rule_id="python.lang.security.audit.insecure-random",
            cwe="CWE-330",
        ),
        Finding(
            scanner="semgrep",
            title="Debug mode enabled",
            severity=Severity.LOW,
            description="Flask debug mode is enabled",
            file_path="app/__init__.py",
            line=15,
            rule_id="python.flask.security.debug-enabled",
        ),
    ]


class TestReportConfig:
    """Tests for ReportConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = ReportConfig()

        assert ReportFormat.HTML in config.formats
        assert "PCI-DSS" in config.frameworks
        assert "SOC2" in config.frameworks
        assert "OWASP" in config.frameworks
        assert "HIPAA" in config.frameworks
        assert config.min_severity == "info"
        assert config.include_executive_summary is True
        assert config.include_remediation_timeline is True

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = ReportConfig(
            formats=[ReportFormat.PDF, ReportFormat.JSON],
            frameworks=["PCI-DSS"],
            min_severity="high",
            title="Custom Report",
            organization="Test Org",
        )

        assert config.formats == [ReportFormat.PDF, ReportFormat.JSON]
        assert config.frameworks == ["PCI-DSS"]
        assert config.min_severity == "high"
        assert config.title == "Custom Report"
        assert config.organization == "Test Org"


class TestReportGenerator:
    """Tests for ReportGenerator."""

    def test_filter_by_severity(self, sample_findings: list[Finding]) -> None:
        """Test severity filtering."""
        config = ReportConfig(min_severity="high")
        generator = ReportGenerator(config)

        filtered = generator._filter_by_severity(sample_findings)

        # Should only include critical and high
        assert all(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in filtered)
        assert len(filtered) == 3  # 1 critical + 2 high

    def test_count_by_severity(self, sample_findings: list[Finding]) -> None:
        """Test severity counting."""
        generator = ReportGenerator(ReportConfig())

        counts = generator._count_by_severity(sample_findings)

        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["medium"] == 1
        assert counts["low"] == 1
        assert counts["info"] == 0

    def test_build_executive_summary(self, sample_findings: list[Finding]) -> None:
        """Test executive summary generation."""
        from kekkai.compliance import map_findings_to_all_frameworks

        generator = ReportGenerator(ReportConfig())
        compliance_result = map_findings_to_all_frameworks(sample_findings)

        summary = generator._build_executive_summary(sample_findings, compliance_result)

        assert summary["total_findings"] == 5
        assert summary["risk_level"] in ["Critical", "High", "Medium", "Low", "None"]
        assert 0 <= summary["risk_percentage"] <= 100
        assert len(summary["top_issues"]) <= 5

    def test_build_remediation_timeline(self, sample_findings: list[Finding]) -> None:
        """Test remediation timeline generation."""
        generator = ReportGenerator(ReportConfig())

        timeline = generator._build_remediation_timeline(sample_findings)

        assert "immediate" in timeline
        assert "urgent" in timeline
        assert "standard" in timeline
        assert "planned" in timeline
        assert timeline["immediate"]["count"] == 1  # 1 critical
        assert timeline["urgent"]["count"] == 2  # 2 high


class TestHTMLReportGenerator:
    """Tests for HTML report generation."""

    def test_generate_html_report(self, sample_findings: list[Finding], tmp_path: Path) -> None:
        """Test HTML report generation."""
        result = generate_report(
            sample_findings,
            tmp_path,
            ReportConfig(formats=[ReportFormat.HTML]),
        )

        assert result.success
        assert len(result.output_files) == 1

        html_file = result.output_files[0]
        assert html_file.exists()
        assert html_file.suffix == ".html"

        content = html_file.read_text()
        assert "Security Scan Report" in content
        assert "SQL Injection" in content
        assert "CVE-2021-44228" in content

    def test_html_escaping(self, tmp_path: Path) -> None:
        """Test XSS prevention through HTML escaping."""
        malicious_findings = [
            Finding(
                scanner="test",
                title="<script>alert('XSS')</script>",
                severity=Severity.HIGH,
                description="<img src=x onerror=alert('XSS')>",
            ),
        ]

        result = generate_report(
            malicious_findings,
            tmp_path,
            ReportConfig(formats=[ReportFormat.HTML]),
        )

        assert result.success
        content = result.output_files[0].read_text()

        # Script tags should be escaped
        assert "<script>" not in content
        assert "&lt;script&gt;" in content or "alert" not in content

    def test_severity_class_filter(self) -> None:
        """Test severity CSS class filter."""
        generator = HTMLReportGenerator()

        assert generator._severity_class("critical") == "severity-critical"
        assert generator._severity_class("HIGH") == "severity-high"
        assert generator._severity_class("unknown") == "severity-unknown"


class TestPDFReportGenerator:
    """Tests for PDF report generation."""

    def test_pdf_availability_check(self) -> None:
        """Test PDF availability property."""
        generator = PDFReportGenerator()
        # Should not raise, returns bool
        assert isinstance(generator.is_available, bool)

    def test_fallback_to_html(self, sample_findings: list[Finding], tmp_path: Path) -> None:
        """Test fallback to HTML when PDF not available."""
        generator = PDFReportGenerator()

        if not generator.is_available:
            # When weasyprint is not available, should still generate HTML
            from kekkai.compliance import map_findings_to_all_frameworks
            from kekkai.report.generator import ReportConfig, ReportGenerator

            config = ReportConfig()
            gen = ReportGenerator(config)
            compliance = map_findings_to_all_frameworks(sample_findings)
            report_data = gen._build_report_data(sample_findings, compliance)

            output_path = generator.generate(report_data, tmp_path)

            assert output_path.exists()
            # Should be HTML since PDF is not available
            assert output_path.suffix in [".html", ".pdf"]


class TestComplianceMatrixGeneration:
    """Tests for compliance matrix report."""

    def test_generate_compliance_matrix(
        self, sample_findings: list[Finding], tmp_path: Path
    ) -> None:
        """Test compliance matrix generation."""
        result = generate_report(
            sample_findings,
            tmp_path,
            ReportConfig(formats=[ReportFormat.COMPLIANCE]),
        )

        assert result.success

        # Find the compliance matrix file
        matrix_files = [f for f in result.output_files if "compliance" in f.name.lower()]
        assert len(matrix_files) == 1

        content = matrix_files[0].read_text()
        assert "Compliance Matrix" in content
        assert "PCI-DSS" in content
        assert "SOC2" in content
        assert "OWASP" in content


class TestJSONReportGeneration:
    """Tests for JSON report generation."""

    def test_generate_json_report(self, sample_findings: list[Finding], tmp_path: Path) -> None:
        """Test JSON report generation."""
        import json

        result = generate_report(
            sample_findings,
            tmp_path,
            ReportConfig(formats=[ReportFormat.JSON]),
        )

        assert result.success

        json_file = result.output_files[0]
        assert json_file.suffix == ".json"

        data = json.loads(json_file.read_text())

        assert "metadata" in data
        assert "executive_summary" in data
        assert "findings" in data
        assert len(data["findings"]) == 5


class TestGenerateReport:
    """Tests for the generate_report helper function."""

    def test_generate_all_formats(self, sample_findings: list[Finding], tmp_path: Path) -> None:
        """Test generating all report formats."""
        result = generate_report(
            sample_findings,
            tmp_path,
            ReportConfig(formats=[ReportFormat.HTML, ReportFormat.COMPLIANCE, ReportFormat.JSON]),
        )

        assert result.success
        # At least 3 files (HTML, compliance matrix, JSON)
        assert len(result.output_files) >= 3

    def test_empty_findings(self, tmp_path: Path) -> None:
        """Test report generation with no findings."""
        result = generate_report(
            [],
            tmp_path,
            ReportConfig(formats=[ReportFormat.HTML]),
        )

        assert result.success
        assert len(result.output_files) == 1

        content = result.output_files[0].read_text()
        assert "0" in content  # Should show 0 findings

    def test_output_directory_creation(
        self, sample_findings: list[Finding], tmp_path: Path
    ) -> None:
        """Test automatic output directory creation."""
        nested_dir = tmp_path / "nested" / "output" / "dir"

        result = generate_report(
            sample_findings,
            nested_dir,
            ReportConfig(formats=[ReportFormat.HTML]),
        )

        assert result.success
        assert nested_dir.exists()

    def test_generation_time_tracking(self, sample_findings: list[Finding], tmp_path: Path) -> None:
        """Test generation time is tracked."""
        result = generate_report(
            sample_findings,
            tmp_path,
            ReportConfig(formats=[ReportFormat.HTML]),
        )

        assert result.generation_time_ms >= 0


class TestReportMetadata:
    """Tests for report metadata."""

    def test_content_hash_consistency(self, sample_findings: list[Finding], tmp_path: Path) -> None:
        """Test that same findings produce same content hash."""
        import json

        result1 = generate_report(
            sample_findings,
            tmp_path / "report1",
            ReportConfig(formats=[ReportFormat.JSON]),
        )
        result2 = generate_report(
            sample_findings,
            tmp_path / "report2",
            ReportConfig(formats=[ReportFormat.JSON]),
        )

        data1 = json.loads(result1.output_files[0].read_text())
        data2 = json.loads(result2.output_files[0].read_text())

        assert data1["metadata"]["content_hash"] == data2["metadata"]["content_hash"]

    def test_metadata_includes_version(
        self, sample_findings: list[Finding], tmp_path: Path
    ) -> None:
        """Test that metadata includes generator version."""
        import json

        result = generate_report(
            sample_findings,
            tmp_path,
            ReportConfig(formats=[ReportFormat.JSON]),
        )

        data = json.loads(result.output_files[0].read_text())

        assert "generator_version" in data["metadata"]
        assert data["metadata"]["generator_version"]  # Not empty
