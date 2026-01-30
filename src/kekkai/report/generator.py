"""Report generation orchestration.

Handles report generation workflow including compliance mapping,
format selection, and output management.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

    from kekkai.compliance.mappings import ComplianceMappingResult
    from kekkai.scanners.base import Finding


class ReportFormat(str, Enum):
    """Available report formats."""

    HTML = "html"
    PDF = "pdf"
    COMPLIANCE = "compliance"
    JSON = "json"


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    formats: list[ReportFormat] = field(default_factory=lambda: [ReportFormat.HTML])
    frameworks: list[str] = field(default_factory=lambda: ["PCI-DSS", "SOC2", "OWASP", "HIPAA"])
    min_severity: str = "info"
    include_executive_summary: bool = True
    include_remediation_timeline: bool = True
    title: str = "Security Scan Report"
    organization: str = ""
    project_name: str = ""


@dataclass
class ReportResult:
    """Result of report generation."""

    success: bool
    output_files: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    generation_time_ms: int = 0


@dataclass
class ReportMetadata:
    """Metadata included in generated reports."""

    generated_at: str
    generator_version: str
    findings_count: int
    frameworks_mapped: list[str]
    content_hash: str


def generate_report(
    findings: Sequence[Finding],
    output_dir: Path,
    config: ReportConfig | None = None,
) -> ReportResult:
    """Generate reports in specified formats.

    Args:
        findings: Security findings to include
        output_dir: Directory for output files
        config: Report configuration

    Returns:
        ReportResult with output files and status
    """
    generator = ReportGenerator(config or ReportConfig())
    return generator.generate(findings, output_dir)


class ReportGenerator:
    """Orchestrates report generation across formats."""

    def __init__(self, config: ReportConfig) -> None:
        self.config = config

    def generate(
        self,
        findings: Sequence[Finding],
        output_dir: Path,
    ) -> ReportResult:
        """Generate reports for all configured formats."""
        import time

        start_time = time.monotonic()
        result = ReportResult(success=True)

        # Ensure output directory exists
        output_dir = output_dir.expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        # Filter findings by severity
        filtered = self._filter_by_severity(list(findings))

        # Map to compliance frameworks
        from kekkai.compliance import map_findings_to_all_frameworks

        compliance_result = map_findings_to_all_frameworks(filtered)

        # Build report data
        report_data = self._build_report_data(filtered, compliance_result)

        # Generate each format
        for fmt in self.config.formats:
            try:
                output_path = self._generate_format(fmt, report_data, output_dir)
                if output_path:
                    result.output_files.append(output_path)
            except Exception as e:
                result.errors.append(f"Failed to generate {fmt.value}: {e}")
                result.success = False

        result.generation_time_ms = int((time.monotonic() - start_time) * 1000)
        return result

    def _filter_by_severity(self, findings: list[Finding]) -> list[Finding]:
        """Filter findings by minimum severity."""
        from kekkai.scanners.base import Severity

        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
            Severity.UNKNOWN,
        ]
        min_sev = Severity.from_string(self.config.min_severity)
        try:
            min_index = severity_order.index(min_sev)
        except ValueError:
            min_index = len(severity_order) - 1

        return [f for f in findings if severity_order.index(f.severity) <= min_index]

    def _build_report_data(
        self,
        findings: list[Finding],
        compliance_result: ComplianceMappingResult,
    ) -> dict[str, Any]:
        """Build unified report data structure."""
        from kekkai.output import VERSION

        # Calculate content hash for integrity
        content = json.dumps(
            [f.dedupe_hash() for f in findings],
            sort_keys=True,
        )
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

        metadata = ReportMetadata(
            generated_at=datetime.now(UTC).isoformat(),
            generator_version=VERSION,
            findings_count=len(findings),
            frameworks_mapped=list(compliance_result.framework_summary.keys()),
            content_hash=content_hash,
        )

        # Severity counts
        severity_counts = self._count_by_severity(findings)

        # Executive summary
        executive_summary = self._build_executive_summary(findings, compliance_result)

        # Remediation timeline
        remediation_timeline = self._build_remediation_timeline(findings)

        return {
            "metadata": metadata,
            "config": self.config,
            "findings": findings,
            "compliance": compliance_result,
            "severity_counts": severity_counts,
            "executive_summary": executive_summary,
            "remediation_timeline": remediation_timeline,
        }

    def _count_by_severity(self, findings: list[Finding]) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for f in findings:
            key = f.severity.value
            if key in counts:
                counts[key] += 1
        return counts

    def _build_executive_summary(
        self,
        findings: list[Finding],
        compliance_result: ComplianceMappingResult,
    ) -> dict[str, Any]:
        """Build executive summary section."""
        severity_counts = self._count_by_severity(findings)

        # Risk score (simple weighted calculation)
        risk_score = (
            severity_counts["critical"] * 10
            + severity_counts["high"] * 5
            + severity_counts["medium"] * 2
            + severity_counts["low"] * 1
        )
        max_possible = len(findings) * 10 if findings else 1
        risk_percentage = min(100, int((risk_score / max_possible) * 100))

        # Risk level
        if risk_percentage >= 70:
            risk_level = "Critical"
        elif risk_percentage >= 50:
            risk_level = "High"
        elif risk_percentage >= 30:
            risk_level = "Medium"
        elif risk_percentage > 0:
            risk_level = "Low"
        else:
            risk_level = "None"

        return {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "risk_score": risk_score,
            "risk_percentage": risk_percentage,
            "risk_level": risk_level,
            "frameworks_impacted": compliance_result.framework_summary,
            "top_issues": self._get_top_issues(findings),
        }

    def _get_top_issues(self, findings: list[Finding], limit: int = 5) -> list[dict[str, Any]]:
        """Get top issues by severity."""
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                ["critical", "high", "medium", "low", "info", "unknown"].index(f.severity.value),
                f.title,
            ),
        )
        return [
            {
                "title": f.title,
                "severity": f.severity.value,
                "file": f.file_path,
                "rule_id": f.rule_id,
            }
            for f in sorted_findings[:limit]
        ]

    def _build_remediation_timeline(self, findings: list[Finding]) -> dict[str, Any]:
        """Build remediation timeline recommendations."""
        severity_counts = self._count_by_severity(findings)

        # SLA recommendations based on industry standards
        return {
            "immediate": {
                "description": "Address within 24 hours",
                "count": severity_counts["critical"],
                "severity": "critical",
            },
            "urgent": {
                "description": "Address within 7 days",
                "count": severity_counts["high"],
                "severity": "high",
            },
            "standard": {
                "description": "Address within 30 days",
                "count": severity_counts["medium"],
                "severity": "medium",
            },
            "planned": {
                "description": "Address within 90 days",
                "count": severity_counts["low"],
                "severity": "low",
            },
            "informational": {
                "description": "Review and document",
                "count": severity_counts["info"],
                "severity": "info",
            },
        }

    def _generate_format(
        self,
        fmt: ReportFormat,
        report_data: dict[str, Any],
        output_dir: Path,
    ) -> Path | None:
        """Generate a specific report format."""
        if fmt == ReportFormat.HTML:
            from .html import HTMLReportGenerator

            html_gen = HTMLReportGenerator()
            return html_gen.generate(report_data, output_dir)

        if fmt == ReportFormat.PDF:
            from .pdf import PDFReportGenerator

            pdf_gen = PDFReportGenerator()
            return pdf_gen.generate(report_data, output_dir)

        if fmt == ReportFormat.COMPLIANCE:
            from .compliance_matrix import generate_compliance_matrix

            return generate_compliance_matrix(report_data, output_dir)

        if fmt == ReportFormat.JSON:
            return self._generate_json(report_data, output_dir)

        return None

    def _generate_json(self, report_data: dict[str, Any], output_dir: Path) -> Path:
        """Generate JSON report."""
        output_path = output_dir / "report.json"

        # Convert dataclasses to dicts for JSON serialization
        json_data = {
            "metadata": {
                "generated_at": report_data["metadata"].generated_at,
                "generator_version": report_data["metadata"].generator_version,
                "findings_count": report_data["metadata"].findings_count,
                "frameworks_mapped": report_data["metadata"].frameworks_mapped,
                "content_hash": report_data["metadata"].content_hash,
            },
            "executive_summary": report_data["executive_summary"],
            "remediation_timeline": report_data["remediation_timeline"],
            "severity_counts": report_data["severity_counts"],
            "compliance_summary": report_data["compliance"].framework_summary,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "scanner": f.scanner,
                    "file_path": f.file_path,
                    "line": f.line,
                    "rule_id": f.rule_id,
                    "cwe": f.cwe,
                    "cve": f.cve,
                    "description": f.description,
                }
                for f in report_data["findings"]
            ],
        }

        output_path.write_text(json.dumps(json_data, indent=2))
        return output_path
