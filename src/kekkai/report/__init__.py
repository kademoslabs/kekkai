"""Security report generation module.

Generates HTML, PDF, and compliance matrix reports from scan findings.

Security considerations:
- HTML output uses Jinja2 autoescaping (XSS prevention)
- Output paths validated to prevent directory traversal
- Reports include generation timestamp for audit trail

ASVS Requirements:
- V5.3.1: Output encoding relevant for HTML
- V5.3.3: Context-aware output escaping
- V8.1.1: Reports in user-specified paths only
"""

from __future__ import annotations

from .compliance_matrix import generate_compliance_matrix
from .generator import (
    ReportConfig,
    ReportFormat,
    ReportGenerator,
    ReportResult,
    generate_report,
)
from .html import HTMLReportGenerator
from .pdf import PDFReportGenerator

__all__ = [
    # Core generator
    "ReportGenerator",
    "ReportConfig",
    "ReportFormat",
    "ReportResult",
    "generate_report",
    # Format-specific generators
    "HTMLReportGenerator",
    "PDFReportGenerator",
    # Compliance matrix
    "generate_compliance_matrix",
]
