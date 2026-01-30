"""HTML report generator.

Uses Jinja2 for templating with autoescaping enabled for XSS prevention.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape


class HTMLReportGenerator:
    """Generates HTML security reports."""

    def __init__(self) -> None:
        self.env = Environment(
            loader=PackageLoader("kekkai.report", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        # Add custom filters
        self.env.filters["severity_class"] = self._severity_class
        self.env.filters["severity_badge"] = self._severity_badge

    def generate(self, report_data: dict[str, Any], output_dir: Path) -> Path:
        """Generate HTML report file."""
        template = self.env.get_template("report.html")

        html_content = template.render(
            metadata=report_data["metadata"],
            config=report_data["config"],
            findings=report_data["findings"],
            compliance=report_data["compliance"],
            severity_counts=report_data["severity_counts"],
            executive_summary=report_data["executive_summary"],
            remediation_timeline=report_data["remediation_timeline"],
        )

        output_path = output_dir / "report.html"
        output_path.write_text(html_content, encoding="utf-8")
        return output_path

    @staticmethod
    def _severity_class(severity: str) -> str:
        """Return CSS class for severity level."""
        classes = {
            "critical": "severity-critical",
            "high": "severity-high",
            "medium": "severity-medium",
            "low": "severity-low",
            "info": "severity-info",
        }
        return classes.get(severity.lower(), "severity-unknown")

    @staticmethod
    def _severity_badge(severity: str) -> str:
        """Return badge HTML for severity level."""
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d",
        }
        color = colors.get(severity.lower(), "#6c757d")
        return f'<span class="badge" style="background-color: {color};">{severity.upper()}</span>'
