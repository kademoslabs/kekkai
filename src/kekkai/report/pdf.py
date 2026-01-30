"""PDF report generator.

Uses weasyprint for HTML-to-PDF conversion if available.
Falls back to HTML-only with warning if weasyprint is not installed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .html import HTMLReportGenerator

# Check weasyprint availability
_WEASYPRINT_AVAILABLE = False
try:
    from weasyprint import HTML as WeasyprintHTML  # type: ignore[import-not-found]

    _WEASYPRINT_AVAILABLE = True
except ImportError:
    WeasyprintHTML = None


class PDFReportGenerator:
    """Generates PDF security reports.

    Requires weasyprint to be installed. If not available,
    falls back to HTML generation with a warning.
    """

    def __init__(self) -> None:
        self.html_generator = HTMLReportGenerator()

    @property
    def is_available(self) -> bool:
        """Check if PDF generation is available."""
        return _WEASYPRINT_AVAILABLE

    def generate(self, report_data: dict[str, Any], output_dir: Path) -> Path:
        """Generate PDF report file.

        If weasyprint is not available, generates HTML instead.
        """
        # First generate HTML
        html_path = self.html_generator.generate(report_data, output_dir)

        if not _WEASYPRINT_AVAILABLE:
            # Return HTML path with warning - caller should handle
            return html_path

        # Convert HTML to PDF
        pdf_path = output_dir / "report.pdf"

        html_content = html_path.read_text(encoding="utf-8")
        html_doc = WeasyprintHTML(string=html_content, base_url=str(output_dir))
        html_doc.write_pdf(pdf_path)

        return pdf_path


def is_pdf_available() -> bool:
    """Check if PDF generation is available."""
    return _WEASYPRINT_AVAILABLE
