"""Rich CLI output utilities for Kekkai.

Provides professional terminal rendering with TTY-awareness,
branded theming, and security-focused sanitization.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "console",
    "splash",
    "print_scan_summary",
    "sanitize_for_terminal",
    "sanitize_error",
    "ScanSummaryRow",
]

ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

KEKKAI_THEME = Theme(
    {
        "info": "dim cyan",
        "warning": "yellow",
        "danger": "bold red",
        "success": "bold green",
        "header": "bold white on blue",
        "muted": "dim white",
        "brand": "bold cyan",
    }
)

console = Console(theme=KEKKAI_THEME)

BANNER_ASCII = r"""
 _  __     _    _         _
| |/ /___ | | _| | ____ _(_)
| ' // _ \| |/ / |/ / _` | |
| . \  __/|   <|   < (_| | |
|_|\_\___|_|\_\_|\_\__,_|_|
"""

VERSION = "1.0.0"


def splash(*, force_plain: bool = False) -> str:
    """Render the Kekkai splash banner.

    Args:
        force_plain: If True, return plain text regardless of TTY.

    Returns:
        Banner string for display.
    """
    if force_plain or not console.is_terminal:
        return f"Kekkai v{VERSION} - Local-First AppSec Orchestrator"

    banner_text = Text(BANNER_ASCII.strip(), style="brand")
    panel = Panel(
        banner_text,
        subtitle=f"[muted]v{VERSION} — Local-First AppSec Orchestrator[/muted]",
        border_style="blue",
        padding=(0, 2),
    )
    with console.capture() as capture:
        console.print(panel)
    result: str = capture.get()
    return result


def splash_minimal() -> str:
    """Return minimal splash for non-TTY environments."""
    return f"Kekkai v{VERSION} - Local-First AppSec Orchestrator"


@dataclass
class ScanSummaryRow:
    """A row in the scan summary table."""

    scanner: str
    success: bool
    findings_count: int
    duration_ms: int


def print_scan_summary(
    rows: Sequence[ScanSummaryRow],
    *,
    force_plain: bool = False,
) -> str:
    """Render scan results as a formatted table.

    Args:
        rows: Scan result rows to display.
        force_plain: If True, return plain text regardless of TTY.

    Returns:
        Formatted table string.
    """
    if force_plain or not console.is_terminal:
        lines = ["Scan Summary:"]
        for row in rows:
            status = "OK" if row.success else "FAIL"
            scanner_name = sanitize_for_terminal(row.scanner)
            lines.append(
                f"  {scanner_name}: {status}, {row.findings_count} findings, {row.duration_ms}ms"
            )
        return "\n".join(lines)

    table = Table(title="Scan Summary", show_header=True, header_style="bold")
    table.add_column("Scanner", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Findings", justify="right")
    table.add_column("Duration", justify="right", style="muted")

    for row in rows:
        status = "[green]✓[/green]" if row.success else "[red]✗[/red]"
        table.add_row(
            sanitize_for_terminal(row.scanner),
            status,
            str(row.findings_count),
            f"{row.duration_ms}ms",
        )

    with console.capture() as capture:
        console.print(table)
    result: str = capture.get()
    return result


def sanitize_for_terminal(text: str) -> str:
    """Strip ANSI escape sequences from untrusted content.

    Prevents terminal escape injection attacks where malicious content
    could manipulate terminal display or hide warnings.

    Args:
        text: Potentially untrusted text to sanitize.

    Returns:
        Text with all ANSI escape sequences removed.
    """
    return ANSI_ESCAPE_PATTERN.sub("", text)


def sanitize_error(error: str | Exception, *, max_length: int = 200) -> str:
    """Sanitize error messages for user display.

    Removes sensitive information like full paths and stack traces
    to prevent information disclosure.

    Args:
        error: Error message or exception to sanitize.
        max_length: Maximum length of returned message.

    Returns:
        Sanitized, truncated error message.
    """
    message = str(error) if isinstance(error, Exception) else error
    message = ANSI_ESCAPE_PATTERN.sub("", message)
    message = re.sub(r"/[^\s:]+", "[path]", message)
    message = re.sub(r"\\[^\s:]+", "[path]", message)
    message = re.sub(r"line \d+", "line [N]", message, flags=re.IGNORECASE)

    if len(message) > max_length:
        message = message[:max_length] + "..."

    return message


def print_quick_start() -> str:
    """Render Quick Start guide panel.

    Returns:
        Formatted Quick Start panel string.
    """
    if not console.is_terminal:
        return (
            "Quick Start:\n"
            "  1. kekkai scan --repo .     # Scan current directory\n"
            "  2. kekkai threatflow        # Generate threat model\n"
            "  3. kekkai dojo up           # Start DefectDojo\n"
        )

    content = Text()
    content.append("1. ", style="bold cyan")
    content.append("kekkai scan --repo .", style="green")
    content.append("     # Scan current directory\n")
    content.append("2. ", style="bold cyan")
    content.append("kekkai threatflow", style="green")
    content.append("        # Generate threat model\n")
    content.append("3. ", style="bold cyan")
    content.append("kekkai dojo up", style="green")
    content.append("           # Start DefectDojo")

    panel = Panel(
        content,
        title="[bold]Quick Start[/bold]",
        border_style="green",
        padding=(1, 2),
    )

    with console.capture() as capture:
        console.print(panel)
    result: str = capture.get()
    return result
