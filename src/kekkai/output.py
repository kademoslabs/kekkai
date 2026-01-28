"""Rich CLI output utilities for Kekkai.

Provides professional terminal rendering with TTY-awareness,
branded theming, and security-focused sanitization.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rich import box
from rich.align import Align
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
    "print_splash",
    "print_scan_summary",
    "sanitize_for_terminal",
    "sanitize_error",
    "ScanSummaryRow",
]

ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

KEKKAI_THEME = Theme(
    {
        "info": "dim cyan",
        "warning": "magenta",
        "danger": "bold red",
        "success": "bold green",
        "header": "bold white",
        "title": "bold cyan",
        "text": "white",
        "muted": "dim white",
        "brand": "bold cyan",
    }
)

console = Console(theme=KEKKAI_THEME)

BANNER_ASCII = r"""
    ██ ▄█▀▓█████  ██ ▄█▀ ██ ▄█▀▄▄▄       ██▓
    ██▄█▒ ▓█   ▀  ██▄█▒  ██▄█▒▒████▄     ▓██▒
   ▓███▄░ ▒███   ▓███▄░ ▓███▄░▒██  ▀█▄   ▒██▒
   ▓██ █▄ ▒▓█  ▄ ▓██ █▄ ▓██ █▄░██▄▄▄▄██ ░██░
   ▒██▒ █▄░▒████▒▒██▒ █▄▒██▒ █▄▓█   ▓██▒░██░
   ▒ ▒▒ ▓▒░░ ▒░ ░▒ ▒▒ ▓▒▒ ▒▒ ▓▒▒▒   ▓▒█░░▓
   ░ ░▒ ▒░ ░ ░  ░░ ░▒ ▒░░ ░▒ ▒░ ▒   ▒▒ ░ ▒ ░
   ░ ░░ ░    ░    ░ ░░ ░ ░ ░░ ░   ░   ▒
"""

VERSION = "1.0.1"


def print_splash() -> None:
    """Print the Kekkai splash screen with menu and tips."""
    header_text = Text(BANNER_ASCII, style="header")
    subtitle = Text("Local-first AppSec Orchestrator", style="info")
    subtitle.justify = "center"

    header_panel = Panel(
        Align.center(Text.assemble(header_text, "\n", subtitle)),
        box=box.HEAVY,
        style="info",
        padding=(1, 2),
    )

    menu_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2), expand=True)
    menu_table.add_column("Command", style="title", ratio=1)
    menu_table.add_column("Description", style="text", ratio=3)

    menu_table.add_row("kekkai scan", "Run a comprehensive security scan in the current directory.")
    menu_table.add_row("kekkai dojo", "Interact with your DefectDojo instance (import/export).")
    menu_table.add_row("kekkai report", "Generate compliance and audit reports.")
    menu_table.add_row("kekkai config", "Configure local settings and API keys.")

    menu_panel = Panel(
        menu_table,
        title="[header]COMMAND MENU[/]",
        border_style="dim cyan",
        padding=(1, 2),
    )

    tips_content = Text()
    tips_content.append("Best Practices:\n", style="warning")
    tips_content.append(" - Run scans locally before pushing to CI to save time.\n", style="text")
    tips_content.append(" - Use .kekkaiignore to filter out known false positives.\n", style="text")
    tips_content.append(
        " - Keep your CLI updated to catch the latest CVE signatures.\n\n", style="text"
    )

    tips_content.append("Open Source:\n", style="success")
    tips_content.append(
        " We are looking for collaborators! Star us on GitHub or submit a PR.\n\n", style="text"
    )

    tips_content.append("Enterprise Features:\n", style="danger")
    tips_content.append(
        " ThreatFlow visualization and RBAC require an active Enterprise license.", style="text"
    )

    tips_panel = Panel(
        tips_content,
        title="[header]QUICK TIPS & INFO[/]",
        border_style="dim cyan",
        padding=(1, 2),
    )

    console.print(header_panel)
    console.print(menu_panel)
    console.print(tips_panel)
    console.print()


def splash(*, force_plain: bool = False) -> str:
    """Render the Kekkai splash banner.

    Args:
        force_plain: If True, return plain text regardless of TTY.

    Returns:
        Banner string for display.
    """
    if force_plain or not console.is_terminal:
        return f"Kekkai v{VERSION} - Local-First AppSec Orchestrator"

    with console.capture() as capture:
        print_splash()
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
