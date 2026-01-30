"""Rich CLI output utilities for Kekkai.

Provides professional terminal rendering with TTY-awareness,
branded theming, and security-focused sanitization.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rich import box
from rich.console import Console, Group
from rich.padding import Padding
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "console",
    "print_dashboard",
    "print_scan_summary",
    "sanitize_for_terminal",
    "sanitize_error",
    "ScanSummaryRow",
    "VERSION",
    "splash",
]

ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

KEKKAI_THEME = Theme(
    {
        "info": "dim cyan",
        "warning": "yellow",
        "danger": "bold red",
        "success": "bold green",
        "header": "bold white",
        "muted": "dim white",
        "brand": "bold cyan",
        "command": "bold white",
        "desc": "dim white",
    }
)

console = Console(theme=KEKKAI_THEME)

BANNER_ASCII = r"""
   __        __   __        _
  / /_____  / /__/ /_____ _(_)
 /  '_/ _ \/  '_/  '_/ _ `/ /
/_/\_\\___/_/\_/_/\_\\_,_/_/
"""

VERSION = "1.1.0"


def print_dashboard() -> None:
    """Render the professional Kekkai dashboard."""
    if not console.is_terminal:
        print(f"Kekkai v{VERSION} - Local-First AppSec Orchestrator")
        return

    header_table = Table.grid(padding=(0, 2), expand=False)

    logo = Text(BANNER_ASCII.strip("\n"), style="brand")

    meta = Text()
    meta.append(f"\nv{VERSION}", style="muted")
    meta.append("\nLocal-First AppSec Orchestrator", style="bold white")
    meta.append("\nhttps://github.com/kademoslabs/kekkai", style="blue link")

    header_table.add_row(logo, meta)

    menu_table = Table(
        box=None,
        padding=(0, 2),
        show_header=True,
        header_style="dim cyan",
        expand=True,
    )
    menu_table.add_column("Command", style="command", ratio=1)
    menu_table.add_column("Description", style="desc", ratio=3)

    menu_table.add_row("kekkai scan", "Run security scan in current directory")
    menu_table.add_row("kekkai threatflow", "Generate AI-powered threat model")
    menu_table.add_row("kekkai dojo", "Manage local DefectDojo instance")
    menu_table.add_row("kekkai triage", "Interactive finding review (TUI)")
    menu_table.add_row("kekkai report", "Generate compliance reports")
    menu_table.add_row("kekkai config", "Manage settings and keys")

    tips_grid = Table.grid(padding=(0, 1))
    tips_grid.add_row("⚡", "[dim]Run scans locally before pushing to CI to save time.[/dim]")
    tips_grid.add_row("🔒", "[dim]ThreatFlow requires an API key for remote models.[/dim]")
    tips_grid.add_row("🤝", "[dim]Star us on GitHub to support open source development.[/dim]")

    dashboard = Group(
        Padding(header_table, (1, 1, 1, 1)),
        Rule(style="dim cyan"),
        Padding(menu_table, (1, 2)),
        Rule(style="dim cyan"),
        Padding(tips_grid, (1, 2, 1, 2)),
        Text("\n"),
    )

    console.print(dashboard)


def splash(*, force_plain: bool = False) -> str:
    """Deprecated: Use print_dashboard() instead."""
    return f"Kekkai v{VERSION} - Local-First AppSec Orchestrator"


def print_quick_start() -> str:
    """Deprecated: Content moved to print_dashboard()."""
    return ""


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
) -> None:
    """Render scan results as a formatted table.

    Prints directly to console/stdout to ensure proper ANSI rendering.
    """
    if force_plain or not console.is_terminal:
        print("Scan Summary:")
        for row in rows:
            status = "OK" if row.success else "FAIL"
            scanner_name = sanitize_for_terminal(row.scanner)
            print(f"  {scanner_name}: {status}, {row.findings_count} findings, {row.duration_ms}ms")
        return

    table = Table(title="Scan Summary", show_header=True, header_style="bold", box=box.SIMPLE)
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

    console.print(table)


def sanitize_for_terminal(text: str) -> str:
    """Strip ANSI escape sequences from untrusted content."""
    return ANSI_ESCAPE_PATTERN.sub("", text)


def sanitize_error(error: str | Exception, *, max_length: int = 200) -> str:
    """Sanitize error messages for user display."""
    message = str(error) if isinstance(error, Exception) else error
    message = ANSI_ESCAPE_PATTERN.sub("", message)
    message = re.sub(r"/[^\s:]+", "[path]", message)
    message = re.sub(r"\\[^\s:]+", "[path]", message)
    message = re.sub(r"line \d+", "line [N]", message, flags=re.IGNORECASE)

    if len(message) > max_length:
        message = message[:max_length] + "..."

    return message
