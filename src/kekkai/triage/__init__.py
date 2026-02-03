"""Triage TUI for interactive security finding review.

Provides a terminal-based interface for reviewing findings,
marking false positives, and generating .kekkaiignore files.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

# Import models and utilities (no heavy dependencies)
from .audit import AuditEntry, TriageAuditLog, log_decisions
from .ignore import IgnoreEntry, IgnoreFile, IgnorePatternValidator, ValidationError
from .loader import load_findings_from_path
from .models import (
    FindingEntry,
    Severity,
    TriageDecision,
    TriageState,
    load_findings_from_json,
)


def run_triage(
    input_path: Path | None = None,
    output_path: Path | None = None,
    findings: Sequence[FindingEntry] | None = None,
    repo_path: Path | None = None,
    context_lines: int = 10,
) -> int:
    """Run the triage TUI (lazy import).

    Args:
        input_path: Path to findings JSON file.
        output_path: Path for .kekkaiignore output.
        findings: Pre-loaded findings (alternative to input_path).
        repo_path: Repository root path for code context display.
        context_lines: Number of lines to show before/after vulnerable line.

    Returns:
        Exit code (0 for success).

    Raises:
        RuntimeError: If Textual is not installed.
    """
    try:
        from .app import run_triage as _run_triage

        return _run_triage(
            input_path=input_path,
            output_path=output_path,
            findings=findings,
            repo_path=repo_path,
            context_lines=context_lines,
        )
    except ImportError as e:
        raise RuntimeError(
            "Triage TUI requires 'textual'. Install with: pip install textual"
        ) from e


# Re-export TriageApp for compatibility (lazy)
def __getattr__(name: str) -> type:
    """Lazy import for TriageApp."""
    if name == "TriageApp":
        from .app import TriageApp

        return TriageApp
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "TriageApp",
    "run_triage",
    "TriageAuditLog",
    "AuditEntry",
    "log_decisions",
    "IgnoreFile",
    "IgnoreEntry",
    "IgnorePatternValidator",
    "ValidationError",
    "FindingEntry",
    "TriageDecision",
    "TriageState",
    "Severity",
    "load_findings_from_json",
    "load_findings_from_path",
]
