"""Triage TUI for interactive security finding review.

Provides a terminal-based interface for reviewing findings,
marking false positives, and generating .kekkaiignore files.
"""

from .app import TriageApp, run_triage
from .audit import AuditEntry, TriageAuditLog, log_decisions
from .ignore import IgnoreEntry, IgnoreFile, IgnorePatternValidator, ValidationError
from .models import (
    FindingEntry,
    Severity,
    TriageDecision,
    TriageState,
    load_findings_from_json,
)

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
]
