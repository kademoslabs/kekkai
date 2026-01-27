"""Audit logging for triage decisions.

Provides append-only audit trail for all triage decisions to
support non-repudiation and compliance requirements.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .models import TriageDecision

__all__ = [
    "TriageAuditLog",
    "AuditEntry",
]


class AuditEntry:
    """A single audit log entry.

    Attributes:
        timestamp: When the action occurred (ISO format).
        action: The action performed (e.g., "mark_false_positive").
        finding_id: ID of the affected finding.
        user: User who performed the action.
        details: Additional action details.
    """

    def __init__(
        self,
        action: str,
        finding_id: str,
        user: str = "",
        details: dict[str, str] | None = None,
        timestamp: str | None = None,
    ) -> None:
        self.timestamp = timestamp or datetime.now(UTC).isoformat()
        self.action = action
        self.finding_id = finding_id
        self.user = user or os.environ.get("USER", "unknown")
        self.details = details or {}

    def to_dict(self) -> dict[str, str | dict[str, str]]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "finding_id": self.finding_id,
            "user": self.user,
            "details": self.details,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, str | dict[str, str]]) -> AuditEntry:
        """Create from dictionary."""
        details_raw = data.get("details", {})
        details = dict(details_raw) if isinstance(details_raw, dict) else {}
        return cls(
            timestamp=str(data.get("timestamp", "")),
            action=str(data.get("action", "")),
            finding_id=str(data.get("finding_id", "")),
            user=str(data.get("user", "")),
            details={str(k): str(v) for k, v in details.items()},
        )


class TriageAuditLog:
    """Append-only audit log for triage decisions.

    Stores entries in JSON Lines format (.jsonl) for easy parsing
    and tamper evidence.

    Attributes:
        path: Path to the audit log file.
    """

    DEFAULT_PATH = Path.home() / ".kekkai" / "triage-audit.jsonl"

    def __init__(self, path: Path | None = None) -> None:
        """Initialize audit log.

        Args:
            path: Path to audit log file. Defaults to ~/.kekkai/triage-audit.jsonl.
        """
        self.path = path or self.DEFAULT_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, entry: AuditEntry) -> None:
        """Append an entry to the audit log.

        Args:
            entry: The audit entry to log.
        """
        with self.path.open("a", encoding="utf-8") as f:
            f.write(entry.to_json() + "\n")

    def log_decision(self, decision: TriageDecision) -> None:
        """Log a triage decision.

        Args:
            decision: The triage decision to log.
        """
        entry = AuditEntry(
            action=f"triage_{decision.state.value}",
            finding_id=decision.finding_id,
            user=decision.user,
            details={
                "reason": decision.reason,
                "ignore_pattern": decision.ignore_pattern or "",
            },
        )
        self.log(entry)

    def log_action(
        self,
        action: str,
        finding_id: str,
        details: dict[str, str] | None = None,
    ) -> None:
        """Log a generic action.

        Args:
            action: Action name.
            finding_id: Affected finding ID.
            details: Additional details.
        """
        entry = AuditEntry(
            action=action,
            finding_id=finding_id,
            details=details,
        )
        self.log(entry)

    def read_all(self) -> list[AuditEntry]:
        """Read all entries from the log.

        Returns:
            List of all audit entries.
        """
        entries: list[AuditEntry] = []

        if not self.path.exists():
            return entries

        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entries.append(AuditEntry.from_dict(data))
                except json.JSONDecodeError:
                    continue

        return entries

    def read_for_finding(self, finding_id: str) -> list[AuditEntry]:
        """Read entries for a specific finding.

        Args:
            finding_id: The finding ID to filter by.

        Returns:
            List of matching audit entries.
        """
        return [e for e in self.read_all() if e.finding_id == finding_id]

    def get_recent(self, count: int = 100) -> list[AuditEntry]:
        """Get most recent entries.

        Args:
            count: Maximum number of entries to return.

        Returns:
            List of recent audit entries (newest last).
        """
        all_entries = self.read_all()
        return all_entries[-count:] if len(all_entries) > count else all_entries


def log_decisions(decisions: Sequence[TriageDecision], log_path: Path | None = None) -> None:
    """Log multiple triage decisions.

    Args:
        decisions: Decisions to log.
        log_path: Optional custom log path.
    """
    audit_log = TriageAuditLog(log_path)
    for decision in decisions:
        audit_log.log_decision(decision)
