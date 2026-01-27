"""Triage data models for security finding review.

Provides dataclasses for triage state management with security-focused
validation and immutable decision records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "TriageState",
    "TriageDecision",
    "FindingEntry",
    "Severity",
]


class Severity(Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TriageState(Enum):
    """States for a triaged finding."""

    PENDING = "pending"
    FALSE_POSITIVE = "false_positive"
    CONFIRMED = "confirmed"
    DEFERRED = "deferred"


@dataclass(frozen=True)
class TriageDecision:
    """Immutable record of a triage decision.

    Attributes:
        finding_id: Unique identifier for the finding.
        state: The triage state assigned.
        reason: Optional reason/notes for the decision.
        timestamp: When the decision was made (UTC).
        user: Username or identifier of the triager.
        ignore_pattern: Generated ignore pattern if applicable.
    """

    finding_id: str
    state: TriageState
    reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    user: str = ""
    ignore_pattern: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        """Convert to dictionary for JSON serialization."""
        return {
            "finding_id": self.finding_id,
            "state": self.state.value,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "user": self.user,
            "ignore_pattern": self.ignore_pattern,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str | None]) -> TriageDecision:
        """Create from dictionary."""
        return cls(
            finding_id=str(data.get("finding_id", "")),
            state=TriageState(data.get("state", "pending")),
            reason=str(data.get("reason", "")),
            timestamp=str(data.get("timestamp", "")),
            user=str(data.get("user", "")),
            ignore_pattern=data.get("ignore_pattern"),
        )


@dataclass
class FindingEntry:
    """A security finding entry for triage.

    Attributes:
        id: Unique finding identifier.
        title: Finding title/summary.
        severity: Severity level.
        scanner: Scanner that produced the finding.
        file_path: File path where finding was detected.
        line: Line number if applicable.
        description: Detailed description.
        rule_id: Scanner rule identifier.
        state: Current triage state.
        notes: User notes for this finding.
    """

    id: str
    title: str
    severity: Severity
    scanner: str
    file_path: str = ""
    line: int | None = None
    description: str = ""
    rule_id: str = ""
    state: TriageState = TriageState.PENDING
    notes: str = ""

    def to_dict(self) -> dict[str, str | int | None]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "scanner": self.scanner,
            "file_path": self.file_path,
            "line": self.line,
            "description": self.description,
            "rule_id": self.rule_id,
            "state": self.state.value,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str | int | None]) -> FindingEntry:
        """Create from dictionary (e.g., from scan results JSON)."""
        severity_str = str(data.get("severity", "info")).lower()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.INFO

        state_str = str(data.get("state", "pending")).lower()
        try:
            state = TriageState(state_str)
        except ValueError:
            state = TriageState.PENDING

        line_val = data.get("line")
        line = int(line_val) if line_val is not None else None

        return cls(
            id=str(data.get("id", "")),
            title=str(data.get("title", "")),
            severity=severity,
            scanner=str(data.get("scanner", "")),
            file_path=str(data.get("file_path", "")),
            line=line,
            description=str(data.get("description", "")),
            rule_id=str(data.get("rule_id", "")),
            state=state,
            notes=str(data.get("notes", "")),
        )

    def generate_ignore_pattern(self) -> str:
        """Generate an ignore pattern for this finding.

        Returns:
            A pattern suitable for .kekkaiignore file.
        """
        parts = [self.scanner]
        if self.rule_id:
            parts.append(self.rule_id)
        if self.file_path:
            parts.append(self.file_path)
        return ":".join(parts)


def load_findings_from_json(data: Sequence[dict[str, str | int | None]]) -> list[FindingEntry]:
    """Load findings from JSON data.

    Args:
        data: List of finding dictionaries.

    Returns:
        List of FindingEntry objects.
    """
    return [FindingEntry.from_dict(item) for item in data]
