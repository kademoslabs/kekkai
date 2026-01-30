"""Audit logging for fix applications.

Records all fix attempts, approvals, and applications with timestamps
for compliance and forensics purposes.

ASVS V8.3.1: Sensitive data not logged inappropriately.
ASVS V16.3.3: Log security-relevant events.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FixAttempt:
    """Record of a single fix attempt."""

    finding_id: str
    rule_id: str
    file_path: str
    line_number: int
    severity: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    model_used: str = ""
    status: str = "pending"  # pending, approved, applied, rejected, failed
    error: str | None = None
    diff_preview: str | None = None
    lines_added: int = 0
    lines_removed: int = 0
    backup_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class FixAuditLog:
    """Audit log for fix operations.

    Maintains an append-only log of all fix attempts for a session.
    """

    session_id: str
    repo_path: str
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    model_mode: str = "local"
    attempts: list[FixAttempt] = field(default_factory=list)
    _output_path: Path | None = field(default=None, repr=False)

    def record_attempt(
        self,
        finding_id: str,
        rule_id: str,
        file_path: str,
        line_number: int,
        severity: str,
        model_used: str = "",
    ) -> FixAttempt:
        """Record a new fix attempt.

        Args:
            finding_id: Unique identifier for the finding
            rule_id: Scanner rule that triggered the finding
            file_path: Path to the affected file
            line_number: Line number of the finding
            severity: Finding severity level
            model_used: LLM model used for fix generation

        Returns:
            The created FixAttempt record
        """
        attempt = FixAttempt(
            finding_id=finding_id,
            rule_id=rule_id,
            file_path=file_path,
            line_number=line_number,
            severity=severity,
            model_used=model_used,
        )
        self.attempts.append(attempt)
        self._auto_save()

        logger.info(
            "fix_attempt_recorded",
            extra={
                "finding_id": finding_id,
                "rule_id": rule_id,
                "file_path": file_path,
                "line_number": line_number,
            },
        )

        return attempt

    def update_attempt(
        self,
        attempt: FixAttempt,
        *,
        status: str | None = None,
        error: str | None = None,
        diff_preview: str | None = None,
        lines_added: int | None = None,
        lines_removed: int | None = None,
        backup_path: str | None = None,
    ) -> None:
        """Update an existing attempt record.

        Args:
            attempt: The attempt to update
            status: New status (approved, applied, rejected, failed)
            error: Error message if failed
            diff_preview: Preview of the diff (truncated for security)
            lines_added: Number of lines added
            lines_removed: Number of lines removed
            backup_path: Path to backup file if created
        """
        if status is not None:
            attempt.status = status
        if error is not None:
            attempt.error = error
        if diff_preview is not None:
            # Truncate diff preview to avoid logging sensitive code
            attempt.diff_preview = diff_preview[:500] if len(diff_preview) > 500 else diff_preview
        if lines_added is not None:
            attempt.lines_added = lines_added
        if lines_removed is not None:
            attempt.lines_removed = lines_removed
        if backup_path is not None:
            attempt.backup_path = backup_path

        self._auto_save()

        logger.info(
            "fix_attempt_updated",
            extra={
                "finding_id": attempt.finding_id,
                "status": attempt.status,
                "lines_changed": (attempt.lines_added + attempt.lines_removed),
            },
        )

    def mark_applied(
        self,
        attempt: FixAttempt,
        lines_added: int,
        lines_removed: int,
        backup_path: str | None = None,
    ) -> None:
        """Mark an attempt as successfully applied."""
        self.update_attempt(
            attempt,
            status="applied",
            lines_added=lines_added,
            lines_removed=lines_removed,
            backup_path=backup_path,
        )

    def mark_failed(self, attempt: FixAttempt, error: str) -> None:
        """Mark an attempt as failed."""
        self.update_attempt(attempt, status="failed", error=error)

    def mark_rejected(self, attempt: FixAttempt, reason: str = "") -> None:
        """Mark an attempt as rejected by user."""
        self.update_attempt(attempt, status="rejected", error=reason or "User rejected")

    @property
    def summary(self) -> dict[str, int]:
        """Get summary counts by status."""
        counts: dict[str, int] = {
            "total": len(self.attempts),
            "pending": 0,
            "approved": 0,
            "applied": 0,
            "rejected": 0,
            "failed": 0,
        }
        for attempt in self.attempts:
            if attempt.status in counts:
                counts[attempt.status] += 1
        return counts

    def set_output_path(self, path: Path) -> None:
        """Set the output path for auto-saving."""
        self._output_path = path
        self._auto_save()

    def _auto_save(self) -> None:
        """Auto-save if output path is set."""
        if self._output_path:
            self.save(self._output_path)

    def save(self, path: Path) -> None:
        """Save audit log to JSON file.

        Args:
            path: Output path for the JSON file
        """
        data = {
            "session_id": self.session_id,
            "repo_path": self.repo_path,
            "started_at": self.started_at,
            "model_mode": self.model_mode,
            "summary": self.summary,
            "attempts": [a.to_dict() for a in self.attempts],
        }

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2))

        logger.debug("audit_log_saved", extra={"path": str(path)})

    @classmethod
    def load(cls, path: Path) -> FixAuditLog:
        """Load audit log from JSON file.

        Args:
            path: Path to the JSON file

        Returns:
            Loaded FixAuditLog instance
        """
        data = json.loads(path.read_text())

        log = cls(
            session_id=data["session_id"],
            repo_path=data["repo_path"],
            started_at=data.get("started_at", ""),
            model_mode=data.get("model_mode", "local"),
        )

        for attempt_data in data.get("attempts", []):
            attempt = FixAttempt(
                finding_id=attempt_data["finding_id"],
                rule_id=attempt_data["rule_id"],
                file_path=attempt_data["file_path"],
                line_number=attempt_data["line_number"],
                severity=attempt_data["severity"],
                timestamp=attempt_data.get("timestamp", ""),
                model_used=attempt_data.get("model_used", ""),
                status=attempt_data.get("status", "pending"),
                error=attempt_data.get("error"),
                diff_preview=attempt_data.get("diff_preview"),
                lines_added=attempt_data.get("lines_added", 0),
                lines_removed=attempt_data.get("lines_removed", 0),
                backup_path=attempt_data.get("backup_path"),
            )
            log.attempts.append(attempt)

        return log

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "repo_path": self.repo_path,
            "started_at": self.started_at,
            "model_mode": self.model_mode,
            "summary": self.summary,
            "attempts": [a.to_dict() for a in self.attempts],
        }


def create_session_id() -> str:
    """Generate a unique session ID for audit logging."""
    import secrets

    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    random_suffix = secrets.token_hex(4)
    return f"fix-{timestamp}-{random_suffix}"
