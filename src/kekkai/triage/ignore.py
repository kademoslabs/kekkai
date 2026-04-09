"""Ignore file management for triage decisions.

Provides validation and I/O for .kekkaiignore files with strict
security controls against injection attacks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "IgnorePatternValidator",
    "IgnoreFile",
    "ValidationError",
]

VALID_PATTERN_CHARS = re.compile(r"^[a-zA-Z0-9_./*\-:]+$")
PATH_TRAVERSAL_PATTERN = re.compile(r"(^|/)\.\.(/|$)")
DANGEROUS_PATTERNS = [
    "..",
    "~",
    "$",
    "`",
    ";",
    "&",
    "|",
    ">",
    "<",
    "\\",
]


class ValidationError(Exception):
    """Raised when pattern validation fails."""


@dataclass
class IgnorePatternValidator:
    """Validates ignore patterns against security constraints.

    Enforces:
    - No path traversal (../)
    - Allowlisted characters only
    - Maximum pattern length
    - No shell metacharacters
    """

    max_pattern_length: int = 500

    def is_valid(self, pattern: str) -> bool:
        """Check if a pattern is valid.

        Args:
            pattern: The ignore pattern to validate.

        Returns:
            True if valid, False otherwise.
        """
        if not pattern or not pattern.strip():
            return False

        if len(pattern) > self.max_pattern_length:
            return False

        if PATH_TRAVERSAL_PATTERN.search(pattern):
            return False

        for dangerous in DANGEROUS_PATTERNS:
            if dangerous in pattern:
                return False

        return bool(VALID_PATTERN_CHARS.match(pattern))

    def validate(self, pattern: str) -> str:
        """Validate and return pattern or raise error.

        Args:
            pattern: The ignore pattern to validate.

        Returns:
            The validated pattern (stripped).

        Raises:
            ValidationError: If pattern is invalid.
        """
        pattern = pattern.strip()

        if not pattern:
            raise ValidationError("Empty pattern")

        if len(pattern) > self.max_pattern_length:
            raise ValidationError(f"Pattern exceeds max length ({self.max_pattern_length})")

        if PATH_TRAVERSAL_PATTERN.search(pattern):
            raise ValidationError("Path traversal not allowed")

        for dangerous in DANGEROUS_PATTERNS:
            if dangerous in pattern:
                raise ValidationError(f"Dangerous character not allowed: {dangerous!r}")

        if not VALID_PATTERN_CHARS.match(pattern):
            raise ValidationError("Pattern contains invalid characters")

        return pattern


@dataclass
class IgnoreEntry:
    """An entry in the ignore file.

    Attributes:
        pattern: The ignore pattern.
        comment: Optional comment/reason.
        finding_id: Associated finding ID if applicable.
    """

    pattern: str
    comment: str = ""
    finding_id: str = ""
    owner: str = ""
    expires_at: str = ""
    created_at: str = ""

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return True if entry has an expiry and it is in the past."""
        if not self.expires_at:
            return False
        try:
            expiry = datetime.fromisoformat(self.expires_at)
        except ValueError:
            return False
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        check_now = now or datetime.now(UTC)
        return expiry < check_now


class IgnoreFile:
    """Manages .kekkaiignore file read/write operations.

    Format:
        # Comment line
        scanner:rule_id:file_path  # inline comment

    Attributes:
        path: Path to the ignore file.
        entries: List of ignore entries.
    """

    def __init__(self, path: Path | None = None) -> None:
        """Initialize ignore file manager.

        Args:
            path: Path to ignore file. Defaults to .kekkaiignore in cwd.
        """
        self.path = path or Path(".kekkaiignore")
        self.entries: list[IgnoreEntry] = []
        self._validator = IgnorePatternValidator()
        self.expired_entries_pruned = 0

    def load(self) -> list[IgnoreEntry]:
        """Load entries from file.

        Returns:
            List of ignore entries.
        """
        self.entries = []
        self.expired_entries_pruned = 0

        if not self.path.exists():
            return self.entries

        content = self.path.read_text(encoding="utf-8")
        for line in content.splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            comment = ""
            owner = ""
            expires_at = ""
            created_at = ""
            if " # " in line:
                line, raw_meta = line.split(" # ", 1)
                line = line.strip()
                comment, owner, expires_at, created_at = self._parse_inline_metadata(raw_meta)

            if self._validator.is_valid(line):
                entry = IgnoreEntry(
                    pattern=line,
                    comment=comment,
                    owner=owner,
                    expires_at=expires_at,
                    created_at=created_at,
                )
                if entry.is_expired():
                    self.expired_entries_pruned += 1
                    continue
                self.entries.append(entry)

        return self.entries

    def save(self, entries: Sequence[IgnoreEntry] | None = None) -> None:
        """Save entries to file.

        Args:
            entries: Entries to save. Uses self.entries if None.
        """
        if entries is not None:
            self.entries = list(entries)

        lines = [
            "# Kekkai Ignore File",
            "# Generated by kekkai triage",
            "# Format: scanner:rule_id:file_path",
            "",
        ]

        for entry in self.entries:
            pattern = self._validator.validate(entry.pattern)
            if entry.is_expired():
                self.expired_entries_pruned += 1
                continue

            meta_parts: list[str] = []
            if entry.comment:
                meta_parts.append(entry.comment.replace("\n", " ").replace("#", "")[:100])
            if entry.owner:
                meta_parts.append(f"owner={entry.owner}")
            if entry.expires_at:
                meta_parts.append(f"expires={entry.expires_at}")
            if entry.created_at:
                meta_parts.append(f"created={entry.created_at}")
            if meta_parts:
                lines.append(f"{pattern}  # {' | '.join(meta_parts)}")
            else:
                lines.append(pattern)

        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def add_entry(
        self,
        pattern: str,
        comment: str = "",
        finding_id: str = "",
        owner: str = "",
        expires_at: str = "",
        ttl_days: int = 0,
    ) -> None:
        """Add a validated entry.

        Args:
            pattern: Ignore pattern to add.
            comment: Optional comment.
            finding_id: Associated finding ID.

        Raises:
            ValidationError: If pattern is invalid.
        """
        validated = self._validator.validate(pattern)
        entry = IgnoreEntry(
            pattern=validated,
            comment=comment,
            finding_id=finding_id,
            owner=owner,
            expires_at=expires_at,
            created_at=datetime.now(UTC).isoformat(),
        )
        if not entry.expires_at and ttl_days > 0:
            entry.expires_at = (datetime.now(UTC) + timedelta(days=ttl_days)).isoformat()
        self.entries.append(entry)

    def has_pattern(self, pattern: str) -> bool:
        """Check if pattern already exists.

        Args:
            pattern: Pattern to check.

        Returns:
            True if pattern exists.
        """
        return any(e.pattern == pattern for e in self.entries)

    def matches(self, scanner: str, rule_id: str, file_path: str) -> bool:
        """Check if a finding matches any ignore pattern.

        Args:
            scanner: Scanner name.
            rule_id: Rule identifier.
            file_path: File path.

        Returns:
            True if finding should be ignored.
        """
        full_pattern = f"{scanner}:{rule_id}:{file_path}"
        scanner_rule = f"{scanner}:{rule_id}"
        scanner_only = scanner

        for entry in self.entries:
            if entry.is_expired():
                continue
            pattern = entry.pattern
            if pattern == full_pattern:
                return True
            if pattern == scanner_rule:
                return True
            if pattern == scanner_only:
                return True
            if "*" in pattern and self._glob_match(pattern, full_pattern):
                return True

        return False

    def _glob_match(self, pattern: str, target: str) -> bool:
        """Simple glob matching with * wildcard.

        Args:
            pattern: Pattern with optional * wildcards.
            target: String to match against.

        Returns:
            True if pattern matches target.
        """
        regex_pattern = re.escape(pattern).replace(r"\*", ".*")
        return bool(re.fullmatch(regex_pattern, target))

    def _parse_inline_metadata(self, raw_meta: str) -> tuple[str, str, str, str]:
        """Parse inline metadata comment into text and key fields."""
        comment = raw_meta.strip()
        owner = ""
        expires = ""
        created = ""
        chunks = [c.strip() for c in raw_meta.split("|")]
        text_chunks: list[str] = []
        for chunk in chunks:
            if chunk.startswith("owner="):
                owner = chunk.split("=", 1)[1].strip()
            elif chunk.startswith("expires="):
                expires = chunk.split("=", 1)[1].strip()
            elif chunk.startswith("created="):
                created = chunk.split("=", 1)[1].strip()
            elif chunk:
                text_chunks.append(chunk)
        comment = " | ".join(text_chunks) if text_chunks else ""
        return comment, owner, expires, created
