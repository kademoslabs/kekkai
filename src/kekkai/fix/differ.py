"""Diff generation and application for code fixes.

Handles:
- Parsing unified diff format from LLM output
- Validating diffs before application
- Applying diffs safely with backup
- Generating preview output

ASVS V5.3.3: Output encoding preserves code intent.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar


@dataclass
class DiffHunk:
    """Represents a single hunk in a unified diff."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str] = field(default_factory=list)

    def to_string(self) -> str:
        """Convert hunk back to unified diff format."""
        header = f"@@ -{self.old_start},{self.old_count} +{self.new_start},{self.new_count} @@"
        return header + "\n" + "\n".join(self.lines)


@dataclass
class ParsedDiff:
    """Represents a parsed unified diff."""

    original_file: str
    modified_file: str
    hunks: list[DiffHunk] = field(default_factory=list)
    raw_diff: str = ""

    @property
    def is_valid(self) -> bool:
        """Check if the diff has required components."""
        return bool(self.original_file and self.hunks)

    def to_string(self) -> str:
        """Convert back to unified diff format."""
        lines = [
            f"--- {self.original_file}",
            f"+++ {self.modified_file}",
        ]
        for hunk in self.hunks:
            lines.append(hunk.to_string())
        return "\n".join(lines)


@dataclass
class ApplyResult:
    """Result of applying a diff."""

    success: bool
    file_path: str
    backup_path: str | None = None
    error: str | None = None
    lines_added: int = 0
    lines_removed: int = 0


class DiffParser:
    """Parses unified diff format from LLM output."""

    HUNK_HEADER: ClassVar[re.Pattern[str]] = re.compile(
        r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"
    )

    def parse(self, diff_text: str) -> ParsedDiff:
        """Parse unified diff text into structured format.

        Args:
            diff_text: Raw diff text (possibly with surrounding content)

        Returns:
            ParsedDiff object with parsed hunks
        """
        # Clean up LLM output - remove markdown fences if present
        cleaned = self._clean_llm_output(diff_text)
        lines = cleaned.splitlines()

        original_file = ""
        modified_file = ""
        hunks: list[DiffHunk] = []
        current_hunk: DiffHunk | None = None

        for line in lines:
            if line.startswith("--- "):
                original_file = line[4:].strip()
                # Handle timestamps in diff headers
                if "\t" in original_file:
                    original_file = original_file.split("\t")[0]
            elif line.startswith("+++ "):
                modified_file = line[4:].strip()
                if "\t" in modified_file:
                    modified_file = modified_file.split("\t")[0]
            elif match := self.HUNK_HEADER.match(line):
                if current_hunk:
                    hunks.append(current_hunk)
                current_hunk = DiffHunk(
                    old_start=int(match.group(1)),
                    old_count=int(match.group(2) or 1),
                    new_start=int(match.group(3)),
                    new_count=int(match.group(4) or 1),
                )
            elif current_hunk is not None:
                is_diff_line = (
                    line.startswith("+")
                    or line.startswith("-")
                    or line.startswith(" ")
                    or line == "\\ No newline at end of file"
                )
                if is_diff_line:
                    current_hunk.lines.append(line)

        if current_hunk:
            hunks.append(current_hunk)

        return ParsedDiff(
            original_file=original_file,
            modified_file=modified_file,
            hunks=hunks,
            raw_diff=cleaned,
        )

    def _clean_llm_output(self, text: str) -> str:
        """Remove markdown code fences and other LLM artifacts."""
        # Remove ```diff or ``` markers
        text = re.sub(r"^```(?:diff)?\s*\n", "", text, flags=re.MULTILINE)
        text = re.sub(r"\n```\s*$", "", text)
        text = text.strip()
        return text


class DiffApplier:
    """Applies unified diffs to files safely."""

    def __init__(self, backup_dir: Path | None = None) -> None:
        """Initialize applier with optional backup directory.

        Args:
            backup_dir: Directory for backups. If None, uses temp dir.
        """
        self._backup_dir = backup_dir

    def validate(self, diff: ParsedDiff, repo_path: Path) -> tuple[bool, str]:
        """Validate that a diff can be applied.

        Args:
            diff: Parsed diff to validate
            repo_path: Base path of the repository

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not diff.is_valid:
            return False, "Invalid diff: missing file path or hunks"

        # Resolve file path
        file_path = self._resolve_file_path(diff.original_file, repo_path)
        if not file_path:
            return False, f"Cannot resolve file path: {diff.original_file}"

        if not file_path.exists():
            return False, f"File not found: {file_path}"

        if not file_path.is_file():
            return False, f"Not a regular file: {file_path}"

        # Check file is readable
        try:
            content = file_path.read_text()
        except (OSError, UnicodeDecodeError) as e:
            return False, f"Cannot read file: {e}"

        # Validate hunks can be applied
        lines = content.splitlines(keepends=True)
        for i, hunk in enumerate(diff.hunks):
            valid, err = self._validate_hunk(hunk, lines, i + 1)
            if not valid:
                return False, err

        return True, ""

    def apply(
        self,
        diff: ParsedDiff,
        repo_path: Path,
        *,
        dry_run: bool = False,
        create_backup: bool = True,
    ) -> ApplyResult:
        """Apply a diff to the target file.

        Args:
            diff: Parsed diff to apply
            repo_path: Base path of the repository
            dry_run: If True, don't actually modify the file
            create_backup: If True, create backup before modifying

        Returns:
            ApplyResult with status and details
        """
        file_path = self._resolve_file_path(diff.original_file, repo_path)
        if not file_path:
            return ApplyResult(
                success=False,
                file_path=diff.original_file,
                error=f"Cannot resolve path: {diff.original_file}",
            )

        # Validate first
        valid, err = self.validate(diff, repo_path)
        if not valid:
            return ApplyResult(
                success=False,
                file_path=str(file_path),
                error=err,
            )

        try:
            original_content = file_path.read_text()
        except (OSError, UnicodeDecodeError) as e:
            return ApplyResult(
                success=False,
                file_path=str(file_path),
                error=f"Cannot read file: {e}",
            )

        # Apply hunks
        try:
            new_content, stats = self._apply_hunks(original_content, diff.hunks)
        except ValueError as e:
            return ApplyResult(
                success=False,
                file_path=str(file_path),
                error=f"Failed to apply hunks: {e}",
            )

        if dry_run:
            return ApplyResult(
                success=True,
                file_path=str(file_path),
                lines_added=stats["added"],
                lines_removed=stats["removed"],
            )

        # Create backup
        backup_path = None
        if create_backup:
            backup_path = self._create_backup(file_path)

        # Write new content
        try:
            file_path.write_text(new_content)
        except OSError as e:
            # Restore from backup if write fails
            if backup_path:
                shutil.copy2(backup_path, file_path)
            return ApplyResult(
                success=False,
                file_path=str(file_path),
                backup_path=str(backup_path) if backup_path else None,
                error=f"Failed to write file: {e}",
            )

        return ApplyResult(
            success=True,
            file_path=str(file_path),
            backup_path=str(backup_path) if backup_path else None,
            lines_added=stats["added"],
            lines_removed=stats["removed"],
        )

    def preview(self, diff: ParsedDiff, repo_path: Path) -> str:
        """Generate a preview of the diff application.

        Args:
            diff: Parsed diff to preview
            repo_path: Base path of the repository

        Returns:
            Formatted string showing the diff
        """
        file_path = self._resolve_file_path(diff.original_file, repo_path)
        if not file_path or not file_path.exists():
            return f"[Cannot preview: file not found: {diff.original_file}]"

        lines = [
            f"File: {file_path}",
            "-" * 60,
            diff.to_string(),
            "-" * 60,
        ]
        return "\n".join(lines)

    def _resolve_file_path(self, diff_path: str, repo_path: Path) -> Path | None:
        """Resolve diff file path to actual file path.

        Handles common diff path prefixes like a/, b/.
        """
        # Remove common prefixes
        clean_path = diff_path
        for prefix in ("a/", "b/", "./"):
            if clean_path.startswith(prefix):
                clean_path = clean_path[len(prefix) :]
                break

        # Try as absolute path first
        if os.path.isabs(clean_path):
            return Path(clean_path)

        # Resolve relative to repo
        full_path = (repo_path / clean_path).resolve()

        # Security: ensure path is within repo
        try:
            full_path.relative_to(repo_path.resolve())
        except ValueError:
            return None

        return full_path

    def _validate_hunk(
        self, hunk: DiffHunk, file_lines: list[str], hunk_num: int
    ) -> tuple[bool, str]:
        """Validate that a hunk can be applied to the file."""
        if hunk.old_start < 1:
            return False, f"Hunk {hunk_num}: invalid start line {hunk.old_start}"

        if hunk.old_start > len(file_lines) + 1:
            return False, f"Hunk {hunk_num}: start line {hunk.old_start} beyond file end"

        return True, ""

    def _apply_hunks(self, content: str, hunks: list[DiffHunk]) -> tuple[str, dict[str, int]]:
        """Apply hunks to content and return new content with stats."""
        lines = content.splitlines(keepends=True)
        # Ensure last line has newline for consistent processing
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"

        stats = {"added": 0, "removed": 0}
        offset = 0

        for hunk in sorted(hunks, key=lambda h: h.old_start):
            # Adjust for previous changes
            start_idx = hunk.old_start - 1 + offset

            # Count lines to remove and add
            remove_count = 0
            add_lines: list[str] = []

            for line in hunk.lines:
                if line.startswith("-"):
                    remove_count += 1
                    stats["removed"] += 1
                elif line.startswith("+"):
                    add_lines.append(line[1:] + "\n")
                    stats["added"] += 1
                elif line.startswith(" "):
                    add_lines.append(line[1:] + "\n")

            # Apply the change
            lines[start_idx : start_idx + remove_count] = add_lines
            offset += len(add_lines) - remove_count

        return "".join(lines), stats

    def _create_backup(self, file_path: Path) -> Path | None:
        """Create a backup of the file."""
        backup_dir = self._backup_dir
        if not backup_dir:
            backup_dir = Path(tempfile.gettempdir()) / "kekkai-fix-backups"

        backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        backup_name = f"{file_path.name}.{timestamp}.bak"
        backup_path = backup_dir / backup_name

        try:
            shutil.copy2(file_path, backup_path)
            return backup_path
        except OSError:
            return None


def generate_diff(original: str, modified: str, file_path: str) -> str:
    """Generate a unified diff between two strings.

    Args:
        original: Original content
        modified: Modified content
        file_path: File path for diff header

    Returns:
        Unified diff string
    """
    import difflib

    original_lines = original.splitlines(keepends=True)
    modified_lines = modified.splitlines(keepends=True)

    diff = difflib.unified_diff(
        original_lines,
        modified_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
    )

    return "".join(diff)
