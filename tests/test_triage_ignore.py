"""Unit tests for triage ignore file handling."""

from __future__ import annotations

from pathlib import Path

import pytest

from kekkai.triage.ignore import (
    IgnoreEntry,
    IgnoreFile,
    IgnorePatternValidator,
    ValidationError,
)


class TestIgnorePatternValidator:
    """Tests for pattern validation security controls."""

    def test_reject_path_traversal_pattern(self) -> None:
        validator = IgnorePatternValidator()
        assert not validator.is_valid("../../../etc/passwd")
        assert not validator.is_valid("**/../secret")
        assert not validator.is_valid("foo/../bar")

    def test_reject_double_dot_in_middle(self) -> None:
        validator = IgnorePatternValidator()
        assert not validator.is_valid("src/../config")
        assert not validator.is_valid("a/b/../c/d")

    def test_accept_valid_glob_pattern(self) -> None:
        validator = IgnorePatternValidator()
        assert validator.is_valid("*.test.js")
        assert validator.is_valid("src/**/generated/**")
        assert validator.is_valid("trivy:CVE-2024-1234:src/main.py")

    def test_accept_scanner_rule_pattern(self) -> None:
        validator = IgnorePatternValidator()
        assert validator.is_valid("semgrep:python.flask.security")
        assert validator.is_valid("gitleaks:generic-api-key")
        assert validator.is_valid("trivy:CVE-2024-1234")

    def test_reject_shell_metacharacters(self) -> None:
        validator = IgnorePatternValidator()
        assert not validator.is_valid("$(whoami)")
        assert not validator.is_valid("`id`")
        assert not validator.is_valid("foo;rm -rf /")
        assert not validator.is_valid("foo|cat /etc/passwd")
        assert not validator.is_valid("foo > /tmp/pwned")

    def test_reject_tilde_expansion(self) -> None:
        validator = IgnorePatternValidator()
        assert not validator.is_valid("~/.ssh/id_rsa")
        assert not validator.is_valid("~/secret")

    def test_reject_empty_pattern(self) -> None:
        validator = IgnorePatternValidator()
        assert not validator.is_valid("")
        assert not validator.is_valid("   ")

    def test_reject_exceeds_max_length(self) -> None:
        validator = IgnorePatternValidator(max_pattern_length=50)
        long_pattern = "a" * 100
        assert not validator.is_valid(long_pattern)

    def test_validate_raises_on_invalid(self) -> None:
        validator = IgnorePatternValidator()
        with pytest.raises(ValidationError, match="Path traversal"):
            validator.validate("../secret")

    def test_validate_returns_stripped_pattern(self) -> None:
        validator = IgnorePatternValidator()
        result = validator.validate("  trivy:CVE-123  ")
        assert result == "trivy:CVE-123"


class TestIgnoreFile:
    """Tests for .kekkaiignore file operations."""

    def test_load_empty_file(self, tmp_path: Path) -> None:
        ignore_path = tmp_path / ".kekkaiignore"
        ignore_path.write_text("")

        ignore_file = IgnoreFile(ignore_path)
        entries = ignore_file.load()
        assert entries == []

    def test_load_with_comments(self, tmp_path: Path) -> None:
        ignore_path = tmp_path / ".kekkaiignore"
        ignore_path.write_text(
            "# This is a comment\ntrivy:CVE-2024-1234\n# Another comment\nsemgrep:rule-id\n"
        )

        ignore_file = IgnoreFile(ignore_path)
        entries = ignore_file.load()
        assert len(entries) == 2
        assert entries[0].pattern == "trivy:CVE-2024-1234"
        assert entries[1].pattern == "semgrep:rule-id"

    def test_load_with_inline_comments(self, tmp_path: Path) -> None:
        ignore_path = tmp_path / ".kekkaiignore"
        ignore_path.write_text("trivy:CVE-123  # False positive in test code\n")

        ignore_file = IgnoreFile(ignore_path)
        entries = ignore_file.load()
        assert len(entries) == 1
        assert entries[0].pattern == "trivy:CVE-123"
        assert entries[0].comment == "False positive in test code"

    def test_load_skips_invalid_patterns(self, tmp_path: Path) -> None:
        ignore_path = tmp_path / ".kekkaiignore"
        ignore_path.write_text("valid:pattern\n../invalid/traversal\nanother:valid:pattern\n")

        ignore_file = IgnoreFile(ignore_path)
        entries = ignore_file.load()
        assert len(entries) == 2

    def test_save_creates_file(self, tmp_path: Path) -> None:
        ignore_path = tmp_path / ".kekkaiignore"
        ignore_file = IgnoreFile(ignore_path)

        ignore_file.add_entry("trivy:CVE-2024-1234", comment="Test finding")
        ignore_file.save()

        assert ignore_path.exists()
        content = ignore_path.read_text()
        assert "trivy:CVE-2024-1234" in content
        assert "Test finding" in content

    def test_save_validates_patterns(self, tmp_path: Path) -> None:
        ignore_path = tmp_path / ".kekkaiignore"
        ignore_file = IgnoreFile(ignore_path)

        with pytest.raises(ValidationError):
            ignore_file.add_entry("../malicious")

    def test_has_pattern(self, tmp_path: Path) -> None:
        ignore_file = IgnoreFile(tmp_path / ".kekkaiignore")
        ignore_file.add_entry("trivy:CVE-123")

        assert ignore_file.has_pattern("trivy:CVE-123")
        assert not ignore_file.has_pattern("trivy:CVE-456")

    def test_matches_exact_pattern(self, tmp_path: Path) -> None:
        ignore_file = IgnoreFile(tmp_path / ".kekkaiignore")
        ignore_file.entries = [IgnoreEntry(pattern="trivy:CVE-123:src/main.py")]

        assert ignore_file.matches("trivy", "CVE-123", "src/main.py")
        assert not ignore_file.matches("trivy", "CVE-456", "src/main.py")

    def test_matches_scanner_rule_pattern(self, tmp_path: Path) -> None:
        ignore_file = IgnoreFile(tmp_path / ".kekkaiignore")
        ignore_file.entries = [IgnoreEntry(pattern="trivy:CVE-123")]

        assert ignore_file.matches("trivy", "CVE-123", "any/file.py")
        assert ignore_file.matches("trivy", "CVE-123", "other/path.js")

    def test_matches_scanner_only_pattern(self, tmp_path: Path) -> None:
        ignore_file = IgnoreFile(tmp_path / ".kekkaiignore")
        ignore_file.entries = [IgnoreEntry(pattern="gitleaks")]

        assert ignore_file.matches("gitleaks", "any-rule", "any/file")

    def test_matches_wildcard_pattern(self, tmp_path: Path) -> None:
        ignore_file = IgnoreFile(tmp_path / ".kekkaiignore")
        ignore_file.entries = [IgnoreEntry(pattern="trivy:*:tests/*")]

        assert ignore_file.matches("trivy", "CVE-123", "tests/test.py")
        assert not ignore_file.matches("trivy", "CVE-123", "src/main.py")

    def test_load_nonexistent_file(self, tmp_path: Path) -> None:
        ignore_file = IgnoreFile(tmp_path / "nonexistent")
        entries = ignore_file.load()
        assert entries == []
