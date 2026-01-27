"""Regression tests for triage backwards compatibility."""

from __future__ import annotations

from pathlib import Path

import pytest

from kekkai.triage import (
    FindingEntry,
    IgnoreFile,
    IgnorePatternValidator,
    Severity,
    TriageState,
)


@pytest.mark.regression
class TestIgnoreFileBackwardsCompat:
    """Ensure existing .kekkaiignore files remain valid."""

    def test_legacy_format_still_valid(self, tmp_path: Path) -> None:
        """Legacy ignore files with simple patterns should still work."""
        ignore_path = tmp_path / ".kekkaiignore"
        ignore_path.write_text(
            "# Legacy format ignore file\n"
            "trivy:CVE-2023-0001\n"
            "semgrep:python.security.audit\n"
            "gitleaks\n"
        )

        ignore_file = IgnoreFile(ignore_path)
        entries = ignore_file.load()

        assert len(entries) == 3
        assert ignore_file.matches("trivy", "CVE-2023-0001", "any/file.py")
        assert ignore_file.matches("semgrep", "python.security.audit", "test.py")
        assert ignore_file.matches("gitleaks", "any-rule", "config.py")

    def test_full_path_patterns_still_work(self, tmp_path: Path) -> None:
        """Full scanner:rule:path patterns should continue working."""
        ignore_path = tmp_path / ".kekkaiignore"
        ignore_path.write_text("trivy:CVE-2024-1234:src/vulnerable.py\n")

        ignore_file = IgnoreFile(ignore_path)
        ignore_file.load()

        assert ignore_file.matches("trivy", "CVE-2024-1234", "src/vulnerable.py")
        assert not ignore_file.matches("trivy", "CVE-2024-1234", "other/file.py")

    def test_wildcard_patterns_still_work(self, tmp_path: Path) -> None:
        """Wildcard patterns should continue matching."""
        ignore_path = tmp_path / ".kekkaiignore"
        ignore_path.write_text("trivy:*:tests/*\n")

        ignore_file = IgnoreFile(ignore_path)
        ignore_file.load()

        assert ignore_file.matches("trivy", "CVE-2024-1234", "tests/test_app.py")
        assert ignore_file.matches("trivy", "OTHER-CVE", "tests/conftest.py")
        assert not ignore_file.matches("trivy", "CVE-2024-1234", "src/main.py")

    def test_inline_comments_preserved(self, tmp_path: Path) -> None:
        """Inline comments should be parsed correctly."""
        ignore_path = tmp_path / ".kekkaiignore"
        ignore_path.write_text("trivy:CVE-2024-1234  # False positive in test deps\n")

        ignore_file = IgnoreFile(ignore_path)
        entries = ignore_file.load()

        assert len(entries) == 1
        assert entries[0].pattern == "trivy:CVE-2024-1234"
        assert entries[0].comment == "False positive in test deps"


@pytest.mark.regression
class TestPatternValidationBackwardsCompat:
    """Ensure pattern validation doesn't break existing patterns."""

    def test_common_valid_patterns(self) -> None:
        """Common patterns used in existing projects should remain valid."""
        validator = IgnorePatternValidator()

        valid_patterns = [
            "trivy:CVE-2024-1234",
            "semgrep:python.security.audit",
            "gitleaks:generic-api-key",
            "trivy:CVE-2024-1234:src/main.py",
            "semgrep:*:tests/*",
            "*.test.js",
            "src/**/generated/**",
            "node_modules/*",
        ]

        for pattern in valid_patterns:
            assert validator.is_valid(pattern), f"Pattern should be valid: {pattern}"

    def test_colon_separated_format(self) -> None:
        """Colon-separated scanner:rule:path format should work."""
        validator = IgnorePatternValidator()

        assert validator.is_valid("scanner:rule:path/to/file.py")
        assert validator.is_valid("scanner:rule-with-dashes:path/file.py")
        assert validator.is_valid("scanner:rule_with_underscores:path/file.py")


@pytest.mark.regression
class TestFindingEntryBackwardsCompat:
    """Ensure finding entry serialization is stable."""

    def test_finding_to_dict_format_stable(self) -> None:
        """Finding serialization format should remain consistent."""
        finding = FindingEntry(
            id="test-123",
            title="Test Finding",
            severity=Severity.HIGH,
            scanner="trivy",
            file_path="src/main.py",
            line=42,
            description="Test description",
            rule_id="CVE-2024-1234",
            state=TriageState.PENDING,
            notes="Test notes",
        )

        data = finding.to_dict()

        expected_keys = {
            "id",
            "title",
            "severity",
            "scanner",
            "file_path",
            "line",
            "description",
            "rule_id",
            "state",
            "notes",
        }
        assert set(data.keys()) == expected_keys
        assert data["severity"] == "high"
        assert data["state"] == "pending"

    def test_finding_from_dict_handles_legacy_data(self) -> None:
        """Should handle legacy data that might be missing optional fields."""
        legacy_data: dict[str, str | int | None] = {
            "id": "old-finding",
            "title": "Old Finding",
            "severity": "HIGH",  # uppercase
            "scanner": "trivy",
        }

        finding = FindingEntry.from_dict(legacy_data)

        assert finding.id == "old-finding"
        assert finding.severity == Severity.HIGH
        assert finding.file_path == ""
        assert finding.line is None
        assert finding.state == TriageState.PENDING


@pytest.mark.regression
class TestGenerateIgnorePatternBackwardsCompat:
    """Ensure ignore pattern generation is stable."""

    def test_pattern_format_unchanged(self) -> None:
        """Generated patterns should use consistent format."""
        finding = FindingEntry(
            id="test",
            title="Test",
            severity=Severity.HIGH,
            scanner="trivy",
            rule_id="CVE-2024-1234",
            file_path="src/main.py",
        )

        pattern = finding.generate_ignore_pattern()

        assert pattern == "trivy:CVE-2024-1234:src/main.py"
        assert pattern.count(":") == 2

    def test_scanner_only_pattern_format(self) -> None:
        """Scanner-only patterns should work."""
        finding = FindingEntry(
            id="test",
            title="Test",
            severity=Severity.HIGH,
            scanner="gitleaks",
        )

        pattern = finding.generate_ignore_pattern()
        assert pattern == "gitleaks"
