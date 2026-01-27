"""Unit tests for GitHub PR comment filtering and deduplication."""

from __future__ import annotations

from kekkai.github.commenter import _dedupe_by_location, _filter_findings
from kekkai.scanners.base import Finding, Severity


class TestFilterFindings:
    """Tests for _filter_findings function."""

    def test_filter_by_medium(self) -> None:
        """Filter keeps critical, high, medium; excludes low, info."""
        findings = [
            Finding(scanner="t", title="1", severity=Severity.CRITICAL, description=""),
            Finding(scanner="t", title="2", severity=Severity.HIGH, description=""),
            Finding(scanner="t", title="3", severity=Severity.MEDIUM, description=""),
            Finding(scanner="t", title="4", severity=Severity.LOW, description=""),
            Finding(scanner="t", title="5", severity=Severity.INFO, description=""),
        ]

        result = _filter_findings(findings, "medium")

        assert len(result) == 3
        severities = {f.severity for f in result}
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities
        assert Severity.LOW not in severities

    def test_filter_by_critical(self) -> None:
        """Filter by critical keeps only critical."""
        findings = [
            Finding(scanner="t", title="1", severity=Severity.CRITICAL, description=""),
            Finding(scanner="t", title="2", severity=Severity.HIGH, description=""),
        ]

        result = _filter_findings(findings, "critical")

        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL

    def test_filter_by_low(self) -> None:
        """Filter by low includes everything except info."""
        findings = [
            Finding(scanner="t", title="1", severity=Severity.CRITICAL, description=""),
            Finding(scanner="t", title="2", severity=Severity.HIGH, description=""),
            Finding(scanner="t", title="3", severity=Severity.MEDIUM, description=""),
            Finding(scanner="t", title="4", severity=Severity.LOW, description=""),
            Finding(scanner="t", title="5", severity=Severity.INFO, description=""),
        ]

        result = _filter_findings(findings, "low")

        assert len(result) == 4
        assert all(f.severity != Severity.INFO for f in result)

    def test_filter_case_insensitive(self) -> None:
        """Filter handles case-insensitive severity."""
        findings = [
            Finding(scanner="t", title="1", severity=Severity.HIGH, description=""),
        ]

        result = _filter_findings(findings, "HIGH")
        assert len(result) == 1

        result = _filter_findings(findings, "High")
        assert len(result) == 1

    def test_filter_invalid_severity_defaults_medium(self) -> None:
        """Invalid severity defaults to medium."""
        findings = [
            Finding(scanner="t", title="1", severity=Severity.MEDIUM, description=""),
            Finding(scanner="t", title="2", severity=Severity.LOW, description=""),
        ]

        result = _filter_findings(findings, "invalid")

        assert len(result) == 1
        assert result[0].severity == Severity.MEDIUM

    def test_empty_findings(self) -> None:
        """Empty input returns empty output."""
        result = _filter_findings([], "medium")
        assert result == []


class TestDedupeByLocation:
    """Tests for _dedupe_by_location function."""

    def test_dedupe_same_file_line(self) -> None:
        """Findings at same location are deduplicated."""
        findings = [
            Finding(
                scanner="trivy",
                title="Issue 1",
                severity=Severity.HIGH,
                description="First",
                file_path="app.py",
                line=10,
            ),
            Finding(
                scanner="semgrep",
                title="Issue 2",
                severity=Severity.MEDIUM,
                description="Second",
                file_path="app.py",
                line=10,
            ),
        ]

        result = _dedupe_by_location(findings)

        assert len(result) == 1
        assert result[0].title == "Issue 1"  # First one kept

    def test_dedupe_different_lines(self) -> None:
        """Findings at different lines kept."""
        findings = [
            Finding(
                scanner="t",
                title="1",
                severity=Severity.HIGH,
                description="",
                file_path="app.py",
                line=10,
            ),
            Finding(
                scanner="t",
                title="2",
                severity=Severity.HIGH,
                description="",
                file_path="app.py",
                line=20,
            ),
        ]

        result = _dedupe_by_location(findings)

        assert len(result) == 2

    def test_dedupe_different_files(self) -> None:
        """Findings in different files kept."""
        findings = [
            Finding(
                scanner="t",
                title="1",
                severity=Severity.HIGH,
                description="",
                file_path="app.py",
                line=10,
            ),
            Finding(
                scanner="t",
                title="2",
                severity=Severity.HIGH,
                description="",
                file_path="util.py",
                line=10,
            ),
        ]

        result = _dedupe_by_location(findings)

        assert len(result) == 2

    def test_dedupe_none_file_path(self) -> None:
        """Findings without file path handled."""
        findings = [
            Finding(
                scanner="t",
                title="1",
                severity=Severity.HIGH,
                description="",
                file_path=None,
                line=None,
            ),
            Finding(
                scanner="t",
                title="2",
                severity=Severity.HIGH,
                description="",
                file_path=None,
                line=None,
            ),
        ]

        result = _dedupe_by_location(findings)

        # Both have same key (None, None) so only first kept
        assert len(result) == 1

    def test_preserves_order(self) -> None:
        """Deduplication preserves original order."""
        findings = [
            Finding(
                scanner="t",
                title="A",
                severity=Severity.HIGH,
                description="",
                file_path="a.py",
                line=1,
            ),
            Finding(
                scanner="t",
                title="B",
                severity=Severity.HIGH,
                description="",
                file_path="b.py",
                line=1,
            ),
            Finding(
                scanner="t",
                title="C",
                severity=Severity.HIGH,
                description="",
                file_path="c.py",
                line=1,
            ),
        ]

        result = _dedupe_by_location(findings)

        assert [f.title for f in result] == ["A", "B", "C"]
