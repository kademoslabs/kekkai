"""Unit tests for GitHub PR comment formatting."""

from __future__ import annotations

from kekkai.github.commenter import (
    SEVERITY_EMOJI,
    _format_comment,
    _format_summary,
)
from kekkai.scanners.base import Finding, Severity


class TestFormatComment:
    """Tests for _format_comment function."""

    def test_basic_finding_format(self) -> None:
        """Basic finding formats correctly."""
        finding = Finding(
            scanner="trivy",
            title="SQL Injection Vulnerability",
            severity=Severity.HIGH,
            description="User input not sanitized",
            file_path="app.py",
            line=42,
            rule_id="CWE-89",
        )

        comment = _format_comment(finding)

        assert "🟠 HIGH" in comment
        assert "SQL Injection Vulnerability" in comment
        assert "trivy" in comment
        assert "CWE-89" in comment
        assert "Posted by [Kekkai]" in comment

    def test_critical_severity_emoji(self) -> None:
        """Critical findings show red emoji."""
        finding = Finding(
            scanner="test",
            title="Critical Issue",
            severity=Severity.CRITICAL,
            description="Very bad",
        )

        comment = _format_comment(finding)

        assert "🔴 CRITICAL" in comment

    def test_all_severity_emojis(self) -> None:
        """All severity levels have correct emojis."""
        for severity, emoji in SEVERITY_EMOJI.items():
            finding = Finding(
                scanner="test",
                title="Test",
                severity=severity,
                description="Test description",
            )
            comment = _format_comment(finding)
            assert emoji in comment

    def test_cve_included(self) -> None:
        """CVE is included when present."""
        finding = Finding(
            scanner="trivy",
            title="Vulnerable Package",
            severity=Severity.HIGH,
            description="Known vulnerability",
            cve="CVE-2024-1234",
        )

        comment = _format_comment(finding)

        assert "CVE-2024-1234" in comment

    def test_cwe_included(self) -> None:
        """CWE is included when present."""
        finding = Finding(
            scanner="semgrep",
            title="Code Issue",
            severity=Severity.MEDIUM,
            description="Bad pattern",
            cwe="CWE-79",
        )

        comment = _format_comment(finding)

        assert "CWE-79" in comment

    def test_description_truncation(self) -> None:
        """Long descriptions are truncated."""
        long_desc = "A" * 1000
        finding = Finding(
            scanner="test",
            title="Test",
            severity=Severity.LOW,
            description=long_desc,
        )

        comment = _format_comment(finding)

        # Description should be truncated to 500 chars before escaping
        assert len(comment) < 1500

    def test_markdown_in_title_escaped(self) -> None:
        """Markdown in title is escaped."""
        finding = Finding(
            scanner="test",
            title="[Click here](http://evil.com) for details",
            severity=Severity.HIGH,
            description="Bad link",
        )

        comment = _format_comment(finding)

        # The markdown link should be broken
        assert "](http://evil.com)" not in comment
        assert "\\[Click" in comment or "Click" in comment

    def test_markdown_injection_prevented(self) -> None:
        """Markdown injection in description is prevented."""
        finding = Finding(
            scanner="test",
            title="Test",
            severity=Severity.HIGH,
            description="Use `rm -rf /` to **destroy** everything",
        )

        comment = _format_comment(finding)

        # Backticks and asterisks should be escaped
        assert "\\`" in comment or "`rm" not in comment


class TestFormatSummary:
    """Tests for _format_summary function."""

    def test_single_finding(self) -> None:
        """Summary for single finding."""
        summary = _format_summary(1)
        assert "1 finding(s)" in summary
        assert "Kekkai Security Scan" in summary

    def test_multiple_findings(self) -> None:
        """Summary for multiple findings."""
        summary = _format_summary(10)
        assert "10 finding(s)" in summary

    def test_zero_findings(self) -> None:
        """Summary for zero findings."""
        summary = _format_summary(0)
        assert "0 finding(s)" in summary
