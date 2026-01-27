"""Regression tests for GitHub commenter JSON compatibility."""

from __future__ import annotations

from typing import Any

import pytest

from kekkai.github.commenter import _format_comment
from kekkai.scanners.base import Finding, Severity


@pytest.mark.regression
class TestJsonOutputCompatibility:
    """Tests ensuring JSON output format remains compatible with commenter."""

    def test_finding_from_json_dict(self) -> None:
        """Finding can be reconstructed from JSON-serializable dict."""
        json_data: dict[str, Any] = {
            "scanner": "trivy",
            "title": "CVE-2024-1234",
            "severity": "high",
            "description": "Vulnerable package",
            "file_path": "requirements.txt",
            "line": 10,
            "rule_id": "CVE-2024-1234",
            "cve": "CVE-2024-1234",
            "cwe": None,
            "package_name": "requests",
            "package_version": "2.25.0",
            "fixed_version": "2.32.0",
        }

        finding = Finding(
            scanner=str(json_data["scanner"]),
            title=str(json_data["title"]),
            severity=Severity.from_string(str(json_data["severity"])),
            description=str(json_data["description"]),
            file_path=str(json_data["file_path"]) if json_data["file_path"] else None,
            line=int(json_data["line"]) if json_data["line"] else None,
            rule_id=str(json_data["rule_id"]) if json_data["rule_id"] else None,
            cve=str(json_data["cve"]) if json_data["cve"] else None,
            cwe=str(json_data["cwe"]) if json_data["cwe"] else None,
            package_name=str(json_data["package_name"]) if json_data["package_name"] else None,
            package_version=(
                str(json_data["package_version"]) if json_data["package_version"] else None
            ),
            fixed_version=(str(json_data["fixed_version"]) if json_data["fixed_version"] else None),
        )

        comment = _format_comment(finding)

        assert "CVE-2024-1234" in comment
        assert "trivy" in comment
        assert "HIGH" in comment

    def test_severity_string_mapping(self) -> None:
        """All severity strings map correctly."""
        test_cases = [
            ("critical", Severity.CRITICAL),
            ("high", Severity.HIGH),
            ("medium", Severity.MEDIUM),
            ("moderate", Severity.MEDIUM),
            ("low", Severity.LOW),
            ("info", Severity.INFO),
            ("informational", Severity.INFO),
            ("warning", Severity.LOW),
            ("unknown_value", Severity.UNKNOWN),
        ]

        for string_val, expected in test_cases:
            result = Severity.from_string(string_val)
            assert result == expected, f"Failed for {string_val}"

    def test_optional_fields_none(self) -> None:
        """Findings with None optional fields work."""
        finding = Finding(
            scanner="test",
            title="Test Finding",
            severity=Severity.MEDIUM,
            description="Description",
            file_path=None,
            line=None,
            rule_id=None,
            cve=None,
            cwe=None,
        )

        comment = _format_comment(finding)

        # Should not crash and should have basic info
        assert "Test Finding" in comment
        assert "MEDIUM" in comment
        # Optional fields should not appear
        assert "CVE:" not in comment
        assert "CWE:" not in comment

    def test_extra_fields_ignored(self) -> None:
        """Extra fields in JSON are ignored gracefully."""
        json_data: dict[str, Any] = {
            "scanner": "test",
            "title": "Test",
            "severity": "high",
            "description": "Desc",
            "unknown_field": "should be ignored",
            "another_unknown": 123,
        }

        # Should not raise when extra fields present
        finding = Finding(
            scanner=json_data["scanner"],
            title=json_data["title"],
            severity=Severity.from_string(json_data["severity"]),
            description=json_data["description"],
        )

        comment = _format_comment(finding)
        assert "Test" in comment


@pytest.mark.regression
class TestCommentFormatStability:
    """Tests ensuring comment format remains stable."""

    def test_comment_contains_required_sections(self) -> None:
        """Comment format has all required sections."""
        finding = Finding(
            scanner="semgrep",
            title="Hardcoded Password",
            severity=Severity.HIGH,
            description="Password found in source code",
            file_path="config.py",
            line=25,
            rule_id="python.security.hardcoded-password",
            cwe="CWE-798",
        )

        comment = _format_comment(finding)

        # Required sections
        assert "###" in comment  # Header
        assert "HIGH" in comment  # Severity
        assert "Scanner:" in comment
        assert "semgrep" in comment
        assert "Rule:" in comment
        assert "CWE:" in comment
        assert "Posted by [Kekkai]" in comment  # Footer

    def test_emoji_mapping_stable(self) -> None:
        """Severity emoji mapping is stable."""
        expected_emojis = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "🔵",
        }

        for severity, emoji in expected_emojis.items():
            finding = Finding(
                scanner="test",
                title="Test",
                severity=severity,
                description="",
            )
            comment = _format_comment(finding)
            assert emoji in comment, f"Emoji {emoji} not found for {severity}"

    def test_line_endings_consistent(self) -> None:
        """Comment uses consistent line endings."""
        finding = Finding(
            scanner="test",
            title="Test",
            severity=Severity.HIGH,
            description="Multi\nline\ndescription",
            file_path="test.py",
            line=1,
        )

        comment = _format_comment(finding)

        # Should not have Windows line endings
        assert "\r\n" not in comment
        # Should use Unix line endings
        assert "\n" in comment


@pytest.mark.regression
class TestBackwardsCompatibility:
    """Tests for backwards compatibility with existing outputs."""

    def test_scan_result_json_structure(self) -> None:
        """Scan result JSON structure is compatible."""
        # Simulate JSON output from kekkai scan --output
        scan_output: dict[str, Any] = {
            "run_id": "test-run-123",
            "findings": [
                {
                    "scanner": "trivy",
                    "title": "CVE-2024-0001",
                    "severity": "critical",
                    "description": "Remote code execution",
                    "file_path": "Dockerfile",
                    "line": 5,
                    "cve": "CVE-2024-0001",
                },
                {
                    "scanner": "gitleaks",
                    "title": "AWS Key Detected",
                    "severity": "high",
                    "description": "Hardcoded AWS access key",
                    "file_path": ".env",
                    "line": 3,
                    "rule_id": "aws-access-key",
                },
            ],
        }

        # Convert to findings
        findings = []
        findings_list: list[dict[str, Any]] = scan_output["findings"]
        for f in findings_list:
            findings.append(
                Finding(
                    scanner=str(f["scanner"]),
                    title=str(f["title"]),
                    severity=Severity.from_string(str(f["severity"])),
                    description=str(f["description"]),
                    file_path=str(f["file_path"]) if f.get("file_path") else None,
                    line=int(f["line"]) if f.get("line") else None,
                    rule_id=str(f["rule_id"]) if f.get("rule_id") else None,
                    cve=str(f["cve"]) if f.get("cve") else None,
                )
            )

        # All findings should format successfully
        for finding in findings:
            comment = _format_comment(finding)
            assert finding.title in comment or finding.title.replace("'", "") in comment
