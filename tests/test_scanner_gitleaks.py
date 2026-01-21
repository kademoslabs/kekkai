from __future__ import annotations

import json

from kekkai.scanners.base import Severity
from kekkai.scanners.gitleaks import GitleaksScanner

GITLEAKS_OUTPUT = json.dumps(
    [
        {
            "RuleID": "aws-access-key-id",
            "Match": "AKIAIOSFODNN7EXAMPLE",
            "File": "config.py",
            "StartLine": 15,
            "Commit": "abc123",
            "Author": "dev@example.com",
            "Entropy": 3.5,
        },
        {
            "RuleID": "generic-api-key",
            "Match": "api_key=sk_live_very_secret_key_12345",
            "File": ".env",
            "StartLine": 3,
            "Commit": "def456",
            "Author": "admin@example.com",
            "Entropy": 4.2,
        },
    ]
)

GITLEAKS_EMPTY = json.dumps([])


class TestGitleaksParser:
    def test_parse_leaks(self) -> None:
        scanner = GitleaksScanner()
        findings = scanner.parse(GITLEAKS_OUTPUT)

        assert len(findings) == 2

        f1 = findings[0]
        assert f1.rule_id == "aws-access-key-id"
        assert f1.file_path == "config.py"
        assert f1.line == 15
        assert f1.severity == Severity.HIGH
        # Verify secret is redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in f1.description
        assert "..." in f1.description or "REDACTED" in f1.description

        f2 = findings[1]
        assert f2.rule_id == "generic-api-key"
        assert f2.file_path == ".env"

    def test_parse_empty(self) -> None:
        scanner = GitleaksScanner()
        findings = scanner.parse(GITLEAKS_EMPTY)
        assert findings == []

    def test_scanner_properties(self) -> None:
        scanner = GitleaksScanner()
        assert scanner.name == "gitleaks"
        assert scanner.scan_type == "Gitleaks Scan"

    def test_secret_redaction(self) -> None:
        scanner = GitleaksScanner()
        leak = {
            "RuleID": "test",
            "Match": "this_is_a_very_long_secret_value",
            "File": "test.py",
            "StartLine": 1,
        }
        finding = scanner._parse_leak(leak)
        assert "this_is_a_very_long_secret_value" not in finding.description
        assert len(finding.description) < 100
