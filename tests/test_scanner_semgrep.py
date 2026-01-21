from __future__ import annotations

import json

from kekkai.scanners.base import Severity
from kekkai.scanners.semgrep import SemgrepScanner

SEMGREP_OUTPUT = json.dumps(
    {
        "results": [
            {
                "check_id": "python.lang.security.audit.exec-detected",
                "path": "src/main.py",
                "start": {"line": 42, "col": 1},
                "end": {"line": 42, "col": 20},
                "extra": {
                    "severity": "ERROR",
                    "message": "Detected use of exec(). This is dangerous.",
                    "fingerprint": "abc123",
                    "fix": "Remove exec() call",
                    "metadata": {
                        "cwe": ["CWE-94"],
                        "message": "Code injection via exec()",
                    },
                },
            },
            {
                "check_id": "python.lang.best-practice.print-used",
                "path": "src/utils.py",
                "start": {"line": 10, "col": 1},
                "end": {"line": 10, "col": 15},
                "extra": {
                    "severity": "WARNING",
                    "message": "Print statement detected",
                    "metadata": {},
                },
            },
        ],
        "errors": [],
    }
)

SEMGREP_EMPTY = json.dumps({"results": [], "errors": []})


class TestSemgrepParser:
    def test_parse_findings(self) -> None:
        scanner = SemgrepScanner()
        findings = scanner.parse(SEMGREP_OUTPUT)

        assert len(findings) == 2

        f1 = findings[0]
        assert f1.rule_id == "python.lang.security.audit.exec-detected"
        assert f1.file_path == "src/main.py"
        assert f1.line == 42
        assert f1.severity == Severity.HIGH  # ERROR maps to HIGH
        assert f1.cwe == "CWE-94"

        f2 = findings[1]
        assert f2.rule_id == "python.lang.best-practice.print-used"
        assert f2.severity == Severity.MEDIUM  # WARNING maps to MEDIUM

    def test_parse_empty(self) -> None:
        scanner = SemgrepScanner()
        findings = scanner.parse(SEMGREP_EMPTY)
        assert findings == []

    def test_scanner_properties(self) -> None:
        scanner = SemgrepScanner()
        assert scanner.name == "semgrep"
        assert scanner.scan_type == "Semgrep JSON Report"
