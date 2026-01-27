from __future__ import annotations

import json

from kekkai.scanners.base import Severity
from kekkai.scanners.trivy import TrivyScanner

TRIVY_OUTPUT_VULN = json.dumps(
    {
        "Results": [
            {
                "Target": "package-lock.json",
                "Type": "npm",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-1234",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.19",
                        "FixedVersion": "4.17.21",
                        "Severity": "HIGH",
                        "Title": "Prototype Pollution",
                        "Description": "Lodash is vulnerable to prototype pollution.",
                    },
                    {
                        "VulnerabilityID": "CVE-2023-5678",
                        "PkgName": "axios",
                        "InstalledVersion": "0.21.0",
                        "FixedVersion": "0.21.2",
                        "Severity": "MEDIUM",
                        "Title": "SSRF in axios",
                        "Description": "Axios is vulnerable to SSRF.",
                    },
                ],
            }
        ]
    }
)

TRIVY_OUTPUT_SECRETS = json.dumps(
    {
        "Results": [
            {
                "Target": "config.py",
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Title": "AWS Access Key",
                        "Severity": "CRITICAL",
                        "Match": "AKIAIOSFODNN7EXAMPLE",
                        "StartLine": 10,
                    },
                ],
            }
        ]
    }
)

TRIVY_OUTPUT_MISCONFIG = json.dumps(
    {
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "Title": "Running as root",
                        "Severity": "HIGH",
                        "Description": "Container runs as root user",
                        "Resolution": "Add USER instruction",
                    },
                ],
            }
        ]
    }
)


class TestTrivyParser:
    def test_parse_vulnerabilities(self) -> None:
        scanner = TrivyScanner()
        findings = scanner.parse(TRIVY_OUTPUT_VULN)

        assert len(findings) == 2
        assert findings[0].cve == "CVE-2023-1234"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].package_name == "lodash"
        assert findings[0].fixed_version == "4.17.21"

        assert findings[1].cve == "CVE-2023-5678"
        assert findings[1].severity == Severity.MEDIUM

    def test_parse_secrets(self) -> None:
        scanner = TrivyScanner()
        findings = scanner.parse(TRIVY_OUTPUT_SECRETS)

        assert len(findings) == 1
        assert findings[0].rule_id == "aws-access-key-id"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].line == 10

    def test_parse_misconfigurations(self) -> None:
        scanner = TrivyScanner()
        findings = scanner.parse(TRIVY_OUTPUT_MISCONFIG)

        assert len(findings) == 1
        assert findings[0].rule_id == "DS002"
        assert findings[0].severity == Severity.HIGH
        assert "resolution" in findings[0].extra

    def test_parse_empty_results(self) -> None:
        scanner = TrivyScanner()
        findings = scanner.parse('{"Results": []}')
        assert findings == []

    def test_scanner_properties(self) -> None:
        scanner = TrivyScanner()
        assert scanner.name == "trivy"
        assert scanner.scan_type == "Trivy Scan"
