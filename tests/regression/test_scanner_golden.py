from __future__ import annotations

import json
from pathlib import Path

import pytest

from kekkai.scanners.gitleaks import GitleaksScanner
from kekkai.scanners.semgrep import SemgrepScanner
from kekkai.scanners.trivy import TrivyScanner

FIXTURES_DIR = Path(__file__).parent / "scanners"


@pytest.mark.regression
class TestTrivyGolden:
    def test_parse_golden_output(self) -> None:
        scanner = TrivyScanner()
        raw = (FIXTURES_DIR / "trivy_output.json").read_text()
        expected = json.loads((FIXTURES_DIR / "expected_findings.json").read_text())["trivy"]

        findings = scanner.parse(raw)

        assert len(findings) == expected["count"]
        severities = [f.severity.value for f in findings]
        assert severities == expected["severities"]

        if expected["has_cve"]:
            assert any(f.cve for f in findings)
        if expected["has_misconfig"]:
            assert any(f.rule_id for f in findings)


@pytest.mark.regression
class TestSemgrepGolden:
    def test_parse_golden_output(self) -> None:
        scanner = SemgrepScanner()
        raw = (FIXTURES_DIR / "semgrep_output.json").read_text()
        expected = json.loads((FIXTURES_DIR / "expected_findings.json").read_text())["semgrep"]

        findings = scanner.parse(raw)

        assert len(findings) == expected["count"]
        severities = [f.severity.value for f in findings]
        assert severities == expected["severities"]

        if expected["has_cwe"]:
            assert any(f.cwe for f in findings)


@pytest.mark.regression
class TestGitleaksGolden:
    def test_parse_golden_output(self) -> None:
        scanner = GitleaksScanner()
        raw = (FIXTURES_DIR / "gitleaks_output.json").read_text()
        expected = json.loads((FIXTURES_DIR / "expected_findings.json").read_text())["gitleaks"]

        findings = scanner.parse(raw)

        assert len(findings) == expected["count"]
        severities = [f.severity.value for f in findings]
        assert severities == expected["severities"]

        if expected["secrets_redacted"]:
            raw_data = json.loads(raw)
            for finding, leak in zip(findings, raw_data, strict=False):
                secret = leak.get("Match", "")
                if len(secret) > 10:
                    assert secret not in finding.description
