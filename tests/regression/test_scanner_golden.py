from __future__ import annotations

import json
from pathlib import Path

import pytest

from kekkai.scanners.falco import FalcoScanner
from kekkai.scanners.gitleaks import GitleaksScanner
from kekkai.scanners.semgrep import SemgrepScanner
from kekkai.scanners.trivy import TrivyScanner
from kekkai.scanners.zap import ZapScanner

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


@pytest.mark.regression
class TestZapGolden:
    """Golden tests for ZAP scanner parser."""

    def test_parse_golden_output(self) -> None:
        scanner = ZapScanner()
        raw = (FIXTURES_DIR / "zap-baseline.json").read_text()

        findings = scanner.parse(raw)

        # Should parse 3 alerts from the golden fixture
        assert len(findings) == 3

        # Check severities match expected risk codes
        severities = [f.severity.value for f in findings]
        assert severities == ["medium", "low", "info"]

        # Check CWE mapping
        csp_finding = findings[0]
        assert csp_finding.cwe == "CWE-693"
        assert csp_finding.rule_id == "10038"

    def test_dedupe_hash_deterministic(self) -> None:
        scanner = ZapScanner()
        raw = (FIXTURES_DIR / "zap-baseline.json").read_text()

        findings1 = scanner.parse(raw)
        findings2 = scanner.parse(raw)

        for f1, f2 in zip(findings1, findings2, strict=True):
            assert f1.dedupe_hash() == f2.dedupe_hash()


@pytest.mark.regression
class TestFalcoGolden:
    """Golden tests for Falco scanner parser."""

    def test_parse_golden_output(self) -> None:
        scanner = FalcoScanner(enabled=True)
        raw = (FIXTURES_DIR / "falco-alerts.json").read_text()

        findings = scanner.parse(raw)

        # Should parse 4 alerts from the golden fixture
        assert len(findings) == 4

        # Check severities match expected priorities
        severities = [f.severity.value for f in findings]
        assert severities == ["low", "high", "medium", "low"]  # Notice, Error, Warning, Notice

        # Check rule extraction
        rules = [f.title for f in findings]
        assert "Terminal shell in container" in rules
        assert "Write below etc" in rules

    def test_container_info_extracted(self) -> None:
        scanner = FalcoScanner(enabled=True)
        raw = (FIXTURES_DIR / "falco-alerts.json").read_text()

        findings = scanner.parse(raw)

        # First finding should have container info
        first = findings[0]
        assert first.extra["container_name"] == "web-app"
        assert first.extra["container_id"] == "abc123"

    def test_dedupe_hash_deterministic(self) -> None:
        scanner = FalcoScanner(enabled=True)
        raw = (FIXTURES_DIR / "falco-alerts.json").read_text()

        findings1 = scanner.parse(raw)
        findings2 = scanner.parse(raw)

        for f1, f2 in zip(findings1, findings2, strict=True):
            assert f1.dedupe_hash() == f2.dedupe_hash()
