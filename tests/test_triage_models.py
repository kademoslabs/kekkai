"""Unit tests for triage data models."""

from __future__ import annotations

import pytest

from kekkai.triage.models import (
    FindingEntry,
    Severity,
    TriageDecision,
    TriageState,
    load_findings_from_json,
)


class TestTriageState:
    """Tests for triage state enum."""

    def test_state_values(self) -> None:
        assert TriageState.PENDING.value == "pending"
        assert TriageState.FALSE_POSITIVE.value == "false_positive"
        assert TriageState.CONFIRMED.value == "confirmed"
        assert TriageState.DEFERRED.value == "deferred"

    def test_state_from_string(self) -> None:
        assert TriageState("pending") == TriageState.PENDING
        assert TriageState("false_positive") == TriageState.FALSE_POSITIVE


class TestSeverity:
    """Tests for severity enum."""

    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


class TestTriageDecision:
    """Tests for triage decision records."""

    def test_decision_is_immutable(self) -> None:
        decision = TriageDecision(
            finding_id="CVE-2024-1234",
            state=TriageState.FALSE_POSITIVE,
        )
        with pytest.raises(AttributeError):
            decision.finding_id = "changed"  # type: ignore[misc]

    def test_decision_to_dict(self) -> None:
        decision = TriageDecision(
            finding_id="CVE-2024-1234",
            state=TriageState.FALSE_POSITIVE,
            reason="Test reason",
            ignore_pattern="trivy:CVE-2024-1234",
        )
        data = decision.to_dict()

        assert data["finding_id"] == "CVE-2024-1234"
        assert data["state"] == "false_positive"
        assert data["reason"] == "Test reason"
        assert data["ignore_pattern"] == "trivy:CVE-2024-1234"

    def test_decision_from_dict(self) -> None:
        data = {
            "finding_id": "CVE-2024-1234",
            "state": "confirmed",
            "reason": "Real vulnerability",
            "timestamp": "2024-01-01T00:00:00Z",
            "user": "testuser",
            "ignore_pattern": None,
        }
        decision = TriageDecision.from_dict(data)

        assert decision.finding_id == "CVE-2024-1234"
        assert decision.state == TriageState.CONFIRMED
        assert decision.reason == "Real vulnerability"
        assert decision.user == "testuser"

    def test_decision_has_timestamp(self) -> None:
        decision = TriageDecision(
            finding_id="test",
            state=TriageState.PENDING,
        )
        assert decision.timestamp
        assert "T" in decision.timestamp  # ISO format


class TestFindingEntry:
    """Tests for finding entry model."""

    def test_finding_defaults(self) -> None:
        finding = FindingEntry(
            id="test-1",
            title="Test Finding",
            severity=Severity.HIGH,
            scanner="trivy",
        )
        assert finding.state == TriageState.PENDING
        assert finding.notes == ""
        assert finding.file_path == ""

    def test_finding_to_dict(self) -> None:
        finding = FindingEntry(
            id="test-1",
            title="Test Finding",
            severity=Severity.CRITICAL,
            scanner="semgrep",
            file_path="src/main.py",
            line=42,
            rule_id="python.security.eval",
        )
        data = finding.to_dict()

        assert data["id"] == "test-1"
        assert data["severity"] == "critical"
        assert data["scanner"] == "semgrep"
        assert data["line"] == 42

    def test_finding_from_dict(self) -> None:
        data: dict[str, str | int | None] = {
            "id": "test-1",
            "title": "SQL Injection",
            "severity": "high",
            "scanner": "semgrep",
            "file_path": "app.py",
            "line": 100,
            "description": "Potential SQL injection",
            "rule_id": "python.sql.injection",
        }
        finding = FindingEntry.from_dict(data)

        assert finding.id == "test-1"
        assert finding.severity == Severity.HIGH
        assert finding.line == 100
        assert finding.state == TriageState.PENDING

    def test_finding_from_dict_unknown_severity(self) -> None:
        data: dict[str, str | int | None] = {
            "id": "test-1",
            "title": "Test",
            "severity": "unknown",
            "scanner": "test",
        }
        finding = FindingEntry.from_dict(data)
        assert finding.severity == Severity.INFO

    def test_finding_from_dict_unknown_state(self) -> None:
        data: dict[str, str | int | None] = {
            "id": "test-1",
            "title": "Test",
            "severity": "high",
            "scanner": "test",
            "state": "invalid_state",
        }
        finding = FindingEntry.from_dict(data)
        assert finding.state == TriageState.PENDING

    def test_generate_ignore_pattern_full(self) -> None:
        finding = FindingEntry(
            id="test-1",
            title="Test",
            severity=Severity.HIGH,
            scanner="trivy",
            rule_id="CVE-2024-1234",
            file_path="src/main.py",
        )
        pattern = finding.generate_ignore_pattern()
        assert pattern == "trivy:CVE-2024-1234:src/main.py"

    def test_generate_ignore_pattern_no_file(self) -> None:
        finding = FindingEntry(
            id="test-1",
            title="Test",
            severity=Severity.HIGH,
            scanner="trivy",
            rule_id="CVE-2024-1234",
        )
        pattern = finding.generate_ignore_pattern()
        assert pattern == "trivy:CVE-2024-1234"

    def test_generate_ignore_pattern_scanner_only(self) -> None:
        finding = FindingEntry(
            id="test-1",
            title="Test",
            severity=Severity.HIGH,
            scanner="gitleaks",
        )
        pattern = finding.generate_ignore_pattern()
        assert pattern == "gitleaks"


class TestLoadFindingsFromJson:
    """Tests for JSON loading utility."""

    def test_load_empty_list(self) -> None:
        findings = load_findings_from_json([])
        assert findings == []

    def test_load_multiple_findings(self) -> None:
        data: list[dict[str, str | int | None]] = [
            {
                "id": "1",
                "title": "Finding 1",
                "severity": "high",
                "scanner": "trivy",
            },
            {
                "id": "2",
                "title": "Finding 2",
                "severity": "low",
                "scanner": "semgrep",
            },
        ]
        findings = load_findings_from_json(data)

        assert len(findings) == 2
        assert findings[0].id == "1"
        assert findings[1].severity == Severity.LOW

    def test_load_preserves_order(self) -> None:
        data: list[dict[str, str | int | None]] = [
            {"id": f"finding-{i}", "title": f"F{i}", "severity": "info", "scanner": "test"}
            for i in range(10)
        ]
        findings = load_findings_from_json(data)

        for i, finding in enumerate(findings):
            assert finding.id == f"finding-{i}"
