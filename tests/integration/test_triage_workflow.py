"""Integration tests for triage TUI workflow."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kekkai.triage import (
    FindingEntry,
    IgnoreFile,
    Severity,
    TriageApp,
    TriageAuditLog,
    TriageState,
)


@pytest.fixture
def sample_findings() -> list[FindingEntry]:
    """Create sample findings for testing."""
    return [
        FindingEntry(
            id="CVE-2024-1234",
            title="Critical vulnerability in dependency",
            severity=Severity.CRITICAL,
            scanner="trivy",
            file_path="requirements.txt",
            line=5,
            description="A critical vulnerability was found.",
            rule_id="CVE-2024-1234",
        ),
        FindingEntry(
            id="SEMGREP-001",
            title="SQL Injection vulnerability",
            severity=Severity.HIGH,
            scanner="semgrep",
            file_path="src/db.py",
            line=42,
            description="Potential SQL injection in query construction.",
            rule_id="python.sql.injection",
        ),
        FindingEntry(
            id="GITLEAKS-001",
            title="API Key detected",
            severity=Severity.MEDIUM,
            scanner="gitleaks",
            file_path="config/settings.py",
            line=10,
            description="Hardcoded API key detected.",
            rule_id="generic-api-key",
        ),
    ]


@pytest.fixture
def findings_json_file(tmp_path: Path, sample_findings: list[FindingEntry]) -> Path:
    """Create a findings JSON file for testing."""
    json_path = tmp_path / "findings.json"
    data = [f.to_dict() for f in sample_findings]
    json_path.write_text(json.dumps(data))
    return json_path


@pytest.mark.integration
class TestTriageAppInitialization:
    """Tests for triage app initialization."""

    def test_app_loads_findings_from_file(self, tmp_path: Path, findings_json_file: Path) -> None:
        app = TriageApp(input_path=findings_json_file)
        assert len(app.findings) == 3

    def test_app_accepts_preloaded_findings(self, sample_findings: list[FindingEntry]) -> None:
        app = TriageApp(findings=sample_findings)
        assert len(app.findings) == 3

    def test_app_creates_ignore_file_manager(self, tmp_path: Path) -> None:
        output_path = tmp_path / ".kekkaiignore"
        app = TriageApp(output_path=output_path)
        assert app.ignore_file.path == output_path

    def test_app_creates_audit_log(self, tmp_path: Path) -> None:
        audit_path = tmp_path / "audit.jsonl"
        app = TriageApp(audit_path=audit_path)
        assert app.audit_log.path == audit_path


@pytest.mark.integration
class TestTriageStateManagement:
    """Tests for triage state management."""

    def test_state_change_updates_finding(
        self, sample_findings: list[FindingEntry], tmp_path: Path
    ) -> None:
        app = TriageApp(
            findings=sample_findings,
            output_path=tmp_path / ".kekkaiignore",
            audit_path=tmp_path / "audit.jsonl",
        )

        app._handle_state_change(0, TriageState.FALSE_POSITIVE)

        # App creates internal copy, check via decisions
        assert "CVE-2024-1234" in app._decisions
        assert app._decisions["CVE-2024-1234"].state == TriageState.FALSE_POSITIVE

    def test_state_change_creates_audit_entry(
        self, sample_findings: list[FindingEntry], tmp_path: Path
    ) -> None:
        audit_path = tmp_path / "audit.jsonl"
        app = TriageApp(
            findings=sample_findings,
            audit_path=audit_path,
        )

        app._handle_state_change(0, TriageState.CONFIRMED)

        entries = TriageAuditLog(audit_path).read_all()
        assert len(entries) == 1
        assert entries[0].action == "triage_confirmed"

    def test_false_positive_generates_ignore_pattern(
        self, sample_findings: list[FindingEntry], tmp_path: Path
    ) -> None:
        app = TriageApp(
            findings=sample_findings,
            output_path=tmp_path / ".kekkaiignore",
            audit_path=tmp_path / "audit.jsonl",
        )

        app._handle_state_change(0, TriageState.FALSE_POSITIVE)

        assert "CVE-2024-1234" in app._decisions
        decision = app._decisions["CVE-2024-1234"]
        assert decision.ignore_pattern == "trivy:CVE-2024-1234:requirements.txt"


@pytest.mark.integration
class TestTriageSaveWorkflow:
    """Tests for saving triage results."""

    def test_save_creates_ignore_file(
        self, sample_findings: list[FindingEntry], tmp_path: Path
    ) -> None:
        output_path = tmp_path / ".kekkaiignore"
        app = TriageApp(
            findings=sample_findings,
            output_path=output_path,
            audit_path=tmp_path / "audit.jsonl",
        )

        sample_findings[0].state = TriageState.FALSE_POSITIVE
        sample_findings[1].state = TriageState.FALSE_POSITIVE

        app._handle_save()

        assert output_path.exists()
        content = output_path.read_text()
        assert "trivy:CVE-2024-1234" in content
        assert "semgrep:python.sql.injection" in content

    def test_save_skips_non_false_positives(
        self, sample_findings: list[FindingEntry], tmp_path: Path
    ) -> None:
        output_path = tmp_path / ".kekkaiignore"
        app = TriageApp(
            findings=sample_findings,
            output_path=output_path,
            audit_path=tmp_path / "audit.jsonl",
        )

        sample_findings[0].state = TriageState.FALSE_POSITIVE
        sample_findings[1].state = TriageState.CONFIRMED
        sample_findings[2].state = TriageState.DEFERRED

        app._handle_save()

        content = output_path.read_text()
        assert "trivy:CVE-2024-1234" in content
        assert "semgrep" not in content
        assert "gitleaks" not in content

    def test_save_logs_action(self, sample_findings: list[FindingEntry], tmp_path: Path) -> None:
        audit_path = tmp_path / "audit.jsonl"
        app = TriageApp(
            findings=sample_findings,
            output_path=tmp_path / ".kekkaiignore",
            audit_path=audit_path,
        )

        app._handle_save()

        entries = TriageAuditLog(audit_path).read_all()
        assert any(e.action == "save_ignore_file" for e in entries)


@pytest.mark.integration
class TestTriageIgnoreFileIntegration:
    """Tests for ignore file integration."""

    def test_existing_ignore_file_preserved(
        self, sample_findings: list[FindingEntry], tmp_path: Path
    ) -> None:
        output_path = tmp_path / ".kekkaiignore"
        output_path.write_text("existing:pattern\n")

        app = TriageApp(
            findings=sample_findings,
            output_path=output_path,
            audit_path=tmp_path / "audit.jsonl",
        )

        sample_findings[0].state = TriageState.FALSE_POSITIVE
        app._handle_save()

        content = output_path.read_text()
        assert "existing:pattern" in content
        assert "trivy:CVE-2024-1234" in content

    def test_duplicate_patterns_not_added(
        self, sample_findings: list[FindingEntry], tmp_path: Path
    ) -> None:
        output_path = tmp_path / ".kekkaiignore"
        output_path.write_text("trivy:CVE-2024-1234:requirements.txt\n")

        app = TriageApp(
            findings=sample_findings,
            output_path=output_path,
            audit_path=tmp_path / "audit.jsonl",
        )

        sample_findings[0].state = TriageState.FALSE_POSITIVE
        app._handle_save()

        content = output_path.read_text()
        pattern = "trivy:CVE-2024-1234:requirements.txt"
        assert content.count(pattern) == 1


@pytest.mark.integration
class TestTriageLargeInput:
    """Performance tests for large finding sets."""

    def test_handles_large_finding_set(self, tmp_path: Path) -> None:
        findings = [
            FindingEntry(
                id=f"finding-{i}",
                title=f"Finding {i}",
                severity=Severity.MEDIUM,
                scanner="test",
                file_path=f"src/file{i}.py",
                rule_id=f"rule-{i}",
            )
            for i in range(1000)
        ]

        app = TriageApp(
            findings=findings,
            output_path=tmp_path / ".kekkaiignore",
            audit_path=tmp_path / "audit.jsonl",
        )

        assert len(app.findings) == 1000

        # Mark findings as false positive via the app's internal list
        for i in range(100):
            app.findings[i].state = TriageState.FALSE_POSITIVE
            app._handle_state_change(i, TriageState.FALSE_POSITIVE)

        app._handle_save()

        ignore_file = IgnoreFile(tmp_path / ".kekkaiignore")
        entries = ignore_file.load()
        assert len(entries) == 100
