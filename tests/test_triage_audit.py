"""Unit tests for triage audit logging."""

from __future__ import annotations

import json
from pathlib import Path

from kekkai.triage.audit import AuditEntry, TriageAuditLog, log_decisions
from kekkai.triage.models import TriageDecision, TriageState


class TestAuditEntry:
    """Tests for audit entry records."""

    def test_entry_has_timestamp(self) -> None:
        entry = AuditEntry(
            action="test_action",
            finding_id="test-123",
        )
        assert entry.timestamp
        assert "T" in entry.timestamp  # ISO format

    def test_entry_to_dict(self) -> None:
        entry = AuditEntry(
            action="mark_false_positive",
            finding_id="CVE-2024-1234",
            user="testuser",
            details={"reason": "Test reason"},
        )
        data = entry.to_dict()

        assert data["action"] == "mark_false_positive"
        assert data["finding_id"] == "CVE-2024-1234"
        assert data["user"] == "testuser"
        details = data["details"]
        assert isinstance(details, dict)
        assert details["reason"] == "Test reason"

    def test_entry_to_json(self) -> None:
        entry = AuditEntry(
            action="test",
            finding_id="test-1",
        )
        json_str = entry.to_json()

        parsed = json.loads(json_str)
        assert parsed["action"] == "test"
        assert parsed["finding_id"] == "test-1"

    def test_entry_from_dict(self) -> None:
        data: dict[str, str | dict[str, str]] = {
            "timestamp": "2024-01-01T00:00:00Z",
            "action": "triage_confirmed",
            "finding_id": "CVE-123",
            "user": "admin",
            "details": {"severity": "high"},
        }
        entry = AuditEntry.from_dict(data)

        assert entry.timestamp == "2024-01-01T00:00:00Z"
        assert entry.action == "triage_confirmed"
        assert entry.user == "admin"
        assert entry.details["severity"] == "high"


class TestTriageAuditLog:
    """Tests for audit log file operations."""

    def test_log_creates_file(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit_log = TriageAuditLog(log_path)

        entry = AuditEntry(action="test", finding_id="test-1")
        audit_log.log(entry)

        assert log_path.exists()

    def test_log_appends_entries(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit_log = TriageAuditLog(log_path)

        audit_log.log(AuditEntry(action="action1", finding_id="f1"))
        audit_log.log(AuditEntry(action="action2", finding_id="f2"))

        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_log_decision(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit_log = TriageAuditLog(log_path)

        decision = TriageDecision(
            finding_id="CVE-2024-1234",
            state=TriageState.FALSE_POSITIVE,
            reason="Test false positive",
            ignore_pattern="trivy:CVE-2024-1234",
        )
        audit_log.log_decision(decision)

        entries = audit_log.read_all()
        assert len(entries) == 1
        assert entries[0].action == "triage_false_positive"
        assert entries[0].finding_id == "CVE-2024-1234"
        assert entries[0].details["reason"] == "Test false positive"

    def test_log_action(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit_log = TriageAuditLog(log_path)

        audit_log.log_action(
            action="save_ignore_file",
            finding_id="*",
            details={"count": "5"},
        )

        entries = audit_log.read_all()
        assert len(entries) == 1
        assert entries[0].action == "save_ignore_file"

    def test_read_all_empty_file(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit_log = TriageAuditLog(log_path)

        entries = audit_log.read_all()
        assert entries == []

    def test_read_all_skips_invalid_json(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        valid_entry = '{"valid": "entry", "action": "test", "finding_id": "1"}\n'
        log_path.write_text(valid_entry + "invalid json\n")

        audit_log = TriageAuditLog(log_path)
        entries = audit_log.read_all()
        assert len(entries) == 1

    def test_read_for_finding(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit_log = TriageAuditLog(log_path)

        audit_log.log(AuditEntry(action="a1", finding_id="f1"))
        audit_log.log(AuditEntry(action="a2", finding_id="f2"))
        audit_log.log(AuditEntry(action="a3", finding_id="f1"))

        entries = audit_log.read_for_finding("f1")
        assert len(entries) == 2
        assert all(e.finding_id == "f1" for e in entries)

    def test_get_recent(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        audit_log = TriageAuditLog(log_path)

        for i in range(10):
            audit_log.log(AuditEntry(action=f"action{i}", finding_id=f"f{i}"))

        recent = audit_log.get_recent(5)
        assert len(recent) == 5
        assert recent[-1].action == "action9"

    def test_creates_parent_directory(self, tmp_path: Path) -> None:
        log_path = tmp_path / "nested" / "dir" / "audit.jsonl"
        audit_log = TriageAuditLog(log_path)

        audit_log.log(AuditEntry(action="test", finding_id="test"))
        assert log_path.exists()


class TestLogDecisions:
    """Tests for batch decision logging."""

    def test_log_multiple_decisions(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"

        decisions = [
            TriageDecision(finding_id="f1", state=TriageState.FALSE_POSITIVE),
            TriageDecision(finding_id="f2", state=TriageState.CONFIRMED),
            TriageDecision(finding_id="f3", state=TriageState.DEFERRED),
        ]

        log_decisions(decisions, log_path)

        audit_log = TriageAuditLog(log_path)
        entries = audit_log.read_all()
        assert len(entries) == 3
