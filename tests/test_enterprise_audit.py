"""Unit tests for enterprise audit logging module."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Generator
from datetime import UTC
from pathlib import Path

import pytest

from portal.enterprise.audit import (
    AuditEvent,
    AuditEventType,
    AuditLog,
    _redact_sensitive,
)


class TestAuditEvent:
    """Tests for AuditEvent dataclass."""

    def test_event_to_dict_includes_type(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
            actor_id="user1",
            tenant_id="tenant_a",
        )
        data = event.to_dict()
        assert data["event_type"] == "auth.login.success"
        assert data["actor_id"] == "user1"
        assert data["tenant_id"] == "tenant_a"

    def test_event_to_dict_includes_client_ip(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
            client_ip="192.168.1.100",
        )
        data = event.to_dict()
        assert "client_ip" in data
        assert data["client_ip"] is not None

    def test_event_to_json_serializable(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.AUTH_LOGIN_FAILURE,
            details={"reason": "invalid_token"},
        )
        json_str = event.to_json()
        parsed = json.loads(json_str)
        assert parsed["event_type"] == "auth.login.failure"
        assert parsed["details"]["reason"] == "invalid_token"

    def test_event_has_unique_id(self) -> None:
        event1 = AuditEvent(event_type=AuditEventType.AUTH_LOGIN_SUCCESS)
        event2 = AuditEvent(event_type=AuditEventType.AUTH_LOGIN_SUCCESS)
        assert event1.event_id != event2.event_id

    def test_event_timestamp_is_utc(self) -> None:
        event = AuditEvent(event_type=AuditEventType.AUTH_LOGIN_SUCCESS)
        assert event.timestamp.tzinfo == UTC


class TestRedactSensitive:
    """Tests for sensitive field redaction."""

    def test_redacts_password_field(self) -> None:
        data = {"username": "test", "password": "FAKE_TEST_VALUE"}
        result = _redact_sensitive(data)
        assert result["username"] == "test"
        assert result["password"] == "[REDACTED]"

    def test_redacts_api_key_field(self) -> None:
        data = {"api_key": "FAKE_TEST_KEY"}
        result = _redact_sensitive(data)
        assert result["api_key"] == "[REDACTED]"

    def test_redacts_nested_secrets(self) -> None:
        data = {
            "config": {
                "api_token": "FAKE_TEST_TOKEN",
                "endpoint": "https://example.com",
            }
        }
        result = _redact_sensitive(data)
        assert result["config"]["api_token"] == "[REDACTED]"
        assert result["config"]["endpoint"] == "https://example.com"

    def test_redacts_in_list(self) -> None:
        data = {
            "items": [
                {"secret_key": "abc"},
                {"value": "ok"},
            ]
        }
        result = _redact_sensitive(data)
        assert result["items"][0]["secret_key"] == "[REDACTED]"
        assert result["items"][1]["value"] == "ok"

    def test_preserves_non_sensitive_fields(self) -> None:
        data = {"user_id": "123", "action": "login"}
        result = _redact_sensitive(data)
        assert result == data


class TestAuditLog:
    """Tests for AuditLog functionality."""

    @pytest.fixture
    def temp_log_file(self) -> Generator[Path, None, None]:
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir) / "audit.jsonl"

    def test_log_writes_to_file(self, temp_log_file: Path) -> None:
        audit = AuditLog(log_path=temp_log_file)
        event = AuditEvent(
            event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
            actor_id="user1",
        )
        audit.log(event)

        assert temp_log_file.exists()
        content = temp_log_file.read_text()
        assert "auth.login.success" in content
        assert "user1" in content

    def test_log_appends_multiple_events(self, temp_log_file: Path) -> None:
        audit = AuditLog(log_path=temp_log_file)

        for i in range(3):
            event = AuditEvent(
                event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
                actor_id=f"user{i}",
            )
            audit.log(event)

        lines = temp_log_file.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_log_includes_hash_chain(self, temp_log_file: Path) -> None:
        audit = AuditLog(log_path=temp_log_file, enable_hash_chain=True)

        event1 = AuditEvent(event_type=AuditEventType.AUTH_LOGIN_SUCCESS)
        event2 = AuditEvent(event_type=AuditEventType.AUTH_LOGIN_SUCCESS)

        audit.log(event1)
        audit.log(event2)

        lines = temp_log_file.read_text().strip().split("\n")
        entry1 = json.loads(lines[0])
        entry2 = json.loads(lines[1])

        assert "_hash" in entry1
        assert "_hash" in entry2
        assert entry2["_prev_hash"] == entry1["_hash"]

    def test_verify_integrity_passes_valid_log(self, temp_log_file: Path) -> None:
        audit = AuditLog(log_path=temp_log_file, enable_hash_chain=True)

        for _i in range(5):
            audit.log(AuditEvent(event_type=AuditEventType.AUTH_LOGIN_SUCCESS))

        is_valid, count, error = audit.verify_integrity()
        assert is_valid is True
        assert count == 5
        assert error is None

    def test_verify_integrity_detects_tampering(self, temp_log_file: Path) -> None:
        audit = AuditLog(log_path=temp_log_file, enable_hash_chain=True)

        for _i in range(3):
            audit.log(AuditEvent(event_type=AuditEventType.AUTH_LOGIN_SUCCESS))

        lines = temp_log_file.read_text().strip().split("\n")
        entry = json.loads(lines[1])
        entry["actor_id"] = "tampered"
        lines[1] = json.dumps(entry)
        temp_log_file.write_text("\n".join(lines) + "\n")

        audit2 = AuditLog(log_path=temp_log_file, enable_hash_chain=True)
        is_valid, line_num, error = audit2.verify_integrity()
        assert is_valid is False
        assert "Hash mismatch" in (error or "")


class TestAuditLogHelpers:
    """Tests for convenience logging methods."""

    @pytest.fixture
    def audit(self) -> AuditLog:
        return AuditLog(log_path=None)

    def test_log_auth_success(self, audit: AuditLog, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("INFO"):
            event_id = audit.log_auth_success(
                user_id="user1",
                tenant_id="tenant_a",
                client_ip="127.0.0.1",
            )

        assert event_id is not None
        assert "audit.event" in caplog.text
        assert "auth.login.success" in caplog.text

    def test_log_auth_failure(self, audit: AuditLog, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("INFO"):
            event_id = audit.log_auth_failure(
                reason="invalid_token",
                client_ip="10.0.0.1",
            )

        assert event_id is not None
        assert "auth.login.failure" in caplog.text

    def test_log_authz_denied(self, audit: AuditLog, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("INFO"):
            event_id = audit.log_authz_denied(
                user_id="user1",
                tenant_id="tenant_a",
                permission="manage_users",
            )

        assert event_id is not None
        assert "authz.denied" in caplog.text

    def test_log_admin_action(self, audit: AuditLog, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("INFO"):
            event_id = audit.log_admin_action(
                event_type=AuditEventType.ADMIN_USER_CREATED,
                admin_id="admin1",
                tenant_id="tenant_a",
                resource_type="user",
                resource_id="new_user1",
                action="create",
            )

        assert event_id is not None
        assert "admin.user.created" in caplog.text

    def test_log_saml_replay_blocked(
        self, audit: AuditLog, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("INFO"):
            event_id = audit.log_saml_replay_blocked(
                assertion_id="_assertion_123",
                client_ip="192.168.1.1",
            )

        assert event_id is not None
        assert "auth.saml.replay_blocked" in caplog.text


class TestAuditLogReading:
    """Tests for reading audit events."""

    @pytest.fixture
    def populated_log(self) -> Generator[tuple[AuditLog, Path], None, None]:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            audit = AuditLog(log_path=log_path, enable_hash_chain=False)

            audit.log_auth_success("user1", "tenant_a")
            audit.log_auth_failure("invalid_token")
            audit.log_authz_denied("user2", "tenant_b", "manage_users")

            yield audit, log_path

    def test_read_all_events(self, populated_log: tuple[AuditLog, Path]) -> None:
        audit, _ = populated_log
        events = audit.read_events()
        assert len(events) == 3

    def test_read_events_filter_by_type(self, populated_log: tuple[AuditLog, Path]) -> None:
        audit, _ = populated_log
        events = audit.read_events(event_types=[AuditEventType.AUTH_LOGIN_FAILURE])
        assert len(events) == 1
        assert events[0]["event_type"] == "auth.login.failure"

    def test_read_events_filter_by_tenant(self, populated_log: tuple[AuditLog, Path]) -> None:
        audit, _ = populated_log
        events = audit.read_events(tenant_id="tenant_a")
        assert len(events) == 1
        assert events[0]["tenant_id"] == "tenant_a"

    def test_read_events_respects_limit(self, populated_log: tuple[AuditLog, Path]) -> None:
        audit, _ = populated_log
        events = audit.read_events(limit=2)
        assert len(events) == 2
