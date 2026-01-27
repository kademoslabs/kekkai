"""Audit logging for enterprise portal.

Security controls:
- ASVS V16.3.1: Log auth events
- Log integrity protection (append-only, hash chain)
- Structured JSON format
- Redaction of sensitive fields
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from kekkai_core import redact

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

SENSITIVE_FIELDS = frozenset(
    {
        "password",
        "api_key",
        "token",
        "secret",
        "authorization",
        "cookie",
        "session_id",
        "credentials",
    }
)


class AuditEventType(Enum):
    """Types of auditable events."""

    # Authentication events
    AUTH_LOGIN_SUCCESS = "auth.login.success"
    AUTH_LOGIN_FAILURE = "auth.login.failure"
    AUTH_LOGOUT = "auth.logout"
    AUTH_SESSION_EXPIRED = "auth.session.expired"
    AUTH_SAML_ASSERTION = "auth.saml.assertion"
    AUTH_SAML_REPLAY_BLOCKED = "auth.saml.replay_blocked"

    # Authorization events
    AUTHZ_DENIED = "authz.denied"
    AUTHZ_CROSS_TENANT = "authz.cross_tenant"

    # Admin actions
    ADMIN_USER_CREATED = "admin.user.created"
    ADMIN_USER_UPDATED = "admin.user.updated"
    ADMIN_USER_DELETED = "admin.user.deleted"
    ADMIN_ROLE_CHANGED = "admin.role.changed"
    ADMIN_TENANT_CREATED = "admin.tenant.created"
    ADMIN_TENANT_UPDATED = "admin.tenant.updated"
    ADMIN_TENANT_DELETED = "admin.tenant.deleted"
    ADMIN_API_KEY_ROTATED = "admin.api_key.rotated"
    ADMIN_SAML_CONFIG_UPDATED = "admin.saml_config.updated"

    # Data access events
    DATA_UPLOAD = "data.upload"
    DATA_EXPORT = "data.export"
    DATA_DELETE = "data.delete"

    # System events
    SYSTEM_LICENSE_CHECK = "system.license.check"
    SYSTEM_LICENSE_EXPIRED = "system.license.expired"


@dataclass
class AuditEvent:
    """Represents an auditable event."""

    event_type: AuditEventType
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    actor_id: str | None = None
    actor_email: str | None = None
    tenant_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    action: str | None = None
    outcome: str = "success"
    client_ip: str | None = None
    user_agent: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(
        default_factory=lambda: f"{int(time.time() * 1000)}-{os.urandom(4).hex()}"
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data["event_type"] = self.event_type.value
        data["timestamp"] = self.timestamp.isoformat()
        data["details"] = _redact_sensitive(self.details)
        if self.client_ip:
            data["client_ip"] = redact(self.client_ip)
        return data

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))


class AuditLog:
    """Append-only audit log with integrity protection."""

    def __init__(
        self,
        log_path: Path | None = None,
        enable_hash_chain: bool = True,
    ) -> None:
        self._log_path = log_path
        self._enable_hash_chain = enable_hash_chain
        self._last_hash: str | None = None
        self._lock = threading.Lock()
        self._load_last_hash()

    def _load_last_hash(self) -> None:
        """Load the last hash from existing log for chain continuity."""
        if not self._log_path or not self._log_path.exists():
            self._last_hash = "0" * 64
            return

        try:
            with open(self._log_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size == 0:
                    self._last_hash = "0" * 64
                    return

                chunk_size = min(4096, size)
                f.seek(-chunk_size, 2)
                last_chunk = f.read()
                lines = last_chunk.split(b"\n")
                for line in reversed(lines):
                    if line.strip():
                        try:
                            entry = json.loads(line)
                            self._last_hash = entry.get("_hash", "0" * 64)
                            return
                        except json.JSONDecodeError:
                            continue
        except OSError as e:
            logger.warning("Failed to load last hash: %s", e)

        self._last_hash = "0" * 64

    def _compute_hash(self, event_json: str) -> str:
        """Compute hash for integrity chain."""
        data = f"{self._last_hash}:{event_json}"
        return hashlib.sha256(data.encode()).hexdigest()

    def log(self, event: AuditEvent) -> str:
        """Log an audit event.

        Returns:
            The event ID
        """
        with self._lock:
            event_data = event.to_dict()
            event_json = json.dumps(event_data, separators=(",", ":"))

            if self._enable_hash_chain:
                event_hash = self._compute_hash(event_json)
                event_data["_hash"] = event_hash
                event_data["_prev_hash"] = self._last_hash
                self._last_hash = event_hash
                event_json = json.dumps(event_data, separators=(",", ":"))

            if self._log_path:
                self._write_to_file(event_json)

            logger.info("audit.event %s", event_json)
            return event.event_id

    def _write_to_file(self, event_json: str) -> None:
        """Write event to log file (append-only)."""
        if not self._log_path:
            return
        try:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(event_json + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            logger.error("Failed to write audit log: %s", e)

    def log_auth_success(
        self,
        user_id: str,
        tenant_id: str,
        client_ip: str | None = None,
        auth_method: str = "api_key",
        **details: Any,
    ) -> str:
        """Log successful authentication."""
        return self.log(
            AuditEvent(
                event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
                actor_id=user_id,
                tenant_id=tenant_id,
                client_ip=client_ip,
                action="login",
                outcome="success",
                details={"auth_method": auth_method, **details},
            )
        )

    def log_auth_failure(
        self,
        reason: str,
        client_ip: str | None = None,
        attempted_user: str | None = None,
        **details: Any,
    ) -> str:
        """Log failed authentication attempt."""
        return self.log(
            AuditEvent(
                event_type=AuditEventType.AUTH_LOGIN_FAILURE,
                actor_id=attempted_user,
                client_ip=client_ip,
                action="login",
                outcome="failure",
                details={"reason": reason, **details},
            )
        )

    def log_authz_denied(
        self,
        user_id: str,
        tenant_id: str,
        permission: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        client_ip: str | None = None,
        **details: Any,
    ) -> str:
        """Log authorization denial (ASVS V16.3.2)."""
        return self.log(
            AuditEvent(
                event_type=AuditEventType.AUTHZ_DENIED,
                actor_id=user_id,
                tenant_id=tenant_id,
                resource_type=resource_type,
                resource_id=resource_id,
                client_ip=client_ip,
                action=permission,
                outcome="denied",
                details=details,
            )
        )

    def log_admin_action(
        self,
        event_type: AuditEventType,
        admin_id: str,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        client_ip: str | None = None,
        **details: Any,
    ) -> str:
        """Log an administrative action."""
        return self.log(
            AuditEvent(
                event_type=event_type,
                actor_id=admin_id,
                tenant_id=tenant_id,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action,
                client_ip=client_ip,
                details=details,
            )
        )

    def log_saml_replay_blocked(
        self,
        assertion_id: str,
        client_ip: str | None = None,
        **details: Any,
    ) -> str:
        """Log blocked SAML replay attempt."""
        return self.log(
            AuditEvent(
                event_type=AuditEventType.AUTH_SAML_REPLAY_BLOCKED,
                client_ip=client_ip,
                action="saml_replay",
                outcome="blocked",
                details={"assertion_id": assertion_id, **details},
            )
        )

    def verify_integrity(self, start_line: int = 0) -> tuple[bool, int, str | None]:
        """Verify the integrity of the audit log.

        Returns:
            Tuple of (is_valid, lines_checked, error_message)
        """
        if not self._log_path or not self._log_path.exists():
            return True, 0, None

        try:
            with open(self._log_path, encoding="utf-8") as f:
                lines = f.readlines()

            if not lines:
                return True, 0, None

            prev_hash = "0" * 64
            for i, line in enumerate(lines[start_line:], start=start_line):
                if not line.strip():
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    return False, i, f"Invalid JSON at line {i}: {e}"

                if "_hash" not in entry:
                    continue

                stored_prev = entry.get("_prev_hash", "0" * 64)
                if stored_prev != prev_hash:
                    return False, i, f"Hash chain broken at line {i}"

                entry_copy = {k: v for k, v in entry.items() if not k.startswith("_")}
                event_json = json.dumps(entry_copy, separators=(",", ":"))
                expected_hash = hashlib.sha256(f"{prev_hash}:{event_json}".encode()).hexdigest()

                if entry["_hash"] != expected_hash:
                    return False, i, f"Hash mismatch at line {i}"

                prev_hash = entry["_hash"]

            return True, len(lines), None

        except OSError as e:
            return False, 0, f"Failed to read log: {e}"

    def read_events(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        event_types: list[AuditEventType] | None = None,
        tenant_id: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Read audit events with optional filtering."""
        if not self._log_path or not self._log_path.exists():
            return []

        events = []
        type_values = {et.value for et in event_types} if event_types else None

        try:
            with open(self._log_path, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue

                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if type_values and entry.get("event_type") not in type_values:
                        continue

                    if tenant_id and entry.get("tenant_id") != tenant_id:
                        continue

                    if start_time or end_time:
                        ts_str = entry.get("timestamp")
                        if ts_str:
                            ts = datetime.fromisoformat(ts_str)
                            if start_time and ts < start_time:
                                continue
                            if end_time and ts > end_time:
                                continue

                    events.append(entry)
                    if len(events) >= limit:
                        break

        except OSError as e:
            logger.error("Failed to read audit log: %s", e)

        return events


def _redact_sensitive(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact sensitive fields in a dictionary."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        lower_key = key.lower()
        if any(s in lower_key for s in SENSITIVE_FIELDS):
            result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            result[key] = _redact_sensitive(value)
        elif isinstance(value, list):
            redacted_list: list[Any] = [
                _redact_sensitive(v) if isinstance(v, dict) else v for v in value
            ]
            result[key] = redacted_list
        else:
            result[key] = value
    return result


def create_audit_log(log_dir: Path | None = None) -> AuditLog:
    """Create an audit log instance."""
    log_path: Path | None
    if log_dir:
        log_path = log_dir / "audit.jsonl"
    else:
        default_dir = os.environ.get("PORTAL_AUDIT_DIR")
        log_path = Path(default_dir) / "audit.jsonl" if default_dir else None

    return AuditLog(log_path=log_path)
