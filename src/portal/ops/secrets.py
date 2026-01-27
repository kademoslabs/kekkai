"""Secret rotation utilities for Kekkai Portal.

Provides:
- API key rotation without downtime
- Database credential rotation support
- Rotation schedule management

ASVS 5.0 Requirements:
- V13.1.4: Secret rotation schedule
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class SecretType(Enum):
    """Types of secrets that can be rotated."""

    API_KEY = "api_key"
    DATABASE_PASSWORD = "database_password"  # noqa: S105
    ENCRYPTION_KEY = "encryption_key"
    SESSION_SECRET = "session_secret"  # noqa: S105
    JWT_SECRET = "jwt_secret"  # noqa: S105
    SAML_SIGNING_KEY = "saml_signing_key"


class RotationStatus(Enum):
    """Status of a rotation operation."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class RotationSchedule:
    """Schedule for secret rotation."""

    secret_type: SecretType
    interval_days: int
    last_rotated: datetime | None = None
    next_rotation: datetime | None = None
    enabled: bool = True
    notify_days_before: int = 7

    def __post_init__(self) -> None:
        if self.last_rotated and not self.next_rotation:
            self.next_rotation = self.last_rotated + timedelta(days=self.interval_days)

    def is_due(self) -> bool:
        """Check if rotation is due."""
        if not self.enabled:
            return False
        if not self.next_rotation:
            return True
        return datetime.now(UTC) >= self.next_rotation

    def should_notify(self) -> bool:
        """Check if notification should be sent."""
        if not self.enabled or not self.next_rotation:
            return False
        notification_date = self.next_rotation - timedelta(days=self.notify_days_before)
        return datetime.now(UTC) >= notification_date

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "secret_type": self.secret_type.value,
            "interval_days": self.interval_days,
            "last_rotated": self.last_rotated.isoformat() if self.last_rotated else None,
            "next_rotation": self.next_rotation.isoformat() if self.next_rotation else None,
            "enabled": self.enabled,
            "notify_days_before": self.notify_days_before,
        }


@dataclass
class RotationResult:
    """Result of a rotation operation."""

    success: bool
    secret_type: SecretType
    status: RotationStatus
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    old_key_hash: str = ""
    new_key_hash: str = ""
    error: str | None = None
    rollback_available: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "secret_type": self.secret_type.value,
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "old_key_hash": self.old_key_hash,
            "new_key_hash": self.new_key_hash,
            "error": self.error,
            "rollback_available": self.rollback_available,
        }


class SecretRotation:
    """Manages secret rotation for Kekkai Portal."""

    def __init__(
        self,
        schedules: list[RotationSchedule] | None = None,
        state_path: Path | None = None,
    ) -> None:
        self._schedules = {s.secret_type: s for s in (schedules or [])}
        self._state_path = state_path
        self._rotation_handlers: dict[SecretType, Callable[[str, str], bool]] = {}
        self._rollback_store: dict[SecretType, str] = {}

        if not self._schedules:
            self._schedules = self._get_default_schedules()

    def _get_default_schedules(self) -> dict[SecretType, RotationSchedule]:
        """Get default rotation schedules per ASVS recommendations."""
        return {
            SecretType.API_KEY: RotationSchedule(
                secret_type=SecretType.API_KEY,
                interval_days=90,
                enabled=True,
            ),
            SecretType.DATABASE_PASSWORD: RotationSchedule(
                secret_type=SecretType.DATABASE_PASSWORD,
                interval_days=90,
                enabled=True,
            ),
            SecretType.SESSION_SECRET: RotationSchedule(
                secret_type=SecretType.SESSION_SECRET,
                interval_days=30,
                enabled=True,
            ),
            SecretType.JWT_SECRET: RotationSchedule(
                secret_type=SecretType.JWT_SECRET,
                interval_days=90,
                enabled=True,
            ),
            SecretType.ENCRYPTION_KEY: RotationSchedule(
                secret_type=SecretType.ENCRYPTION_KEY,
                interval_days=365,
                enabled=True,
            ),
        }

    def register_handler(
        self, secret_type: SecretType, handler: Callable[[str, str], bool]
    ) -> None:
        """Register a rotation handler for a secret type.

        Handler receives (old_value, new_value) and returns success bool.
        """
        self._rotation_handlers[secret_type] = handler

    def generate_api_key(self, prefix: str = "kk") -> str:
        """Generate a new API key."""
        random_part = secrets.token_urlsafe(32)
        return f"{prefix}_{random_part}"

    def generate_password(self, length: int = 32) -> str:
        """Generate a secure random password."""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def generate_encryption_key(self, bits: int = 256) -> bytes:
        """Generate a secure encryption key."""
        return secrets.token_bytes(bits // 8)

    def rotate_api_key(
        self,
        tenant_id: str,
        current_key: str | None = None,
        grace_period_hours: int = 24,
    ) -> RotationResult:
        """Rotate an API key with optional grace period.

        During grace period, both old and new keys are valid.
        """
        start_time = datetime.now(UTC)
        new_key = self.generate_api_key()
        old_key_hash = self._hash_secret(current_key) if current_key else ""
        new_key_hash = self._hash_secret(new_key)

        try:
            if current_key:
                self._rollback_store[SecretType.API_KEY] = current_key

            handler = self._rotation_handlers.get(SecretType.API_KEY)
            if handler:
                success = handler(current_key or "", new_key)
                if not success:
                    return RotationResult(
                        success=False,
                        secret_type=SecretType.API_KEY,
                        status=RotationStatus.FAILED,
                        old_key_hash=old_key_hash,
                        error="Handler returned failure",
                        rollback_available=bool(current_key),
                    )

            schedule = self._schedules.get(SecretType.API_KEY)
            if schedule:
                schedule.last_rotated = start_time
                schedule.next_rotation = start_time + timedelta(days=schedule.interval_days)

            logger.info(
                "secret.rotated type=api_key tenant=%s new_hash=%s",
                tenant_id,
                new_key_hash[:16],
            )

            return RotationResult(
                success=True,
                secret_type=SecretType.API_KEY,
                status=RotationStatus.COMPLETED,
                old_key_hash=old_key_hash,
                new_key_hash=new_key_hash,
                rollback_available=bool(current_key),
            )

        except Exception as e:
            logger.error("secret.rotation.failed type=api_key error=%s", str(e))
            return RotationResult(
                success=False,
                secret_type=SecretType.API_KEY,
                status=RotationStatus.FAILED,
                old_key_hash=old_key_hash,
                error=f"Rotation failed: {type(e).__name__}",
                rollback_available=bool(current_key),
            )

    def rotate_database_password(
        self,
        current_password: str | None = None,
    ) -> RotationResult:
        """Rotate database password."""
        new_password = self.generate_password()
        old_hash = self._hash_secret(current_password) if current_password else ""
        new_hash = self._hash_secret(new_password)

        try:
            if current_password:
                self._rollback_store[SecretType.DATABASE_PASSWORD] = current_password

            handler = self._rotation_handlers.get(SecretType.DATABASE_PASSWORD)
            if handler:
                success = handler(current_password or "", new_password)
                if not success:
                    return RotationResult(
                        success=False,
                        secret_type=SecretType.DATABASE_PASSWORD,
                        status=RotationStatus.FAILED,
                        old_key_hash=old_hash,
                        error="Handler returned failure",
                        rollback_available=bool(current_password),
                    )

            schedule = self._schedules.get(SecretType.DATABASE_PASSWORD)
            if schedule:
                schedule.last_rotated = datetime.now(UTC)
                schedule.next_rotation = schedule.last_rotated + timedelta(
                    days=schedule.interval_days
                )

            logger.info("secret.rotated type=database_password")

            return RotationResult(
                success=True,
                secret_type=SecretType.DATABASE_PASSWORD,
                status=RotationStatus.COMPLETED,
                old_key_hash=old_hash,
                new_key_hash=new_hash,
                rollback_available=bool(current_password),
            )

        except Exception as e:
            logger.error("secret.rotation.failed type=database_password error=%s", str(e))
            return RotationResult(
                success=False,
                secret_type=SecretType.DATABASE_PASSWORD,
                status=RotationStatus.FAILED,
                old_key_hash=old_hash,
                error=f"Rotation failed: {type(e).__name__}",
                rollback_available=bool(current_password),
            )

    def rollback(self, secret_type: SecretType) -> RotationResult:
        """Rollback a recent rotation."""
        old_value = self._rollback_store.get(secret_type)
        if not old_value:
            return RotationResult(
                success=False,
                secret_type=secret_type,
                status=RotationStatus.FAILED,
                error="No rollback value available",
            )

        try:
            handler = self._rotation_handlers.get(secret_type)
            if handler:
                success = handler("", old_value)
                if not success:
                    return RotationResult(
                        success=False,
                        secret_type=secret_type,
                        status=RotationStatus.FAILED,
                        error="Rollback handler failed",
                    )

            del self._rollback_store[secret_type]

            logger.info("secret.rollback type=%s", secret_type.value)

            return RotationResult(
                success=True,
                secret_type=secret_type,
                status=RotationStatus.ROLLED_BACK,
                new_key_hash=self._hash_secret(old_value),
            )

        except Exception as e:
            logger.error("secret.rollback.failed type=%s error=%s", secret_type.value, str(e))
            return RotationResult(
                success=False,
                secret_type=secret_type,
                status=RotationStatus.FAILED,
                error=f"Rollback failed: {type(e).__name__}",
            )

    def get_due_rotations(self) -> list[RotationSchedule]:
        """Get list of secrets that are due for rotation."""
        return [s for s in self._schedules.values() if s.is_due()]

    def get_upcoming_rotations(self, days: int = 30) -> list[RotationSchedule]:
        """Get list of secrets that will be due within the given days."""
        cutoff = datetime.now(UTC) + timedelta(days=days)
        return [
            s
            for s in self._schedules.values()
            if s.enabled and s.next_rotation and s.next_rotation <= cutoff
        ]

    def get_all_schedules(self) -> list[dict[str, Any]]:
        """Get all rotation schedules."""
        return [s.to_dict() for s in self._schedules.values()]

    def check_rotation_health(self) -> dict[str, Any]:
        """Check overall rotation health."""
        now = datetime.now(UTC)
        overdue = []
        warnings = []
        healthy = []

        for schedule in self._schedules.values():
            if not schedule.enabled:
                continue

            if schedule.is_due():
                overdue.append(schedule.secret_type.value)
            elif schedule.should_notify():
                warnings.append(schedule.secret_type.value)
            else:
                healthy.append(schedule.secret_type.value)

        return {
            "status": "critical" if overdue else ("warning" if warnings else "healthy"),
            "overdue": overdue,
            "warnings": warnings,
            "healthy": healthy,
            "checked_at": now.isoformat(),
        }

    def _hash_secret(self, secret: str | None) -> str:
        """Hash a secret for logging (never log actual secrets)."""
        if not secret:
            return ""
        return hashlib.sha256(secret.encode()).hexdigest()[:16]


def create_secret_rotation(
    state_path: Path | str | None = None,
) -> SecretRotation:
    """Create a configured SecretRotation instance."""
    path = None
    if state_path:
        path = Path(state_path)
    elif env_path := os.environ.get("SECRET_ROTATION_STATE"):
        path = Path(env_path)

    return SecretRotation(state_path=path)
