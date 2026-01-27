"""Unit tests for secret rotation operations."""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

from portal.ops.secrets import (
    RotationResult,
    RotationSchedule,
    RotationStatus,
    SecretRotation,
    SecretType,
    create_secret_rotation,
)


class TestRotationSchedule:
    """Tests for RotationSchedule."""

    def test_schedule_creation(self) -> None:
        """Test schedule creation."""
        schedule = RotationSchedule(
            secret_type=SecretType.API_KEY,
            interval_days=90,
        )
        assert schedule.secret_type == SecretType.API_KEY
        assert schedule.interval_days == 90
        assert schedule.enabled is True

    def test_schedule_with_last_rotated(self) -> None:
        """Test schedule computes next rotation from last."""
        last = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        schedule = RotationSchedule(
            secret_type=SecretType.API_KEY,
            interval_days=90,
            last_rotated=last,
        )
        assert schedule.next_rotation is not None
        assert schedule.next_rotation == last + timedelta(days=90)

    def test_is_due_no_rotation(self) -> None:
        """Test is_due when never rotated."""
        schedule = RotationSchedule(
            secret_type=SecretType.API_KEY,
            interval_days=90,
            enabled=True,
        )
        assert schedule.is_due() is True

    def test_is_due_past(self) -> None:
        """Test is_due when past due."""
        schedule = RotationSchedule(
            secret_type=SecretType.API_KEY,
            interval_days=90,
            last_rotated=datetime.now(UTC) - timedelta(days=100),
        )
        assert schedule.is_due() is True

    def test_is_due_future(self) -> None:
        """Test is_due when not yet due."""
        schedule = RotationSchedule(
            secret_type=SecretType.API_KEY,
            interval_days=90,
            last_rotated=datetime.now(UTC) - timedelta(days=10),
        )
        assert schedule.is_due() is False

    def test_is_due_disabled(self) -> None:
        """Test is_due when disabled."""
        schedule = RotationSchedule(
            secret_type=SecretType.API_KEY,
            interval_days=90,
            enabled=False,
        )
        assert schedule.is_due() is False

    def test_should_notify(self) -> None:
        """Test notification threshold."""
        # Due in 5 days, notification at 7 days before
        schedule = RotationSchedule(
            secret_type=SecretType.API_KEY,
            interval_days=90,
            notify_days_before=7,
        )
        schedule.next_rotation = datetime.now(UTC) + timedelta(days=5)
        assert schedule.should_notify() is True

        schedule.next_rotation = datetime.now(UTC) + timedelta(days=10)
        assert schedule.should_notify() is False

    def test_schedule_to_dict(self) -> None:
        """Test schedule serialization."""
        schedule = RotationSchedule(
            secret_type=SecretType.DATABASE_PASSWORD,
            interval_days=30,
        )
        data = schedule.to_dict()

        assert data["secret_type"] == "database_password"
        assert data["interval_days"] == 30


class TestRotationResult:
    """Tests for RotationResult."""

    def test_result_creation(self) -> None:
        """Test result creation."""
        result = RotationResult(
            success=True,
            secret_type=SecretType.API_KEY,
            status=RotationStatus.COMPLETED,
            old_key_hash="abc123",
            new_key_hash="def456",
        )
        assert result.success is True
        assert result.status == RotationStatus.COMPLETED

    def test_result_to_dict(self) -> None:
        """Test result serialization."""
        result = RotationResult(
            success=True,
            secret_type=SecretType.API_KEY,
            status=RotationStatus.COMPLETED,
        )
        data = result.to_dict()

        assert data["success"] is True
        assert data["secret_type"] == "api_key"
        assert data["status"] == "completed"


class TestSecretRotation:
    """Tests for SecretRotation."""

    def test_default_schedules(self) -> None:
        """Test default schedules are created."""
        rotation = SecretRotation()
        schedules = rotation.get_all_schedules()

        assert len(schedules) > 0
        secret_types = [s["secret_type"] for s in schedules]
        assert "api_key" in secret_types
        assert "database_password" in secret_types

    def test_generate_api_key(self) -> None:
        """Test API key generation."""
        rotation = SecretRotation()
        key = rotation.generate_api_key()

        assert key.startswith("kk_")
        assert len(key) > 40

    def test_generate_api_key_custom_prefix(self) -> None:
        """Test API key generation with custom prefix."""
        rotation = SecretRotation()
        key = rotation.generate_api_key(prefix="test")

        assert key.startswith("test_")

    def test_generate_password(self) -> None:
        """Test password generation."""
        rotation = SecretRotation()
        password = rotation.generate_password()

        assert len(password) == 32
        # Should contain various character types
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)

    def test_generate_password_custom_length(self) -> None:
        """Test password generation with custom length."""
        rotation = SecretRotation()
        password = rotation.generate_password(length=64)

        assert len(password) == 64

    def test_generate_encryption_key(self) -> None:
        """Test encryption key generation."""
        rotation = SecretRotation()
        key = rotation.generate_encryption_key()

        assert len(key) == 32  # 256 bits = 32 bytes
        assert isinstance(key, bytes)

    def test_generate_encryption_key_custom_bits(self) -> None:
        """Test encryption key generation with custom bits."""
        rotation = SecretRotation()
        key = rotation.generate_encryption_key(bits=128)

        assert len(key) == 16  # 128 bits = 16 bytes

    def test_register_handler(self) -> None:
        """Test handler registration."""
        rotation = SecretRotation()
        handler = MagicMock(return_value=True)

        rotation.register_handler(SecretType.API_KEY, handler)
        assert SecretType.API_KEY in rotation._rotation_handlers

    def test_rotate_api_key_success(self) -> None:
        """Test successful API key rotation."""
        rotation = SecretRotation()
        handler = MagicMock(return_value=True)
        rotation.register_handler(SecretType.API_KEY, handler)

        result = rotation.rotate_api_key("tenant1", current_key="old_key")

        assert result.success is True
        assert result.status == RotationStatus.COMPLETED
        assert result.rollback_available is True
        handler.assert_called_once()

    def test_rotate_api_key_handler_failure(self) -> None:
        """Test API key rotation when handler fails."""
        rotation = SecretRotation()
        handler = MagicMock(return_value=False)
        rotation.register_handler(SecretType.API_KEY, handler)

        result = rotation.rotate_api_key("tenant1")

        assert result.success is False
        assert "Handler" in (result.error or "")

    def test_rotate_database_password_success(self) -> None:
        """Test successful database password rotation."""
        rotation = SecretRotation()
        handler = MagicMock(return_value=True)
        rotation.register_handler(SecretType.DATABASE_PASSWORD, handler)

        result = rotation.rotate_database_password(current_password="old_pass")

        assert result.success is True
        assert result.status == RotationStatus.COMPLETED

    def test_rollback_success(self) -> None:
        """Test successful rollback."""
        rotation = SecretRotation()
        handler = MagicMock(return_value=True)
        rotation.register_handler(SecretType.API_KEY, handler)

        # First rotate
        rotation.rotate_api_key("tenant1", current_key="old_key")

        # Then rollback
        result = rotation.rollback(SecretType.API_KEY)

        assert result.success is True
        assert result.status == RotationStatus.ROLLED_BACK

    def test_rollback_no_value(self) -> None:
        """Test rollback when no value stored."""
        rotation = SecretRotation()

        result = rotation.rollback(SecretType.API_KEY)

        assert result.success is False
        assert "no rollback" in (result.error or "").lower()

    def test_get_due_rotations(self) -> None:
        """Test getting due rotations."""
        rotation = SecretRotation()

        # All defaults have no last_rotated, so all are due
        due = rotation.get_due_rotations()
        assert len(due) > 0

    def test_get_upcoming_rotations(self) -> None:
        """Test getting upcoming rotations."""
        rotation = SecretRotation()

        # Mark one as recently rotated
        for schedule in rotation._schedules.values():
            schedule.last_rotated = datetime.now(UTC)
            schedule.next_rotation = datetime.now(UTC) + timedelta(days=15)
            break

        upcoming = rotation.get_upcoming_rotations(days=30)
        assert len(upcoming) > 0

    def test_check_rotation_health_all_due(self) -> None:
        """Test health check when all rotations due."""
        rotation = SecretRotation()

        health = rotation.check_rotation_health()

        assert health["status"] == "critical"
        assert len(health["overdue"]) > 0

    def test_check_rotation_health_all_healthy(self) -> None:
        """Test health check when all rotations healthy."""
        rotation = SecretRotation()

        # Mark all as recently rotated
        for schedule in rotation._schedules.values():
            schedule.last_rotated = datetime.now(UTC)
            schedule.next_rotation = datetime.now(UTC) + timedelta(days=60)

        health = rotation.check_rotation_health()

        assert health["status"] == "healthy"
        assert len(health["overdue"]) == 0

    def test_hash_secret_redaction(self) -> None:
        """Test that secrets are hashed for logging."""
        rotation = SecretRotation()
        secret = "super_secret_value_12345"

        hashed = rotation._hash_secret(secret)

        assert hashed != secret
        assert len(hashed) == 16  # Truncated hash
        assert secret not in hashed


class TestCreateSecretRotation:
    """Tests for create_secret_rotation factory."""

    def test_create_with_defaults(self) -> None:
        """Test creating rotation manager with defaults."""
        rotation = create_secret_rotation()
        assert isinstance(rotation, SecretRotation)

    def test_create_with_state_path(self) -> None:
        """Test creating rotation manager with state path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "rotation_state.json"
            rotation = create_secret_rotation(state_path=state_path)
            assert rotation._state_path == state_path
