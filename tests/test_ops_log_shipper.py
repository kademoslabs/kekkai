"""Unit tests for log shipper operations."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from portal.ops.log_shipper import (
    LogEntry,
    LogShipper,
    LogShipperConfig,
    ShipperType,
    SyslogFacility,
    SyslogSeverity,
    create_log_shipper,
)


class TestLogEntry:
    """Tests for LogEntry."""

    def test_entry_creation(self) -> None:
        """Test log entry creation."""
        entry = LogEntry(
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            level="INFO",
            message="Test message",
            source="test",
            metadata={"key": "value"},
        )

        assert entry.level == "INFO"
        assert entry.message == "Test message"
        assert entry.metadata["key"] == "value"

    def test_entry_to_dict(self) -> None:
        """Test entry serialization."""
        entry = LogEntry(
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            level="WARNING",
            message="Warning message",
        )
        data = entry.to_dict()

        assert data["level"] == "WARNING"
        assert data["message"] == "Warning message"
        assert "timestamp" in data

    def test_entry_to_json(self) -> None:
        """Test entry JSON serialization."""
        entry = LogEntry(
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            level="ERROR",
            message="Error message",
        )
        json_str = entry.to_json()

        parsed = json.loads(json_str)
        assert parsed["level"] == "ERROR"

    def test_entry_to_syslog(self) -> None:
        """Test syslog message formatting."""
        entry = LogEntry(
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            level="INFO",
            message="Syslog test",
            source="kekkai",
        )
        syslog_msg = entry.to_syslog(SyslogFacility.LOCAL0, "testhost")

        assert syslog_msg.startswith("<")
        assert "kekkai" in syslog_msg
        assert "Syslog test" in syslog_msg

    def test_level_to_severity_mapping(self) -> None:
        """Test log level to syslog severity mapping."""
        entry = LogEntry(
            timestamp=datetime.now(UTC),
            level="DEBUG",
            message="test",
        )
        assert entry._level_to_severity() == SyslogSeverity.DEBUG

        entry.level = "CRITICAL"
        assert entry._level_to_severity() == SyslogSeverity.CRITICAL


class TestLogShipperConfig:
    """Tests for LogShipperConfig."""

    def test_default_config(self) -> None:
        """Test default configuration."""
        config = LogShipperConfig()
        assert config.shipper_type == ShipperType.FILE
        assert config.enabled is True
        assert config.buffer_size == 10000
        assert config.retry_count == 3

    def test_syslog_config(self) -> None:
        """Test syslog configuration."""
        config = LogShipperConfig(
            shipper_type=ShipperType.SYSLOG,
            syslog_host="syslog.example.com",
            syslog_port=1514,
            syslog_protocol="tcp",
        )
        assert config.syslog_host == "syslog.example.com"
        assert config.syslog_port == 1514

    def test_webhook_config(self) -> None:
        """Test webhook configuration."""
        config = LogShipperConfig(
            shipper_type=ShipperType.WEBHOOK,
            webhook_url="https://example.com/logs",
            webhook_auth_header="Bearer token",
        )
        assert config.webhook_url == "https://example.com/logs"


class TestLogShipper:
    """Tests for LogShipper."""

    def test_ship_to_buffer(self) -> None:
        """Test shipping to buffer."""
        config = LogShipperConfig(
            shipper_type=ShipperType.FILE,
            enabled=True,
        )
        shipper = LogShipper(config)

        entry = LogEntry(
            timestamp=datetime.now(UTC),
            level="INFO",
            message="Test message",
        )

        result = shipper.ship(entry)
        assert result is True

    def test_ship_disabled(self) -> None:
        """Test shipping when disabled."""
        config = LogShipperConfig(enabled=False)
        shipper = LogShipper(config)

        entry = LogEntry(
            timestamp=datetime.now(UTC),
            level="INFO",
            message="Test",
        )

        result = shipper.ship(entry)
        assert result is False

    def test_ship_dict(self) -> None:
        """Test shipping dictionary as log entry."""
        config = LogShipperConfig(enabled=True)
        shipper = LogShipper(config)

        result = shipper.ship_dict({"message": "Test", "extra": "data"})
        assert result is True

    def test_hash_chain(self) -> None:
        """Test hash chain integrity."""
        config = LogShipperConfig(
            enabled=True,
            include_hash_chain=True,
        )
        shipper = LogShipper(config)

        entry1 = LogEntry(
            timestamp=datetime.now(UTC),
            level="INFO",
            message="First",
        )
        entry2 = LogEntry(
            timestamp=datetime.now(UTC),
            level="INFO",
            message="Second",
        )

        shipper.ship(entry1)
        first_hash = entry1.entry_hash

        shipper.ship(entry2)
        second_hash = entry2.entry_hash

        # Hashes should be different
        assert first_hash != second_hash
        # Both should be valid SHA-256 hashes
        assert len(first_hash) == 64
        assert len(second_hash) == 64

    def test_get_stats(self) -> None:
        """Test getting shipping statistics."""
        config = LogShipperConfig(enabled=True)
        shipper = LogShipper(config)

        stats = shipper.get_stats()
        assert "shipped" in stats
        assert "failed" in stats
        assert "dropped" in stats

    def test_buffer_overflow_handling(self) -> None:
        """Test buffer overflow handling."""
        config = LogShipperConfig(
            enabled=True,
            buffer_size=2,
        )
        shipper = LogShipper(config)

        # Fill buffer
        for _ in range(3):
            entry = LogEntry(
                timestamp=datetime.now(UTC),
                level="INFO",
                message="Test",
            )
            shipper.ship(entry)

        stats = shipper.get_stats()
        assert stats["dropped"] >= 1

    def test_ship_to_file(self) -> None:
        """Test shipping to file destination."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "shipped.jsonl"
            config = LogShipperConfig(
                shipper_type=ShipperType.FILE,
                file_path=log_file,
                enabled=True,
            )
            shipper = LogShipper(config)

            entry = LogEntry(
                timestamp=datetime.now(UTC),
                level="INFO",
                message="File test",
            )

            try:
                # Ship directly (bypass background thread)
                shipper._ship_file([entry])

                assert log_file.exists()
                content = log_file.read_text()
                assert "File test" in content
            finally:
                shipper.stop()  # Close file handle before temp dir cleanup

    @patch("socket.socket")
    def test_ship_to_syslog_udp(self, mock_socket_class: MagicMock) -> None:
        """Test shipping to syslog via UDP."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        config = LogShipperConfig(
            shipper_type=ShipperType.SYSLOG,
            syslog_protocol="udp",
            syslog_host="localhost",
            syslog_port=514,
            enabled=True,
        )
        shipper = LogShipper(config)

        entry = LogEntry(
            timestamp=datetime.now(UTC),
            level="INFO",
            message="Syslog test",
        )

        shipper._ship_syslog([entry])
        mock_socket.sendto.assert_called()

    @patch("portal.ops.log_shipper.urlopen")
    def test_ship_to_webhook(self, mock_urlopen: MagicMock) -> None:
        """Test shipping to webhook."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        config = LogShipperConfig(
            shipper_type=ShipperType.WEBHOOK,
            webhook_url="https://example.com/logs",
            enabled=True,
        )
        shipper = LogShipper(config)

        entry = LogEntry(
            timestamp=datetime.now(UTC),
            level="INFO",
            message="Webhook test",
        )

        shipper._ship_webhook([entry])
        mock_urlopen.assert_called_once()

    def test_file_rotation(self) -> None:
        """Test file rotation logic."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "shipped.jsonl"
            config = LogShipperConfig(
                shipper_type=ShipperType.FILE,
                file_path=log_file,
                file_rotate_size_mb=0,  # Rotate immediately
                file_compress=False,
                enabled=True,
            )
            shipper = LogShipper(config)

            try:
                # Write initial content
                log_file.write_text("initial content\n")

                # Ship an entry (should trigger rotation)
                shipper._ensure_file_handle()
                shipper._maybe_rotate_file()

                # Check for rotated file
                rotated_file = log_file.with_suffix(".1.jsonl")
                assert rotated_file.exists()
            finally:
                shipper.stop()  # Close file handle before temp dir cleanup


class TestCreateLogShipper:
    """Tests for create_log_shipper factory."""

    def test_create_file_shipper(self) -> None:
        """Test creating file shipper."""
        with tempfile.TemporaryDirectory() as tmpdir:
            shipper = create_log_shipper(
                ShipperType.FILE,
                path=f"{tmpdir}/logs.jsonl",
            )
            assert shipper._config.shipper_type == ShipperType.FILE

    def test_create_syslog_shipper(self) -> None:
        """Test creating syslog shipper."""
        shipper = create_log_shipper(
            "syslog",
            host="syslog.example.com",
            port=1514,
        )
        assert shipper._config.shipper_type == ShipperType.SYSLOG
        assert shipper._config.syslog_host == "syslog.example.com"

    def test_create_webhook_shipper(self) -> None:
        """Test creating webhook shipper."""
        shipper = create_log_shipper(
            ShipperType.WEBHOOK,
            url="https://example.com/logs",
            auth="Bearer token",
        )
        assert shipper._config.shipper_type == ShipperType.WEBHOOK
        assert shipper._config.webhook_url == "https://example.com/logs"

    @patch.dict("os.environ", {"LOG_SHIP_PATH": "/custom/path/logs.jsonl"})
    def test_create_with_env_vars(self) -> None:
        """Test creating shipper with environment variables."""
        shipper = create_log_shipper(ShipperType.FILE)
        assert shipper._config.file_path == Path("/custom/path/logs.jsonl")
