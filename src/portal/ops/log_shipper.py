"""Log shipping to external systems for Kekkai Portal.

Provides centralized logging capabilities:
- Ship logs to syslog servers
- Ship logs to webhook endpoints
- Ship logs to file destinations
- Log integrity verification

ASVS 5.0 Requirements:
- V16.4.3: Send logs to separate system
- V16.4.2: Log protection
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import queue
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

SHIPPER_VERSION = "1.0"


class ShipperType(Enum):
    """Type of log destination."""

    SYSLOG = "syslog"
    WEBHOOK = "webhook"
    FILE = "file"


class SyslogFacility(Enum):
    """Syslog facility codes."""

    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


class SyslogSeverity(Enum):
    """Syslog severity codes."""

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


@dataclass
class LogShipperConfig:
    """Configuration for log shipper."""

    shipper_type: ShipperType = ShipperType.FILE
    enabled: bool = True

    syslog_host: str = "localhost"
    syslog_port: int = 514
    syslog_protocol: str = "udp"
    syslog_facility: SyslogFacility = SyslogFacility.LOCAL0
    syslog_use_tls: bool = False

    webhook_url: str = ""
    webhook_auth_header: str = ""
    webhook_batch_size: int = 100
    webhook_flush_interval: int = 10

    file_path: Path = field(default_factory=lambda: Path("/var/log/kekkai/shipped.jsonl"))
    file_rotate_size_mb: int = 100
    file_rotate_count: int = 5
    file_compress: bool = True

    buffer_size: int = 10000
    retry_count: int = 3
    retry_delay_seconds: float = 1.0

    include_hash_chain: bool = True
    hostname: str = field(default_factory=socket.gethostname)


@dataclass
class LogEntry:
    """Represents a log entry to be shipped."""

    timestamp: datetime
    level: str
    message: str
    source: str = "kekkai-portal"
    metadata: dict[str, Any] = field(default_factory=dict)
    entry_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level,
            "message": self.message,
            "source": self.source,
            "metadata": self.metadata,
            "hash": self.entry_hash,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))

    def to_syslog(self, facility: SyslogFacility, hostname: str) -> str:
        """Format as syslog message (RFC 5424)."""
        severity = self._level_to_severity()
        priority = facility.value * 8 + severity.value

        timestamp = self.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        structured_data = "-"

        if self.metadata:
            sd_params = " ".join(f'{k}="{v}"' for k, v in self.metadata.items())
            structured_data = f"[kekkai@0 {sd_params}]"

        return (
            f"<{priority}>1 {timestamp} {hostname} "
            f"{self.source} - - {structured_data} {self.message}"
        )

    def _level_to_severity(self) -> SyslogSeverity:
        """Map log level to syslog severity."""
        mapping = {
            "DEBUG": SyslogSeverity.DEBUG,
            "INFO": SyslogSeverity.INFO,
            "WARNING": SyslogSeverity.WARNING,
            "ERROR": SyslogSeverity.ERROR,
            "CRITICAL": SyslogSeverity.CRITICAL,
        }
        return mapping.get(self.level.upper(), SyslogSeverity.INFO)


class LogShipper:
    """Ships logs to external systems."""

    def __init__(self, config: LogShipperConfig) -> None:
        self._config = config
        self._buffer: queue.Queue[LogEntry] = queue.Queue(maxsize=config.buffer_size)
        self._last_hash = "0" * 64
        self._lock = threading.Lock()
        self._running = False
        self._ship_thread: threading.Thread | None = None
        self._stats = {"shipped": 0, "failed": 0, "dropped": 0}

        self._socket: socket.socket | None = None
        self._file_handle: BinaryIO | None = None

    def start(self) -> None:
        """Start the log shipper background thread."""
        if not self._config.enabled:
            return

        self._running = True
        self._ship_thread = threading.Thread(target=self._ship_loop, daemon=True)
        self._ship_thread.start()
        logger.info("log_shipper.started type=%s", self._config.shipper_type.value)

    def stop(self) -> None:
        """Stop the log shipper and flush remaining logs."""
        self._running = False
        if self._ship_thread:
            self._ship_thread.join(timeout=10)

        self._flush_buffer()
        self._cleanup()
        logger.info(
            "log_shipper.stopped shipped=%d failed=%d dropped=%d",
            self._stats["shipped"],
            self._stats["failed"],
            self._stats["dropped"],
        )

    def ship(self, entry: LogEntry) -> bool:
        """Add a log entry to the shipping queue."""
        if not self._config.enabled:
            return False

        if self._config.include_hash_chain:
            with self._lock:
                entry.entry_hash = self._compute_hash(entry)
                self._last_hash = entry.entry_hash

        try:
            self._buffer.put_nowait(entry)
            return True
        except queue.Full:
            self._stats["dropped"] += 1
            logger.warning("log_shipper.buffer_full")
            return False

    def ship_dict(self, data: dict[str, Any], level: str = "INFO") -> bool:
        """Ship a dictionary as a log entry."""
        entry = LogEntry(
            timestamp=datetime.now(UTC),
            level=level,
            message=data.get("message", json.dumps(data)),
            source=data.get("source", "kekkai-portal"),
            metadata={k: v for k, v in data.items() if k not in ("message", "source")},
        )
        return self.ship(entry)

    def get_stats(self) -> dict[str, int]:
        """Get shipping statistics."""
        return dict(self._stats)

    def _ship_loop(self) -> None:
        """Background loop to ship logs."""
        batch: list[LogEntry] = []
        last_flush = time.time()

        while self._running:
            try:
                entry = self._buffer.get(timeout=1.0)
                batch.append(entry)

                should_flush = (
                    len(batch) >= self._config.webhook_batch_size
                    or (time.time() - last_flush) >= self._config.webhook_flush_interval
                )

                if should_flush:
                    self._ship_batch(batch)
                    batch = []
                    last_flush = time.time()

            except queue.Empty:
                if batch and (time.time() - last_flush) >= self._config.webhook_flush_interval:
                    self._ship_batch(batch)
                    batch = []
                    last_flush = time.time()

        if batch:
            self._ship_batch(batch)

    def _ship_batch(self, batch: list[LogEntry]) -> None:
        """Ship a batch of log entries."""
        if not batch:
            return

        for attempt in range(self._config.retry_count):
            try:
                if self._config.shipper_type == ShipperType.SYSLOG:
                    self._ship_syslog(batch)
                elif self._config.shipper_type == ShipperType.WEBHOOK:
                    self._ship_webhook(batch)
                elif self._config.shipper_type == ShipperType.FILE:
                    self._ship_file(batch)

                self._stats["shipped"] += len(batch)
                return

            except Exception as e:
                logger.warning(
                    "log_shipper.retry attempt=%d error=%s",
                    attempt + 1,
                    str(e),
                )
                if attempt < self._config.retry_count - 1:
                    time.sleep(self._config.retry_delay_seconds * (attempt + 1))

        self._stats["failed"] += len(batch)
        logger.error("log_shipper.failed count=%d", len(batch))

    def _ship_syslog(self, batch: list[LogEntry]) -> None:
        """Ship logs to syslog server."""
        if self._socket is None:
            self._connect_syslog()

        for entry in batch:
            msg = entry.to_syslog(self._config.syslog_facility, self._config.hostname)
            msg_bytes = msg.encode("utf-8")

            if self._config.syslog_protocol == "tcp":
                msg_bytes = msg_bytes + b"\n"
                self._socket.sendall(msg_bytes)  # type: ignore
            else:
                self._socket.sendto(  # type: ignore
                    msg_bytes, (self._config.syslog_host, self._config.syslog_port)
                )

    def _ship_webhook(self, batch: list[LogEntry]) -> None:
        """Ship logs to webhook endpoint."""
        if not self._config.webhook_url:
            raise ValueError("Webhook URL not configured")

        payload = json.dumps(
            {
                "shipper_version": SHIPPER_VERSION,
                "hostname": self._config.hostname,
                "timestamp": datetime.now(UTC).isoformat(),
                "entries": [e.to_dict() for e in batch],
            }
        ).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        if self._config.webhook_auth_header:
            headers["Authorization"] = self._config.webhook_auth_header

        req = Request(  # noqa: S310
            self._config.webhook_url,
            data=payload,
            headers=headers,
            method="POST",
        )

        try:
            with urlopen(req, timeout=30) as resp:  # noqa: S310
                if resp.status >= 400:
                    raise ValueError(f"Webhook returned {resp.status}")
        except URLError as e:
            raise ConnectionError(f"Webhook request failed: {e}") from e

    def _ship_file(self, batch: list[LogEntry]) -> None:
        """Ship logs to local file."""
        self._ensure_file_handle()

        for entry in batch:
            line = entry.to_json() + "\n"
            self._file_handle.write(line.encode("utf-8"))  # type: ignore

        self._file_handle.flush()  # type: ignore
        self._maybe_rotate_file()

    def _connect_syslog(self) -> None:
        """Connect to syslog server."""
        if self._config.syslog_protocol == "tcp":
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self._config.syslog_use_tls:
                context = ssl.create_default_context()
                self._socket = context.wrap_socket(
                    self._socket, server_hostname=self._config.syslog_host
                )
            self._socket.connect((self._config.syslog_host, self._config.syslog_port))
        else:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _ensure_file_handle(self) -> None:
        """Ensure file handle is open."""
        if self._file_handle is not None:
            return

        self._config.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._file_handle = open(self._config.file_path, "ab")  # noqa: SIM115

    def _maybe_rotate_file(self) -> None:
        """Rotate log file if needed."""
        if not self._file_handle:
            return

        max_size = self._config.file_rotate_size_mb * 1024 * 1024
        current_size = self._config.file_path.stat().st_size

        if current_size < max_size:
            return

        self._file_handle.close()
        self._file_handle = None

        for i in range(self._config.file_rotate_count - 1, 0, -1):
            old_path = self._config.file_path.with_suffix(f".{i}.jsonl")
            new_path = self._config.file_path.with_suffix(f".{i + 1}.jsonl")
            if self._config.file_compress:
                old_path = old_path.with_suffix(old_path.suffix + ".gz")
                new_path = new_path.with_suffix(new_path.suffix + ".gz")
            if old_path.exists():
                old_path.rename(new_path)

        rotated_path = self._config.file_path.with_suffix(".1.jsonl")
        if self._config.file_compress:
            with (
                open(self._config.file_path, "rb") as f_in,
                gzip.open(rotated_path.with_suffix(rotated_path.suffix + ".gz"), "wb") as f_out,
            ):
                f_out.writelines(f_in)
            self._config.file_path.unlink()
        else:
            self._config.file_path.rename(rotated_path)

        self._ensure_file_handle()
        logger.info("log_shipper.file_rotated")

    def _flush_buffer(self) -> None:
        """Flush remaining entries from buffer."""
        batch: list[LogEntry] = []
        while True:
            try:
                entry = self._buffer.get_nowait()
                batch.append(entry)
            except queue.Empty:
                break

        if batch:
            self._ship_batch(batch)

    def _cleanup(self) -> None:
        """Clean up resources."""
        import contextlib

        if self._socket:
            with contextlib.suppress(OSError):
                self._socket.close()
            self._socket = None

        if self._file_handle:
            with contextlib.suppress(OSError):
                self._file_handle.close()
            self._file_handle = None

    def _compute_hash(self, entry: LogEntry) -> str:
        """Compute hash for integrity chain."""
        data = f"{self._last_hash}:{entry.to_json()}"
        return hashlib.sha256(data.encode()).hexdigest()


def create_log_shipper(
    shipper_type: ShipperType | str = ShipperType.FILE,
    **kwargs: Any,
) -> LogShipper:
    """Create a configured LogShipper instance."""
    if isinstance(shipper_type, str):
        shipper_type = ShipperType(shipper_type)

    config = LogShipperConfig(shipper_type=shipper_type)

    if shipper_type == ShipperType.SYSLOG:
        config.syslog_host = kwargs.get("host", os.environ.get("SYSLOG_HOST", "localhost"))
        config.syslog_port = int(kwargs.get("port", os.environ.get("SYSLOG_PORT", "514")))
        config.syslog_protocol = kwargs.get("protocol", os.environ.get("SYSLOG_PROTOCOL", "udp"))
        config.syslog_use_tls = kwargs.get(
            "use_tls", os.environ.get("SYSLOG_USE_TLS", "").lower() == "true"
        )

    elif shipper_type == ShipperType.WEBHOOK:
        config.webhook_url = kwargs.get("url", os.environ.get("LOG_WEBHOOK_URL", ""))
        config.webhook_auth_header = kwargs.get("auth", os.environ.get("LOG_WEBHOOK_AUTH", ""))

    elif shipper_type == ShipperType.FILE:
        file_path = kwargs.get(
            "path", os.environ.get("LOG_SHIP_PATH", "/var/log/kekkai/shipped.jsonl")
        )
        config.file_path = Path(file_path)

    return LogShipper(config)
