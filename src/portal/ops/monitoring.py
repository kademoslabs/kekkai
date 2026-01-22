"""Monitoring and alerting system for Kekkai Portal.

Provides:
- Alert rules for auth/authz anomalies
- Alert rules for import failures
- Metric collection
- Integration with audit log system

ASVS 5.0 Requirements:
- V16.4.3: Send logs to separate system
- V16.3.2: Log failed authz
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertType(Enum):
    """Types of alerts."""

    AUTH_FAILURE_SPIKE = "auth_failure_spike"
    AUTH_BRUTE_FORCE = "auth_brute_force"
    AUTHZ_DENIAL = "authz_denial"
    CROSS_TENANT_ATTEMPT = "cross_tenant_attempt"
    IMPORT_FAILURE = "import_failure"
    BACKUP_FAILURE = "backup_failure"
    SYSTEM_ERROR = "system_error"
    SAML_REPLAY = "saml_replay"
    LICENSE_EXPIRED = "license_expired"


@dataclass
class AlertRule:
    """Definition of an alert rule."""

    name: str
    alert_type: AlertType
    severity: AlertSeverity
    threshold: int
    window_seconds: int
    description: str = ""
    enabled: bool = True
    cooldown_seconds: int = 300

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "description": self.description,
            "enabled": self.enabled,
            "cooldown_seconds": self.cooldown_seconds,
        }


@dataclass
class Alert:
    """Represents a triggered alert."""

    rule_name: str
    alert_type: AlertType
    severity: AlertSeverity
    timestamp: datetime
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    alert_id: str = ""

    def __post_init__(self) -> None:
        if not self.alert_id:
            import secrets

            self.alert_id = f"alert_{int(time.time())}_{secrets.token_hex(4)}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "rule_name": self.rule_name,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "message": self.message,
            "details": self.details,
        }


@dataclass
class MonitoringConfig:
    """Configuration for monitoring service."""

    enabled: bool = True
    alert_handlers: list[Callable[[Alert], None]] = field(default_factory=list)
    metrics_retention_hours: int = 24
    check_interval_seconds: int = 60

    rules: list[AlertRule] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.rules:
            self.rules = get_default_rules()


def get_default_rules() -> list[AlertRule]:
    """Get default alert rules."""
    return [
        AlertRule(
            name="auth_failure_spike",
            alert_type=AlertType.AUTH_FAILURE_SPIKE,
            severity=AlertSeverity.WARNING,
            threshold=10,
            window_seconds=300,
            description="Multiple authentication failures in short period",
        ),
        AlertRule(
            name="brute_force_detection",
            alert_type=AlertType.AUTH_BRUTE_FORCE,
            severity=AlertSeverity.CRITICAL,
            threshold=5,
            window_seconds=60,
            description="Potential brute force attack from single IP",
        ),
        AlertRule(
            name="authz_denial_alert",
            alert_type=AlertType.AUTHZ_DENIAL,
            severity=AlertSeverity.WARNING,
            threshold=5,
            window_seconds=300,
            description="Multiple authorization denials for user",
        ),
        AlertRule(
            name="cross_tenant_attempt",
            alert_type=AlertType.CROSS_TENANT_ATTEMPT,
            severity=AlertSeverity.CRITICAL,
            threshold=1,
            window_seconds=60,
            description="Cross-tenant access attempt detected",
        ),
        AlertRule(
            name="import_failure_alert",
            alert_type=AlertType.IMPORT_FAILURE,
            severity=AlertSeverity.WARNING,
            threshold=3,
            window_seconds=600,
            description="Multiple import failures",
        ),
        AlertRule(
            name="saml_replay_alert",
            alert_type=AlertType.SAML_REPLAY,
            severity=AlertSeverity.CRITICAL,
            threshold=1,
            window_seconds=60,
            description="SAML replay attack blocked",
        ),
        AlertRule(
            name="backup_failure_alert",
            alert_type=AlertType.BACKUP_FAILURE,
            severity=AlertSeverity.CRITICAL,
            threshold=1,
            window_seconds=3600,
            description="Backup job failed",
        ),
    ]


class MetricsCollector:
    """Collects and stores metrics for monitoring."""

    def __init__(self, retention_hours: int = 24) -> None:
        self._retention_hours = retention_hours
        self._metrics: dict[str, list[tuple[datetime, Any]]] = defaultdict(list)
        self._counters: dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def increment(
        self, metric_name: str, value: int = 1, labels: dict[str, str] | None = None
    ) -> None:
        """Increment a counter metric."""
        key = self._make_key(metric_name, labels)
        with self._lock:
            self._counters[key] += value
            self._metrics[key].append((datetime.now(UTC), value))

    def gauge(self, metric_name: str, value: float, labels: dict[str, str] | None = None) -> None:
        """Set a gauge metric value."""
        key = self._make_key(metric_name, labels)
        with self._lock:
            self._metrics[key].append((datetime.now(UTC), value))

    def get_count(
        self, metric_name: str, window_seconds: int, labels: dict[str, str] | None = None
    ) -> int:
        """Get count of events within window."""
        key = self._make_key(metric_name, labels)
        cutoff = datetime.now(UTC) - timedelta(seconds=window_seconds)

        with self._lock:
            values = self._metrics.get(key, [])
            return sum(v for ts, v in values if ts >= cutoff and isinstance(v, int))

    def get_events_in_window(
        self, metric_name: str, window_seconds: int, labels: dict[str, str] | None = None
    ) -> list[tuple[datetime, Any]]:
        """Get all events within window."""
        key = self._make_key(metric_name, labels)
        cutoff = datetime.now(UTC) - timedelta(seconds=window_seconds)

        with self._lock:
            values = self._metrics.get(key, [])
            return [(ts, v) for ts, v in values if ts >= cutoff]

    def cleanup_old_metrics(self) -> int:
        """Remove metrics older than retention period. Returns count removed."""
        cutoff = datetime.now(UTC) - timedelta(hours=self._retention_hours)
        removed = 0

        with self._lock:
            for key in list(self._metrics.keys()):
                original_len = len(self._metrics[key])
                self._metrics[key] = [(ts, v) for ts, v in self._metrics[key] if ts >= cutoff]
                removed += original_len - len(self._metrics[key])

        return removed

    def get_all_metrics(self) -> dict[str, Any]:
        """Get snapshot of all current metrics."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "metrics": {k: len(v) for k, v in self._metrics.items()},
            }

    def _make_key(self, metric_name: str, labels: dict[str, str] | None) -> str:
        """Create metric key from name and labels."""
        if not labels:
            return metric_name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{metric_name}{{{label_str}}}"


class MonitoringService:
    """Main monitoring service for Kekkai Portal."""

    def __init__(self, config: MonitoringConfig) -> None:
        self._config = config
        self._metrics = MetricsCollector(config.metrics_retention_hours)
        self._last_alert_time: dict[str, datetime] = {}
        self._lock = threading.Lock()
        self._running = False
        self._check_thread: threading.Thread | None = None

    def start(self) -> None:
        """Start background monitoring."""
        if not self._config.enabled:
            return

        self._running = True
        self._check_thread = threading.Thread(target=self._check_loop, daemon=True)
        self._check_thread.start()
        logger.info("monitoring.started")

    def stop(self) -> None:
        """Stop background monitoring."""
        self._running = False
        if self._check_thread:
            self._check_thread.join(timeout=5)
        logger.info("monitoring.stopped")

    def record_auth_failure(self, client_ip: str, reason: str, user_id: str | None = None) -> None:
        """Record an authentication failure event."""
        self._metrics.increment("auth_failures", labels={"ip": client_ip})
        self._metrics.increment("auth_failures_total")

        self._check_rule_immediate(AlertType.AUTH_FAILURE_SPIKE)
        self._check_brute_force(client_ip)

    def record_authz_denial(
        self, user_id: str, tenant_id: str, permission: str, resource: str | None = None
    ) -> None:
        """Record an authorization denial event."""
        self._metrics.increment("authz_denials", labels={"user": user_id, "tenant": tenant_id})
        self._metrics.increment("authz_denials_total")

        self._check_rule_immediate(AlertType.AUTHZ_DENIAL, {"user_id": user_id})

    def record_cross_tenant_attempt(
        self, user_id: str, source_tenant: str, target_tenant: str
    ) -> None:
        """Record a cross-tenant access attempt."""
        self._metrics.increment(
            "cross_tenant_attempts",
            labels={"user": user_id, "source": source_tenant, "target": target_tenant},
        )

        self._trigger_alert(
            AlertRule(
                name="cross_tenant_attempt",
                alert_type=AlertType.CROSS_TENANT_ATTEMPT,
                severity=AlertSeverity.CRITICAL,
                threshold=1,
                window_seconds=60,
            ),
            f"Cross-tenant access attempt: user={user_id} from={source_tenant} to={target_tenant}",
            {"user_id": user_id, "source_tenant": source_tenant, "target_tenant": target_tenant},
        )

    def record_import_failure(self, tenant_id: str, reason: str) -> None:
        """Record an import failure event."""
        self._metrics.increment("import_failures", labels={"tenant": tenant_id})
        self._metrics.increment("import_failures_total")

        self._check_rule_immediate(AlertType.IMPORT_FAILURE, {"tenant_id": tenant_id})

    def record_saml_replay_blocked(self, assertion_id: str, client_ip: str) -> None:
        """Record a blocked SAML replay attempt."""
        self._metrics.increment("saml_replay_blocked", labels={"ip": client_ip})

        self._trigger_alert(
            AlertRule(
                name="saml_replay_alert",
                alert_type=AlertType.SAML_REPLAY,
                severity=AlertSeverity.CRITICAL,
                threshold=1,
                window_seconds=60,
            ),
            f"SAML replay attack blocked: assertion={assertion_id[:16]}... ip={client_ip}",
            {"assertion_id": assertion_id, "client_ip": client_ip},
        )

    def record_backup_failure(self, backup_id: str, error: str) -> None:
        """Record a backup failure event."""
        self._metrics.increment("backup_failures")

        self._trigger_alert(
            AlertRule(
                name="backup_failure_alert",
                alert_type=AlertType.BACKUP_FAILURE,
                severity=AlertSeverity.CRITICAL,
                threshold=1,
                window_seconds=3600,
            ),
            f"Backup failed: {backup_id}",
            {"backup_id": backup_id, "error": error},
        )

    def get_metrics(self) -> dict[str, Any]:
        """Get current metrics snapshot."""
        return self._metrics.get_all_metrics()

    def get_recent_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get recent alerts (from log - placeholder for full implementation)."""
        return []

    def add_alert_handler(self, handler: Callable[[Alert], None]) -> None:
        """Add an alert handler callback."""
        self._config.alert_handlers.append(handler)

    def _check_loop(self) -> None:
        """Background loop to check alert rules."""
        while self._running:
            try:
                self._check_all_rules()
                self._metrics.cleanup_old_metrics()
            except Exception as e:
                logger.error("monitoring.check_error error=%s", str(e))

            time.sleep(self._config.check_interval_seconds)

    def _check_all_rules(self) -> None:
        """Check all configured alert rules."""
        for rule in self._config.rules:
            if not rule.enabled:
                continue
            self._check_rule(rule)

    def _check_rule(self, rule: AlertRule) -> None:
        """Check a single alert rule."""
        metric_name = self._alert_type_to_metric(rule.alert_type)
        if not metric_name:
            return

        count = self._metrics.get_count(metric_name, rule.window_seconds)
        if count >= rule.threshold:
            self._trigger_alert(
                rule, f"{rule.description}: {count} events in {rule.window_seconds}s"
            )

    def _check_rule_immediate(
        self, alert_type: AlertType, context: dict[str, Any] | None = None
    ) -> None:
        """Check rules immediately for a specific alert type."""
        for rule in self._config.rules:
            if rule.alert_type == alert_type and rule.enabled:
                self._check_rule(rule)

    def _check_brute_force(self, client_ip: str) -> None:
        """Check for brute force attack from specific IP."""
        count = self._metrics.get_count("auth_failures", 60, labels={"ip": client_ip})
        if count >= 5:
            rule = AlertRule(
                name="brute_force_detection",
                alert_type=AlertType.AUTH_BRUTE_FORCE,
                severity=AlertSeverity.CRITICAL,
                threshold=5,
                window_seconds=60,
            )
            self._trigger_alert(
                rule,
                f"Potential brute force attack from {client_ip}: {count} failures in 60s",
                {"client_ip": client_ip, "failure_count": count},
            )

    def _trigger_alert(
        self, rule: AlertRule, message: str, details: dict[str, Any] | None = None
    ) -> None:
        """Trigger an alert if not in cooldown."""
        with self._lock:
            last_time = self._last_alert_time.get(rule.name)
            now = datetime.now(UTC)

            if last_time and (now - last_time).total_seconds() < rule.cooldown_seconds:
                return

            self._last_alert_time[rule.name] = now

        alert = Alert(
            rule_name=rule.name,
            alert_type=rule.alert_type,
            severity=rule.severity,
            timestamp=now,
            message=message,
            details=details or {},
        )

        logger.warning(
            "alert.triggered rule=%s severity=%s message=%s",
            rule.name,
            rule.severity.value,
            message,
        )

        for handler in self._config.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error("alert.handler.error handler=%s error=%s", handler.__name__, str(e))

    def _alert_type_to_metric(self, alert_type: AlertType) -> str | None:
        """Map alert type to metric name."""
        mapping = {
            AlertType.AUTH_FAILURE_SPIKE: "auth_failures_total",
            AlertType.AUTHZ_DENIAL: "authz_denials_total",
            AlertType.IMPORT_FAILURE: "import_failures_total",
            AlertType.BACKUP_FAILURE: "backup_failures",
        }
        return mapping.get(alert_type)


def create_monitoring_service(
    enabled: bool = True,
    rules: list[AlertRule] | None = None,
) -> MonitoringService:
    """Create a configured MonitoringService instance."""
    config = MonitoringConfig(enabled=enabled)
    if rules:
        config.rules = rules
    return MonitoringService(config)


def log_alert_handler(alert: Alert) -> None:
    """Default alert handler that logs to file."""
    logger.warning("ALERT: %s", json.dumps(alert.to_dict()))


def webhook_alert_handler_factory(webhook_url: str) -> Callable[[Alert], None]:
    """Create a webhook alert handler."""
    import urllib.error
    import urllib.request

    def handler(alert: Alert) -> None:
        try:
            data = json.dumps(alert.to_dict()).encode("utf-8")
            req = urllib.request.Request(  # noqa: S310
                webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                if resp.status >= 400:
                    logger.error("webhook.failed status=%d", resp.status)
        except urllib.error.URLError as e:
            logger.error("webhook.error url=%s error=%s", webhook_url, str(e))

    return handler
