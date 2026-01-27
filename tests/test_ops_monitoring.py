"""Unit tests for monitoring operations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from portal.ops.monitoring import (
    Alert,
    AlertRule,
    AlertSeverity,
    AlertType,
    MetricsCollector,
    MonitoringConfig,
    MonitoringService,
    create_monitoring_service,
    get_default_rules,
    log_alert_handler,
    webhook_alert_handler_factory,
)


class TestAlertRule:
    """Tests for AlertRule."""

    def test_alert_rule_to_dict(self) -> None:
        """Test alert rule serialization."""
        rule = AlertRule(
            name="test_rule",
            alert_type=AlertType.AUTH_FAILURE_SPIKE,
            severity=AlertSeverity.WARNING,
            threshold=10,
            window_seconds=300,
            description="Test description",
        )
        data = rule.to_dict()

        assert data["name"] == "test_rule"
        assert data["alert_type"] == "auth_failure_spike"
        assert data["severity"] == "warning"
        assert data["threshold"] == 10


class TestAlert:
    """Tests for Alert."""

    def test_alert_generation(self) -> None:
        """Test alert creation with auto-generated ID."""
        alert = Alert(
            rule_name="test_rule",
            alert_type=AlertType.AUTH_FAILURE_SPIKE,
            severity=AlertSeverity.WARNING,
            timestamp=datetime.now(UTC),
            message="Test alert",
        )

        assert alert.alert_id.startswith("alert_")
        assert len(alert.alert_id) > 10

    def test_alert_to_dict(self) -> None:
        """Test alert serialization."""
        alert = Alert(
            rule_name="test_rule",
            alert_type=AlertType.AUTH_FAILURE_SPIKE,
            severity=AlertSeverity.WARNING,
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            message="Test alert",
            details={"count": 10},
        )
        data = alert.to_dict()

        assert data["rule_name"] == "test_rule"
        assert data["alert_type"] == "auth_failure_spike"
        assert data["message"] == "Test alert"
        assert data["details"]["count"] == 10


class TestMetricsCollector:
    """Tests for MetricsCollector."""

    def test_increment_counter(self) -> None:
        """Test counter increment."""
        collector = MetricsCollector()
        collector.increment("test_metric")
        collector.increment("test_metric")
        collector.increment("test_metric", value=3)

        count = collector.get_count("test_metric", window_seconds=60)
        assert count == 5

    def test_increment_with_labels(self) -> None:
        """Test counter increment with labels."""
        collector = MetricsCollector()
        collector.increment("auth_failures", labels={"ip": "1.2.3.4"})
        collector.increment("auth_failures", labels={"ip": "1.2.3.4"})
        collector.increment("auth_failures", labels={"ip": "5.6.7.8"})

        count_ip1 = collector.get_count("auth_failures", 60, labels={"ip": "1.2.3.4"})
        count_ip2 = collector.get_count("auth_failures", 60, labels={"ip": "5.6.7.8"})

        assert count_ip1 == 2
        assert count_ip2 == 1

    def test_gauge(self) -> None:
        """Test gauge metric."""
        collector = MetricsCollector()
        collector.gauge("cpu_usage", 75.5)
        collector.gauge("cpu_usage", 80.0)

        events = collector.get_events_in_window("cpu_usage", 60)
        assert len(events) == 2
        assert events[-1][1] == 80.0

    def test_window_filtering(self) -> None:
        """Test that metrics outside window are excluded."""
        collector = MetricsCollector()

        # Add old metrics by manipulating internal state
        old_time = datetime.now(UTC) - timedelta(seconds=120)
        collector._metrics["test_metric"].append((old_time, 1))

        # Add recent metric
        collector.increment("test_metric")

        # Only recent metric should be counted in 60-second window
        count = collector.get_count("test_metric", window_seconds=60)
        assert count == 1

    def test_cleanup_old_metrics(self) -> None:
        """Test cleanup of old metrics."""
        collector = MetricsCollector(retention_hours=1)

        # Add old metric
        old_time = datetime.now(UTC) - timedelta(hours=2)
        collector._metrics["old_metric"].append((old_time, 1))

        # Add recent metric
        collector.increment("recent_metric")

        removed = collector.cleanup_old_metrics()
        assert removed == 1
        assert len(collector._metrics["old_metric"]) == 0
        assert len(collector._metrics["recent_metric"]) == 1

    def test_get_all_metrics(self) -> None:
        """Test getting all metrics snapshot."""
        collector = MetricsCollector()
        collector.increment("metric_a")
        collector.increment("metric_b", value=5)

        snapshot = collector.get_all_metrics()
        assert "counters" in snapshot
        assert "metrics" in snapshot


class TestMonitoringService:
    """Tests for MonitoringService."""

    def test_create_service(self) -> None:
        """Test service creation."""
        config = MonitoringConfig(enabled=True)
        service = MonitoringService(config)
        assert service is not None

    def test_record_auth_failure(self) -> None:
        """Test recording authentication failure."""
        config = MonitoringConfig(enabled=True)
        service = MonitoringService(config)

        service.record_auth_failure("1.2.3.4", "invalid_credentials")

        metrics = service.get_metrics()
        assert metrics["counters"]["auth_failures_total"] >= 1

    def test_record_authz_denial(self) -> None:
        """Test recording authorization denial."""
        config = MonitoringConfig(enabled=True)
        service = MonitoringService(config)

        service.record_authz_denial("user123", "tenant1", "delete", "resource1")

        metrics = service.get_metrics()
        assert metrics["counters"]["authz_denials_total"] >= 1

    def test_alert_handler_called(self) -> None:
        """Test that alert handlers are called when alert triggers."""
        handler = MagicMock()
        config = MonitoringConfig(
            enabled=True,
            alert_handlers=[handler],
            rules=[
                AlertRule(
                    name="test_rule",
                    alert_type=AlertType.CROSS_TENANT_ATTEMPT,
                    severity=AlertSeverity.CRITICAL,
                    threshold=1,
                    window_seconds=60,
                    cooldown_seconds=0,  # No cooldown for test
                ),
            ],
        )
        service = MonitoringService(config)

        service.record_cross_tenant_attempt("user1", "tenant1", "tenant2")

        handler.assert_called_once()
        alert = handler.call_args[0][0]
        assert isinstance(alert, Alert)
        assert alert.alert_type == AlertType.CROSS_TENANT_ATTEMPT

    def test_alert_cooldown(self) -> None:
        """Test that alerts respect cooldown period."""
        handler = MagicMock()
        config = MonitoringConfig(
            enabled=True,
            alert_handlers=[handler],
            rules=[
                AlertRule(
                    name="test_rule",
                    alert_type=AlertType.CROSS_TENANT_ATTEMPT,
                    severity=AlertSeverity.CRITICAL,
                    threshold=1,
                    window_seconds=60,
                    cooldown_seconds=300,  # 5 minute cooldown
                ),
            ],
        )
        service = MonitoringService(config)

        # First alert should trigger
        service.record_cross_tenant_attempt("user1", "tenant1", "tenant2")
        assert handler.call_count == 1

        # Second alert within cooldown should not trigger
        service.record_cross_tenant_attempt("user2", "tenant1", "tenant3")
        assert handler.call_count == 1

    def test_brute_force_detection(self) -> None:
        """Test brute force attack detection."""
        handler = MagicMock()
        config = MonitoringConfig(
            enabled=True,
            alert_handlers=[handler],
        )
        service = MonitoringService(config)

        # Simulate multiple auth failures from same IP
        for _ in range(6):
            service.record_auth_failure("1.2.3.4", "invalid_credentials")

        # Should have triggered brute force alert
        assert handler.call_count >= 1

    def test_record_saml_replay(self) -> None:
        """Test recording SAML replay block."""
        handler = MagicMock()
        config = MonitoringConfig(
            enabled=True,
            alert_handlers=[handler],
        )
        service = MonitoringService(config)

        service.record_saml_replay_blocked("assertion123", "1.2.3.4")

        handler.assert_called()
        alert = handler.call_args[0][0]
        assert alert.alert_type == AlertType.SAML_REPLAY

    def test_record_import_failure(self) -> None:
        """Test recording import failure."""
        config = MonitoringConfig(enabled=True)
        service = MonitoringService(config)

        service.record_import_failure("tenant1", "Invalid format")

        metrics = service.get_metrics()
        assert metrics["counters"]["import_failures_total"] >= 1

    def test_record_backup_failure(self) -> None:
        """Test recording backup failure."""
        handler = MagicMock()
        config = MonitoringConfig(
            enabled=True,
            alert_handlers=[handler],
        )
        service = MonitoringService(config)

        service.record_backup_failure("backup_123", "Disk full")

        handler.assert_called()
        alert = handler.call_args[0][0]
        assert alert.alert_type == AlertType.BACKUP_FAILURE


class TestDefaultRules:
    """Tests for default alert rules."""

    def test_default_rules_exist(self) -> None:
        """Test that default rules are defined."""
        rules = get_default_rules()
        assert len(rules) > 0

    def test_default_rules_have_required_fields(self) -> None:
        """Test that default rules have all required fields."""
        rules = get_default_rules()
        for rule in rules:
            assert rule.name
            assert rule.alert_type
            assert rule.severity
            assert rule.threshold > 0
            assert rule.window_seconds > 0


class TestAlertHandlers:
    """Tests for alert handlers."""

    def test_log_alert_handler(self) -> None:
        """Test log alert handler doesn't raise."""
        alert = Alert(
            rule_name="test",
            alert_type=AlertType.AUTH_FAILURE_SPIKE,
            severity=AlertSeverity.WARNING,
            timestamp=datetime.now(UTC),
            message="Test",
        )

        # Should not raise
        log_alert_handler(alert)

    @patch("urllib.request.urlopen")
    def test_webhook_handler_factory(self, mock_urlopen: MagicMock) -> None:
        """Test webhook alert handler factory."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        handler = webhook_alert_handler_factory("https://example.com/webhook")

        alert = Alert(
            rule_name="test",
            alert_type=AlertType.AUTH_FAILURE_SPIKE,
            severity=AlertSeverity.WARNING,
            timestamp=datetime.now(UTC),
            message="Test",
        )

        handler(alert)
        mock_urlopen.assert_called_once()


class TestCreateMonitoringService:
    """Tests for create_monitoring_service factory."""

    def test_create_with_defaults(self) -> None:
        """Test creating service with defaults."""
        service = create_monitoring_service()
        assert isinstance(service, MonitoringService)

    def test_create_disabled(self) -> None:
        """Test creating disabled service."""
        service = create_monitoring_service(enabled=False)
        assert service._config.enabled is False

    def test_create_with_custom_rules(self) -> None:
        """Test creating service with custom rules."""
        custom_rules = [
            AlertRule(
                name="custom_rule",
                alert_type=AlertType.SYSTEM_ERROR,
                severity=AlertSeverity.CRITICAL,
                threshold=1,
                window_seconds=60,
            ),
        ]
        service = create_monitoring_service(rules=custom_rules)
        assert len(service._config.rules) == 1
        assert service._config.rules[0].name == "custom_rule"
