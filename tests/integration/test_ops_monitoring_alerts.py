"""Integration tests for monitoring and alerting."""

from __future__ import annotations

import pytest

from portal.ops.monitoring import (
    Alert,
    AlertRule,
    AlertSeverity,
    AlertType,
    MonitoringConfig,
    MonitoringService,
)


@pytest.mark.integration
class TestMonitoringAlertIntegration:
    """Integration tests for monitoring alert triggering."""

    def test_auth_failure_spike_triggers_alert(self) -> None:
        """Test that auth failure spike triggers alert."""
        alerts_received: list[Alert] = []

        def handler(alert: Alert) -> None:
            alerts_received.append(alert)

        config = MonitoringConfig(
            enabled=True,
            alert_handlers=[handler],
            rules=[
                AlertRule(
                    name="auth_spike_test",
                    alert_type=AlertType.AUTH_FAILURE_SPIKE,
                    severity=AlertSeverity.WARNING,
                    threshold=5,
                    window_seconds=60,
                    cooldown_seconds=0,
                ),
            ],
        )
        service = MonitoringService(config)

        # Generate failures below threshold
        for i in range(4):
            service.record_auth_failure(f"1.2.3.{i}", "invalid_password")

        # Check rule manually (don't rely on background thread)
        service._check_all_rules()
        initial_count = len(alerts_received)

        # Generate more failures to exceed threshold
        for i in range(3):
            service.record_auth_failure(f"5.6.7.{i}", "invalid_password")

        service._check_all_rules()

        # Should have triggered at least one more alert
        assert len(alerts_received) > initial_count

    def test_brute_force_detection_integration(self) -> None:
        """Test brute force detection with single IP."""
        alerts_received: list[Alert] = []

        def handler(alert: Alert) -> None:
            alerts_received.append(alert)

        config = MonitoringConfig(
            enabled=True,
            alert_handlers=[handler],
        )
        service = MonitoringService(config)

        # Simulate brute force from single IP
        attacker_ip = "192.168.1.100"
        for _ in range(6):
            service.record_auth_failure(attacker_ip, "wrong_password")

        # Should have triggered brute force alert
        brute_force_alerts = [
            a for a in alerts_received if a.alert_type == AlertType.AUTH_BRUTE_FORCE
        ]
        assert len(brute_force_alerts) >= 1
        assert attacker_ip in brute_force_alerts[0].details.get("client_ip", "")

    def test_cross_tenant_alert_immediate(self) -> None:
        """Test that cross-tenant attempts trigger immediate alert."""
        alerts_received: list[Alert] = []

        def handler(alert: Alert) -> None:
            alerts_received.append(alert)

        config = MonitoringConfig(
            enabled=True,
            alert_handlers=[handler],
        )
        service = MonitoringService(config)

        # Single cross-tenant attempt should trigger immediately
        service.record_cross_tenant_attempt("user1", "tenant_a", "tenant_b")

        cross_tenant_alerts = [
            a for a in alerts_received if a.alert_type == AlertType.CROSS_TENANT_ATTEMPT
        ]
        assert len(cross_tenant_alerts) == 1
        assert cross_tenant_alerts[0].severity == AlertSeverity.CRITICAL

    def test_saml_replay_alert_immediate(self) -> None:
        """Test that SAML replay triggers immediate alert."""
        alerts_received: list[Alert] = []

        def handler(alert: Alert) -> None:
            alerts_received.append(alert)

        config = MonitoringConfig(
            enabled=True,
            alert_handlers=[handler],
        )
        service = MonitoringService(config)

        service.record_saml_replay_blocked("assertion_id_123", "10.0.0.1")

        saml_alerts = [a for a in alerts_received if a.alert_type == AlertType.SAML_REPLAY]
        assert len(saml_alerts) == 1
        assert saml_alerts[0].severity == AlertSeverity.CRITICAL

    def test_multiple_alert_types_independent(self) -> None:
        """Test that different alert types trigger independently."""
        alerts_by_type: dict[AlertType, list[Alert]] = {}

        def handler(alert: Alert) -> None:
            alerts_by_type.setdefault(alert.alert_type, []).append(alert)

        config = MonitoringConfig(
            enabled=True,
            alert_handlers=[handler],
        )
        service = MonitoringService(config)

        # Trigger different alert types
        service.record_cross_tenant_attempt("user1", "t1", "t2")
        service.record_saml_replay_blocked("assertion1", "1.1.1.1")
        service.record_backup_failure("backup_1", "Disk full")

        # Each type should have its own alert
        assert AlertType.CROSS_TENANT_ATTEMPT in alerts_by_type
        assert AlertType.SAML_REPLAY in alerts_by_type
        assert AlertType.BACKUP_FAILURE in alerts_by_type

    def test_alert_cooldown_respected(self) -> None:
        """Test that alert cooldown is respected."""
        alerts_received: list[Alert] = []

        def handler(alert: Alert) -> None:
            alerts_received.append(alert)

        config = MonitoringConfig(
            enabled=True,
            alert_handlers=[handler],
            rules=[
                AlertRule(
                    name="cooldown_test",
                    alert_type=AlertType.CROSS_TENANT_ATTEMPT,
                    severity=AlertSeverity.CRITICAL,
                    threshold=1,
                    window_seconds=60,
                    cooldown_seconds=300,  # 5 minute cooldown
                ),
            ],
        )
        service = MonitoringService(config)

        # First attempt triggers
        service.record_cross_tenant_attempt("user1", "t1", "t2")
        first_count = len(alerts_received)
        assert first_count == 1

        # Second attempt within cooldown should not trigger
        service.record_cross_tenant_attempt("user2", "t3", "t4")
        assert len(alerts_received) == first_count

    def test_metrics_aggregation(self) -> None:
        """Test metrics are correctly aggregated."""
        config = MonitoringConfig(enabled=True)
        service = MonitoringService(config)

        # Generate various events
        for _ in range(5):
            service.record_auth_failure("1.2.3.4", "invalid")

        for _ in range(3):
            service.record_authz_denial("user1", "tenant1", "delete")

        for _ in range(2):
            service.record_import_failure("tenant1", "Invalid format")

        metrics = service.get_metrics()

        assert metrics["counters"]["auth_failures_total"] >= 5
        assert metrics["counters"]["authz_denials_total"] >= 3
        assert metrics["counters"]["import_failures_total"] >= 2

    def test_handler_exception_doesnt_break_alerting(self) -> None:
        """Test that handler exceptions don't break alerting."""
        good_alerts: list[Alert] = []

        def bad_handler(alert: Alert) -> None:
            raise ValueError("Handler error!")

        def good_handler(alert: Alert) -> None:
            good_alerts.append(alert)

        config = MonitoringConfig(
            enabled=True,
            alert_handlers=[bad_handler, good_handler],
        )
        service = MonitoringService(config)

        # Should not raise, and good handler should still be called
        service.record_cross_tenant_attempt("user1", "t1", "t2")

        assert len(good_alerts) == 1
