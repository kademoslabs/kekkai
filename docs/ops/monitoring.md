# Monitoring and Alerting Guide

This guide covers the monitoring and alerting system for Kekkai Portal.

## Overview

Kekkai Portal includes built-in monitoring for:

- **Authentication Events**: Login attempts, failures, brute force detection
- **Authorization Events**: Access denials, cross-tenant attempts
- **System Events**: Backup failures, import failures, SAML replay blocks
- **Metrics Collection**: Event counts, timing, resource usage

## Quick Start

### Enable Monitoring

```python
from portal.ops.monitoring import create_monitoring_service

# Create and start monitoring
monitoring = create_monitoring_service(enabled=True)
monitoring.start()

# Record events
monitoring.record_auth_failure("192.168.1.100", "invalid_password")
monitoring.record_authz_denial("user123", "tenant1", "delete")

# Get metrics
metrics = monitoring.get_metrics()
print(metrics)

# Stop when done
monitoring.stop()
```

### Configure Alerts

```python
from portal.ops.monitoring import (
    AlertRule, AlertType, AlertSeverity, MonitoringConfig, MonitoringService
)

# Custom alert rules
rules = [
    AlertRule(
        name="custom_auth_spike",
        alert_type=AlertType.AUTH_FAILURE_SPIKE,
        severity=AlertSeverity.WARNING,
        threshold=10,
        window_seconds=300,
        description="More than 10 auth failures in 5 minutes"
    ),
]

config = MonitoringConfig(enabled=True, rules=rules)
service = MonitoringService(config)
```

## Alert Types

### Authentication Alerts

| Type | Severity | Default Threshold | Description |
|------|----------|-------------------|-------------|
| `AUTH_FAILURE_SPIKE` | Warning | 10 in 5min | Multiple auth failures across system |
| `AUTH_BRUTE_FORCE` | Critical | 5 in 1min per IP | Potential brute force from single IP |

### Authorization Alerts

| Type | Severity | Default Threshold | Description |
|------|----------|-------------------|-------------|
| `AUTHZ_DENIAL` | Warning | 5 in 5min | Multiple authorization denials |
| `CROSS_TENANT_ATTEMPT` | Critical | 1 | Any cross-tenant access attempt |

### System Alerts

| Type | Severity | Default Threshold | Description |
|------|----------|-------------------|-------------|
| `SAML_REPLAY` | Critical | 1 | SAML replay attack blocked |
| `IMPORT_FAILURE` | Warning | 3 in 10min | Multiple scan import failures |
| `BACKUP_FAILURE` | Critical | 1 | Backup job failed |

## Alert Handlers

### Built-in Handlers

```python
from portal.ops.monitoring import log_alert_handler, webhook_alert_handler_factory

# Log to standard logger
monitoring.add_alert_handler(log_alert_handler)

# Send to webhook
webhook_handler = webhook_alert_handler_factory("https://alerts.example.com/webhook")
monitoring.add_alert_handler(webhook_handler)
```

### Custom Handler

```python
def slack_handler(alert):
    import urllib.request
    import json

    payload = {
        "text": f":warning: *{alert.rule_name}*\n{alert.message}",
        "attachments": [{
            "color": "danger" if alert.severity.value == "critical" else "warning",
            "fields": [
                {"title": "Type", "value": alert.alert_type.value, "short": True},
                {"title": "Severity", "value": alert.severity.value, "short": True},
            ]
        }]
    }

    req = urllib.request.Request(
        "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req)

monitoring.add_alert_handler(slack_handler)
```

## Centralized Logging

### Log Shipping Configuration

```python
from portal.ops.log_shipper import create_log_shipper, ShipperType

# Ship to syslog
syslog_shipper = create_log_shipper(
    ShipperType.SYSLOG,
    host="syslog.example.com",
    port=514,
    protocol="tcp"
)

# Ship to webhook (e.g., Splunk, ELK)
webhook_shipper = create_log_shipper(
    ShipperType.WEBHOOK,
    url="https://logs.example.com/v1/ingest",
    auth="Bearer your-token"
)

# Ship to file (for rotation)
file_shipper = create_log_shipper(
    ShipperType.FILE,
    path="/var/log/kekkai/shipped.jsonl"
)
```

### Start Shipping

```python
# Start background shipping
shipper.start()

# Ship log entries
from portal.ops.log_shipper import LogEntry
from datetime import datetime, UTC

entry = LogEntry(
    timestamp=datetime.now(UTC),
    level="WARNING",
    message="Suspicious activity detected",
    metadata={"user_id": "user123", "action": "failed_login"}
)
shipper.ship(entry)

# Or ship dictionaries directly
shipper.ship_dict({
    "message": "Import completed",
    "tenant_id": "tenant1",
    "file_count": 5
}, level="INFO")

# Stop and flush
shipper.stop()
```

### Log Format

```json
{
    "timestamp": "2024-01-15T12:00:00.000000+00:00",
    "level": "WARNING",
    "message": "Authentication failed",
    "source": "kekkai-portal",
    "metadata": {
        "client_ip": "192.168.1.100",
        "reason": "invalid_password"
    },
    "hash": "abc123def456..."
}
```

## Metrics Collection

### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `auth_failures` | Counter | ip | Auth failures by IP |
| `auth_failures_total` | Counter | - | Total auth failures |
| `authz_denials` | Counter | user, tenant | Authz denials by user/tenant |
| `authz_denials_total` | Counter | - | Total authz denials |
| `import_failures` | Counter | tenant | Import failures by tenant |
| `cross_tenant_attempts` | Counter | user, source, target | Cross-tenant attempts |
| `saml_replay_blocked` | Counter | ip | SAML replays blocked |
| `backup_failures` | Counter | - | Backup job failures |

### Querying Metrics

```python
from portal.ops.monitoring import MetricsCollector

collector = MetricsCollector(retention_hours=24)

# Get count in window
auth_failures = collector.get_count("auth_failures_total", window_seconds=3600)
print(f"Auth failures in last hour: {auth_failures}")

# Get events with details
events = collector.get_events_in_window(
    "auth_failures",
    window_seconds=300,
    labels={"ip": "192.168.1.100"}
)
for timestamp, count in events:
    print(f"{timestamp}: {count} failures")

# Get all metrics snapshot
snapshot = collector.get_all_metrics()
print(snapshot)
```

## Integration with External Systems

### Prometheus

Export metrics in Prometheus format:

```python
def prometheus_metrics_handler():
    metrics = monitoring.get_metrics()
    lines = []

    for name, value in metrics["counters"].items():
        lines.append(f"kekkai_{name} {value}")

    return "\n".join(lines)

# Add to web app
@app.route("/metrics")
def metrics():
    return prometheus_metrics_handler(), 200, {"Content-Type": "text/plain"}
```

### Grafana Dashboard

Example Grafana queries:

```promql
# Auth failure rate
rate(kekkai_auth_failures_total[5m])

# Cross-tenant attempts
increase(kekkai_cross_tenant_attempts[1h])

# Backup failure events
kekkai_backup_failures
```

### PagerDuty Integration

```python
def pagerduty_handler(alert):
    import urllib.request
    import json

    if alert.severity != AlertSeverity.CRITICAL:
        return

    payload = {
        "routing_key": "YOUR_ROUTING_KEY",
        "event_action": "trigger",
        "payload": {
            "summary": alert.message,
            "severity": "critical",
            "source": "kekkai-portal",
            "custom_details": alert.details
        }
    }

    req = urllib.request.Request(
        "https://events.pagerduty.com/v2/enqueue",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req)

monitoring.add_alert_handler(pagerduty_handler)
```

## ASVS Compliance

The monitoring system addresses these ASVS 5.0 requirements:

| Requirement | Implementation |
|-------------|----------------|
| V16.4.3 (Send logs to separate system) | Log shipper supports syslog, webhook, file destinations |
| V16.4.2 (Log protection) | Hash chain integrity for log entries |
| V16.3.2 (Log failed authz) | `record_authz_denial()` captures all denials |
| V16.3.1 (Log auth events) | `record_auth_failure()` captures all failures |

## Troubleshooting

### High Alert Volume

If receiving too many alerts:

1. Increase thresholds
2. Extend cooldown periods
3. Filter by severity

```python
rules = [
    AlertRule(
        name="auth_spike",
        alert_type=AlertType.AUTH_FAILURE_SPIKE,
        threshold=50,  # Higher threshold
        window_seconds=600,  # Longer window
        cooldown_seconds=1800  # 30 min cooldown
    )
]
```

### Missing Events

Check that:

1. Monitoring is enabled
2. Background thread is running
3. Buffer isn't overflowing

```python
# Check stats
stats = shipper.get_stats()
print(f"Shipped: {stats['shipped']}")
print(f"Failed: {stats['failed']}")
print(f"Dropped: {stats['dropped']}")  # Buffer overflow
```

### Log Shipping Failures

Enable debug logging:

```python
import logging
logging.getLogger("portal.ops.log_shipper").setLevel(logging.DEBUG)
```

Common issues:
- Network connectivity
- Authentication failures
- Rate limiting by destination
