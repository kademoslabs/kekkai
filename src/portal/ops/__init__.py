"""Production operations module for Kekkai Portal.

Provides:
- Backup/restore functionality for DB and media
- Upgrade management with version pinning and rollback
- Centralized logging and monitoring
- Secret rotation utilities

ASVS 5.0 Requirements:
- V16.4.3: Send logs to separate system
- V16.4.2: Log protection
- V13.1.4: Secret rotation schedule
- V12.1.2: Strong cipher suites
"""

from __future__ import annotations

from .backup import BackupConfig, BackupJob, BackupResult, create_backup_job
from .log_shipper import LogShipper, LogShipperConfig, ShipperType
from .monitoring import (
    AlertRule,
    AlertSeverity,
    MonitoringConfig,
    MonitoringService,
    create_monitoring_service,
)
from .restore import RestoreConfig, RestoreJob, RestoreResult, create_restore_job
from .secrets import RotationSchedule, SecretRotation
from .upgrade import UpgradeManager, UpgradeResult, VersionManifest

__all__ = [
    "BackupConfig",
    "BackupJob",
    "BackupResult",
    "create_backup_job",
    "RestoreConfig",
    "RestoreJob",
    "RestoreResult",
    "create_restore_job",
    "AlertRule",
    "AlertSeverity",
    "MonitoringConfig",
    "MonitoringService",
    "create_monitoring_service",
    "LogShipper",
    "LogShipperConfig",
    "ShipperType",
    "SecretRotation",
    "RotationSchedule",
    "UpgradeManager",
    "VersionManifest",
    "UpgradeResult",
]
