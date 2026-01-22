# Backup and Restore Guide

This guide covers backup and restore operations for Kekkai Portal.

## Overview

Kekkai Portal provides automated backup and restore capabilities for:

- **PostgreSQL Database**: Full database backup using `pg_dump`
- **Media Files**: User uploads and attachments
- **Audit Logs**: Compliance and security event logs

## Quick Start

### Creating a Backup

```bash
# Full backup (database + media + audit logs)
./scripts/backup.sh full

# Database only
./scripts/backup.sh database

# Media files only
./scripts/backup.sh media
```

### Restoring from Backup

```bash
# Validate backup first (dry-run)
./scripts/restore.sh /path/to/backup.tar.gz --dry-run

# Full restore
./scripts/restore.sh /path/to/backup.tar.gz

# Database only
./scripts/restore.sh /path/to/backup.tar.gz --database-only
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DD_DATABASE_HOST` | PostgreSQL host | `localhost` |
| `DD_DATABASE_PORT` | PostgreSQL port | `5432` |
| `DD_DATABASE_NAME` | Database name | `defectdojo` |
| `DD_DATABASE_USER` | Database user | `defectdojo` |
| `DD_DATABASE_PASSWORD` | Database password | (required) |
| `BACKUP_LOCAL_PATH` | Backup storage directory | `/var/lib/kekkai-portal/backups` |
| `PORTAL_UPLOAD_DIR` | Media uploads directory | `/var/lib/kekkai-portal/uploads` |
| `PORTAL_AUDIT_DIR` | Audit logs directory | (optional) |
| `BACKUP_RETENTION_DAYS` | Days to keep backups | `30` |
| `BACKUP_RETENTION_COUNT` | Minimum backups to keep | `10` |

### Python API

```python
from portal.ops.backup import BackupConfig, BackupJob, create_backup_job
from portal.ops.restore import RestoreJob, create_restore_job

# Create backup
backup_job = create_backup_job(
    local_path="/var/backups/kekkai",
    db_host="localhost",
    media_path="/var/lib/kekkai-portal/uploads"
)

# Run full backup
result = backup_job.backup_full()
if result.success:
    print(f"Backup created: {result.destination_path}")
    print(f"Checksum: {result.checksum}")

# Verify backup integrity
valid, message = backup_job.verify_backup(result.destination_path)
print(f"Integrity check: {message}")

# Restore
restore_job = create_restore_job(dry_run=True)  # Validate first
restore_result = restore_job.restore_full("/path/to/backup.tar.gz")
```

## Backup Structure

Each backup archive contains:

```
backup_id/
├── manifest.json       # Backup metadata
├── database.sql        # PostgreSQL custom format dump
├── media/              # User uploads
│   ├── upload1.json
│   └── upload2.sarif
└── audit/              # Audit logs
    └── audit.jsonl
```

### Manifest Format

```json
{
    "backup_id": "full_20240115_120000_abc123",
    "type": "full",
    "timestamp": "2024-01-15T12:00:00Z",
    "format_version": 1,
    "components": ["database", "media", "audit_logs"],
    "hostname": "portal-server",
    "db_name": "defectdojo"
}
```

## Integrity Verification

All backups include SHA-256 checksums for integrity verification:

```bash
# Manual verification
sha256sum -c backup.tar.gz.sha256

# Using the API
backup_job.verify_backup("/path/to/backup.tar.gz")
```

## Retention Policy

Backups are automatically cleaned up based on:

1. **Age**: Backups older than `BACKUP_RETENTION_DAYS` are removed
2. **Count**: At least `BACKUP_RETENTION_COUNT` backups are always kept

Configure retention in your backup schedule:

```python
config = BackupConfig(
    retention_days=30,
    retention_count=10
)
```

## Restore Procedures

### Pre-Restore Checklist

1. Verify backup integrity
2. Note current system state
3. Plan for downtime
4. Notify affected users
5. Have rollback plan ready

### Database Restore

The restore uses `pg_restore` with these options:

- `--clean`: Drop existing objects before restore
- `--if-exists`: Don't error if objects don't exist
- `--no-owner`: Don't set object ownership

```bash
# Restore database only
./scripts/restore.sh backup.tar.gz --database-only
```

### Media Restore

Media files are copied to the configured upload directory:

```bash
# Restore media only
./scripts/restore.sh backup.tar.gz --media-only
```

## Scheduled Backups

### Using cron

```cron
# Daily full backup at 2 AM
0 2 * * * /opt/kekkai/scripts/backup.sh full >> /var/log/kekkai-backup.log 2>&1

# Hourly database backup
0 * * * * /opt/kekkai/scripts/backup.sh database >> /var/log/kekkai-backup.log 2>&1
```

### Using systemd timer

Create `/etc/systemd/system/kekkai-backup.service`:

```ini
[Unit]
Description=Kekkai Portal Backup

[Service]
Type=oneshot
ExecStart=/opt/kekkai/scripts/backup.sh full
Environment=DD_DATABASE_PASSWORD=your_password
```

Create `/etc/systemd/system/kekkai-backup.timer`:

```ini
[Unit]
Description=Daily Kekkai Backup

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:

```bash
systemctl enable --now kekkai-backup.timer
```

## Disaster Recovery

### Full System Recovery

1. **Restore infrastructure** (containers, networking)
2. **Restore database first**:
   ```bash
   ./scripts/restore.sh backup.tar.gz --database-only --force
   ```
3. **Restore media files**:
   ```bash
   ./scripts/restore.sh backup.tar.gz --media-only
   ```
4. **Verify services**:
   ```bash
   curl http://localhost:8000/api/v1/health
   ```

### Point-in-Time Recovery

For PostgreSQL point-in-time recovery, consider enabling WAL archiving in your DefectDojo PostgreSQL configuration.

## Troubleshooting

### Common Issues

**pg_dump not found**
```bash
# Install PostgreSQL client
apt-get install postgresql-client-16
```

**Permission denied**
```bash
# Ensure backup user has required permissions
chmod 755 /var/lib/kekkai-portal/backups
chown kekkai:kekkai /var/lib/kekkai-portal/backups
```

**Backup too large**
- Enable compression (default)
- Implement incremental backups
- Archive older backups to cold storage

### Restore Failures

**Checksum mismatch**
- Backup may be corrupted during transfer
- Re-transfer from source
- Verify source checksum

**Database restore errors**
- Check PostgreSQL logs
- Ensure target database exists
- Verify user permissions

## Security Considerations

- Store backup encryption keys separately from backups
- Use encrypted transfer for off-site backups
- Restrict access to backup storage
- Regularly test restore procedures
- Audit backup access logs
