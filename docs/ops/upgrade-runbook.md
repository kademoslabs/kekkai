# Upgrade Runbook

This runbook provides procedures for upgrading Kekkai Portal components safely.

## Overview

The upgrade system provides:

- **Version Manifest**: Tracks all component versions
- **Pre-upgrade Checks**: Validates system health before upgrade
- **Rollback Capability**: Safe recovery from failed upgrades
- **Migration Tracking**: Database migration status

## Version Manifest

### Location

The version manifest is stored at:
- Default: `/var/lib/kekkai-portal/version-manifest.json`
- Override: Set `VERSION_MANIFEST_PATH` environment variable

### Structure

```json
{
    "manifest_version": 1,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-15T12:00:00Z",
    "components": [
        {
            "component": "portal",
            "current_version": "1.0.0",
            "target_version": null,
            "image_digest": null,
            "pinned": true
        },
        {
            "component": "defectdojo",
            "current_version": "2.37.0",
            "image_digest": "sha256:abc123...",
            "pinned": true
        }
    ],
    "environment": "production",
    "notes": "Initial deployment"
}
```

### Components

| Component | Description |
|-----------|-------------|
| `portal` | Kekkai Portal application |
| `defectdojo` | DefectDojo backend |
| `postgres` | PostgreSQL database |
| `nginx` | Reverse proxy |
| `valkey` | Cache/queue backend |

## Pre-Upgrade Checklist

Before any upgrade:

- [ ] Review release notes for target version
- [ ] Verify backup exists and is recent (< 24 hours)
- [ ] Check disk space (< 90% usage)
- [ ] Verify database connectivity
- [ ] Notify stakeholders of maintenance window
- [ ] Test rollback procedure in staging

## Upgrade Procedures

### Using Python API

```python
from portal.ops.upgrade import UpgradeManager, ComponentType

# Initialize manager
manager = UpgradeManager()

# Run pre-upgrade checks
checks = manager.run_pre_upgrade_checks()
for check in checks:
    status = "PASS" if check.passed else "FAIL"
    print(f"{check.name}: {status} - {check.message}")

# Check if all passed
if all(c.passed for c in checks):
    # Dry run first
    result = manager.upgrade_component(
        ComponentType.PORTAL,
        target_version="2.0.0",
        dry_run=True
    )

    if result.success:
        # Actual upgrade
        result = manager.upgrade_component(
            ComponentType.PORTAL,
            target_version="2.0.0",
            create_backup=True
        )

        if result.success:
            print(f"Upgrade complete in {result.duration_seconds:.1f}s")
        else:
            print(f"Upgrade failed: {result.error}")
            # Rollback available
            if result.rollback_available:
                manager.rollback(result.backup_id)
```

### Using Shell Scripts

```bash
# Create pre-upgrade backup
./scripts/backup.sh full

# Upgrade portal
docker pull kekkai-portal:2.0.0
docker-compose up -d portal

# Verify health
curl http://localhost:8000/api/v1/health

# If failed, rollback
docker-compose down
./scripts/restore.sh /var/lib/kekkai-portal/backups/latest.tar.gz
docker-compose up -d
```

## Component-Specific Procedures

### Portal Upgrade

1. Create backup
2. Pull new container image
3. Update docker-compose.yml with new version
4. Run database migrations (if any)
5. Restart portal service
6. Verify health endpoint

```bash
# Example
docker pull ghcr.io/kademoslabs/kekkai-portal:v2.0.0
docker-compose up -d --no-deps portal
curl http://localhost:8000/api/v1/health
```

### DefectDojo Upgrade

DefectDojo upgrades require careful migration handling:

1. Review DefectDojo release notes
2. Create full backup
3. Stop celery workers
4. Update DefectDojo version in compose
5. Run migrations
6. Start services
7. Verify API access

```bash
# Stop workers
docker-compose stop celeryworker celerybeat

# Update version
sed -i 's/DOJO_VERSION=.*/DOJO_VERSION=2.38.0/' .env

# Restart (initializer runs migrations)
docker-compose up -d

# Verify
curl http://localhost:8080/api/v2/users/
```

### Database Upgrade (PostgreSQL)

PostgreSQL major version upgrades require data export/import:

1. Create full backup
2. Stop all services
3. Export data using pg_dump
4. Start new PostgreSQL version
5. Import data using pg_restore
6. Update connection strings
7. Start services
8. Verify connectivity

### Nginx Upgrade

1. Test new config syntax
2. Pull new image
3. Reload configuration
4. Verify HTTPS and proxying

```bash
# Test config
docker run --rm -v $(pwd)/nginx.conf:/etc/nginx/nginx.conf:ro nginx:1.26-alpine nginx -t

# Update
docker pull nginx:1.26-alpine
docker-compose up -d nginx
```

## Rollback Procedures

### Automatic Rollback

If an upgrade fails and a pre-upgrade backup was created:

```python
from portal.ops.upgrade import UpgradeManager

manager = UpgradeManager()
result = manager.rollback("backup_20240115_120000_abc123")

if result.success:
    print("Rollback completed")
else:
    print(f"Rollback failed: {result.error}")
```

### Manual Rollback

```bash
# Stop services
docker-compose down

# Restore from backup
./scripts/restore.sh /var/lib/kekkai-portal/backups/pre_upgrade.tar.gz

# Revert docker images
docker tag kekkai-portal:2.0.0 kekkai-portal:failed
docker tag kekkai-portal:1.0.0 kekkai-portal:latest

# Start services
docker-compose up -d

# Verify
curl http://localhost:8000/api/v1/health
```

## Health Checks

### Pre-Upgrade Checks

| Check | Criteria | Action if Failed |
|-------|----------|------------------|
| `disk_space` | < 90% usage | Free space or expand storage |
| `database_connection` | pg_isready returns 0 | Check PostgreSQL status |
| `services_running` | All containers healthy | Investigate unhealthy services |
| `backup_recent` | Backup < 24 hours old | Create new backup |

### Post-Upgrade Verification

1. **Health Endpoint**:
   ```bash
   curl http://localhost:8000/api/v1/health
   ```

2. **Database Connectivity**:
   ```bash
   docker exec portal-db psql -U defectdojo -c "SELECT 1"
   ```

3. **API Access**:
   ```bash
   curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/upload
   ```

4. **UI Access**:
   - Login to portal
   - Verify dashboard loads
   - Check recent uploads visible

## Troubleshooting

### Upgrade Stuck

```bash
# Check container logs
docker-compose logs portal

# Check for failed migrations
docker exec portal-django python manage.py showmigrations

# Force migration
docker exec portal-django python manage.py migrate --fake-initial
```

### Database Connection Lost

```bash
# Restart database
docker-compose restart postgres

# Check connection
docker exec postgres pg_isready

# Check logs
docker-compose logs postgres
```

### Version Mismatch

If manifest version doesn't match actual:

```python
from portal.ops.upgrade import UpgradeManager, ComponentVersion, ComponentType

manager = UpgradeManager()
manifest = manager.get_manifest()

# Update to actual version
manifest.set_component(ComponentVersion(
    component=ComponentType.PORTAL,
    current_version="2.0.0"  # Actual running version
))
manager.save_manifest()
```

## Maintenance Windows

### Recommended Schedule

| Day | Time (UTC) | Activity |
|-----|------------|----------|
| Monday | 02:00-04:00 | Minor updates |
| Wednesday | 02:00-04:00 | Security patches |
| Saturday | 02:00-06:00 | Major upgrades |

### Communication Template

```
Subject: Kekkai Portal Maintenance - [DATE]

Scheduled maintenance window:
- Start: [DATE TIME UTC]
- Duration: ~[X] hours
- Services affected: [LIST]

Updates being applied:
- [COMPONENT] v[OLD] -> v[NEW]
- [DESCRIPTION OF CHANGES]

Expected impact:
- [DOWNTIME/READONLY/ETC]

Contact for issues:
- [CONTACT INFO]
```

## Security Considerations

- Pin all image versions by digest in production
- Verify image signatures before pulling
- Review CVEs fixed in new versions
- Update secrets if rotation due
- Audit trail all upgrade operations
