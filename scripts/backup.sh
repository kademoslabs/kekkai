#!/usr/bin/env bash
# Kekkai Portal Backup Script
# Automated backup for database, media, and audit logs
#
# Usage: ./scripts/backup.sh [full|database|media] [--config /path/to/config]
#
# Environment variables:
#   DD_DATABASE_HOST     - PostgreSQL host (default: localhost)
#   DD_DATABASE_PORT     - PostgreSQL port (default: 5432)
#   DD_DATABASE_NAME     - Database name (default: defectdojo)
#   DD_DATABASE_USER     - Database user (default: defectdojo)
#   DD_DATABASE_PASSWORD - Database password
#   BACKUP_LOCAL_PATH    - Backup storage directory (default: /var/lib/kekkai-portal/backups)
#   PORTAL_UPLOAD_DIR    - Media uploads directory
#   PORTAL_AUDIT_DIR     - Audit logs directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
BACKUP_TYPE="${1:-full}"
BACKUP_DIR="${BACKUP_LOCAL_PATH:-/var/lib/kekkai-portal/backups}"
DB_HOST="${DD_DATABASE_HOST:-localhost}"
DB_PORT="${DD_DATABASE_PORT:-5432}"
DB_NAME="${DD_DATABASE_NAME:-defectdojo}"
DB_USER="${DD_DATABASE_USER:-defectdojo}"
MEDIA_DIR="${PORTAL_UPLOAD_DIR:-/var/lib/kekkai-portal/uploads}"
AUDIT_DIR="${PORTAL_AUDIT_DIR:-}"
TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"
BACKUP_ID="${BACKUP_TYPE}_${TIMESTAMP}_$(head -c 4 /dev/urandom | xxd -p)"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for pg_dump
    if ! command -v pg_dump &> /dev/null && [[ "$BACKUP_TYPE" != "media" ]]; then
        log_error "pg_dump is required for database backups"
        exit 1
    fi

    # Create backup directory
    mkdir -p "$BACKUP_DIR"

    log_info "Prerequisites check passed"
}

backup_database() {
    log_info "Starting database backup..."
    local db_backup_file="$1/database.sql"

    if [[ -n "${DD_DATABASE_PASSWORD:-}" ]]; then
        export PGPASSWORD="$DD_DATABASE_PASSWORD"
    fi

    if pg_dump \
        -h "$DB_HOST" \
        -p "$DB_PORT" \
        -U "$DB_USER" \
        -d "$DB_NAME" \
        --format=custom \
        --no-password \
        -f "$db_backup_file" 2>/dev/null; then
        log_info "Database backup completed: $db_backup_file"
        return 0
    else
        log_error "Database backup failed"
        return 1
    fi
}

backup_media() {
    log_info "Starting media backup..."
    local media_backup_dir="$1/media"
    mkdir -p "$media_backup_dir"

    if [[ -d "$MEDIA_DIR" ]]; then
        cp -r "$MEDIA_DIR"/* "$media_backup_dir/" 2>/dev/null || true
        local file_count
        file_count=$(find "$media_backup_dir" -type f | wc -l)
        log_info "Media backup completed: $file_count files"
    else
        log_warn "Media directory not found: $MEDIA_DIR"
    fi
    return 0
}

backup_audit_logs() {
    log_info "Starting audit log backup..."
    local audit_backup_dir="$1/audit"
    mkdir -p "$audit_backup_dir"

    if [[ -n "$AUDIT_DIR" && -d "$AUDIT_DIR" ]]; then
        cp -r "$AUDIT_DIR"/* "$audit_backup_dir/" 2>/dev/null || true
        log_info "Audit log backup completed"
    elif [[ -n "$AUDIT_DIR" && -f "$AUDIT_DIR" ]]; then
        cp "$AUDIT_DIR" "$audit_backup_dir/audit.jsonl"
        log_info "Audit log backup completed"
    else
        log_warn "Audit log directory not configured or not found"
    fi
    return 0
}

create_manifest() {
    local backup_dir="$1"
    local manifest_file="$backup_dir/manifest.json"

    cat > "$manifest_file" << EOF
{
    "backup_id": "$BACKUP_ID",
    "type": "$BACKUP_TYPE",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "format_version": 1,
    "components": ["database", "media", "audit_logs"],
    "hostname": "$(hostname)",
    "db_name": "$DB_NAME"
}
EOF
    log_info "Manifest created: $manifest_file"
}

create_archive() {
    local source_dir="$1"
    local archive_name="${BACKUP_ID}.tar.gz"
    local archive_path="$BACKUP_DIR/$archive_name"

    log_info "Creating compressed archive..."
    tar -czf "$archive_path" -C "$(dirname "$source_dir")" "$(basename "$source_dir")"

    # Generate checksum
    local checksum
    checksum=$(sha256sum "$archive_path" | cut -d' ' -f1)
    echo "$checksum  $archive_name" > "${archive_path}.sha256"

    log_info "Archive created: $archive_path"
    log_info "Checksum: $checksum"

    # Cleanup temp directory
    rm -rf "$source_dir"

    echo "$archive_path"
}

cleanup_old_backups() {
    local retention_days="${BACKUP_RETENTION_DAYS:-30}"
    local retention_count="${BACKUP_RETENTION_COUNT:-10}"

    log_info "Cleaning up old backups (retention: $retention_days days, min keep: $retention_count)..."

    # Count current backups
    local backup_count
    backup_count=$(find "$BACKUP_DIR" -name "*.tar.gz" -type f | wc -l)

    if [[ $backup_count -le $retention_count ]]; then
        log_info "Backup count ($backup_count) within retention limit, skipping cleanup"
        return 0
    fi

    # Remove old backups
    find "$BACKUP_DIR" -name "*.tar.gz" -type f -mtime "+$retention_days" -delete 2>/dev/null || true
    find "$BACKUP_DIR" -name "*.sha256" -type f -mtime "+$retention_days" -delete 2>/dev/null || true

    log_info "Cleanup completed"
}

main() {
    log_info "Starting Kekkai Portal backup (type: $BACKUP_TYPE)"
    log_info "Backup ID: $BACKUP_ID"

    check_prerequisites

    # Create temporary directory for backup
    local temp_dir
    temp_dir=$(mktemp -d)
    local backup_content_dir="$temp_dir/$BACKUP_ID"
    mkdir -p "$backup_content_dir"

    case "$BACKUP_TYPE" in
        full)
            backup_database "$backup_content_dir" || true
            backup_media "$backup_content_dir"
            backup_audit_logs "$backup_content_dir"
            ;;
        database)
            backup_database "$backup_content_dir"
            ;;
        media)
            backup_media "$backup_content_dir"
            ;;
        *)
            log_error "Unknown backup type: $BACKUP_TYPE"
            log_info "Usage: $0 [full|database|media]"
            exit 1
            ;;
    esac

    create_manifest "$backup_content_dir"

    local archive_path
    archive_path=$(create_archive "$backup_content_dir")

    cleanup_old_backups

    log_info "Backup completed successfully!"
    log_info "Backup file: $archive_path"

    # Output JSON for programmatic use
    local size
    size=$(stat -f%z "$archive_path" 2>/dev/null || stat -c%s "$archive_path" 2>/dev/null || echo "0")

    echo ""
    echo "{"
    echo "  \"success\": true,"
    echo "  \"backup_id\": \"$BACKUP_ID\","
    echo "  \"path\": \"$archive_path\","
    echo "  \"size_bytes\": $size,"
    echo "  \"type\": \"$BACKUP_TYPE\""
    echo "}"
}

main "$@"
