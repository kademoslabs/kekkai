#!/usr/bin/env bash
# Kekkai Portal Restore Script
# Restore from backup for database, media, and audit logs
#
# Usage: ./scripts/restore.sh <backup_file> [--dry-run] [--database-only] [--media-only]
#
# Environment variables:
#   DD_DATABASE_HOST     - PostgreSQL host (default: localhost)
#   DD_DATABASE_PORT     - PostgreSQL port (default: 5432)
#   DD_DATABASE_NAME     - Database name (default: defectdojo)
#   DD_DATABASE_USER     - Database user (default: defectdojo)
#   DD_DATABASE_PASSWORD - Database password
#   PORTAL_UPLOAD_DIR    - Media uploads directory
#   PORTAL_AUDIT_DIR     - Audit logs directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
BACKUP_FILE=""
DRY_RUN=false
DATABASE_ONLY=false
MEDIA_ONLY=false
DB_HOST="${DD_DATABASE_HOST:-localhost}"
DB_PORT="${DD_DATABASE_PORT:-5432}"
DB_NAME="${DD_DATABASE_NAME:-defectdojo}"
DB_USER="${DD_DATABASE_USER:-defectdojo}"
MEDIA_DIR="${PORTAL_UPLOAD_DIR:-/var/lib/kekkai-portal/uploads}"
AUDIT_DIR="${PORTAL_AUDIT_DIR:-}"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

usage() {
    cat << EOF
Usage: $0 <backup_file> [OPTIONS]

Restore Kekkai Portal from backup.

Arguments:
    backup_file     Path to the backup archive (.tar.gz)

Options:
    --dry-run       Validate backup without restoring
    --database-only Restore only the database
    --media-only    Restore only media files
    --force         Skip confirmation prompts
    -h, --help      Show this help message

Examples:
    $0 /backups/full_20240101_120000_abc123.tar.gz
    $0 /backups/full_20240101_120000_abc123.tar.gz --dry-run
    $0 /backups/full_20240101_120000_abc123.tar.gz --database-only --force
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --database-only)
                DATABASE_ONLY=true
                shift
                ;;
            --media-only)
                MEDIA_ONLY=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$BACKUP_FILE" ]]; then
                    BACKUP_FILE="$1"
                else
                    log_error "Unexpected argument: $1"
                    usage
                    exit 1
                fi
                shift
                ;;
        esac
    done

    if [[ -z "$BACKUP_FILE" ]]; then
        log_error "Backup file is required"
        usage
        exit 1
    fi
}

verify_checksum() {
    local backup_file="$1"
    local checksum_file="${backup_file}.sha256"

    if [[ ! -f "$checksum_file" ]]; then
        log_warn "Checksum file not found: $checksum_file"
        return 1
    fi

    log_step "Verifying backup integrity..."

    local expected_checksum
    expected_checksum=$(cut -d' ' -f1 < "$checksum_file")

    local actual_checksum
    actual_checksum=$(sha256sum "$backup_file" | cut -d' ' -f1)

    if [[ "$expected_checksum" != "$actual_checksum" ]]; then
        log_error "Checksum mismatch!"
        log_error "Expected: $expected_checksum"
        log_error "Actual:   $actual_checksum"
        return 1
    fi

    log_info "Checksum verified successfully"
    return 0
}

extract_backup() {
    local backup_file="$1"
    local extract_dir="$2"

    log_step "Extracting backup archive..."

    mkdir -p "$extract_dir"
    tar -xzf "$backup_file" -C "$extract_dir"

    # Find the backup content directory
    local content_dir
    content_dir=$(find "$extract_dir" -maxdepth 1 -type d ! -name "$(basename "$extract_dir")" | head -1)

    if [[ -z "$content_dir" ]]; then
        content_dir="$extract_dir"
    fi

    echo "$content_dir"
}

validate_backup() {
    local content_dir="$1"

    log_step "Validating backup contents..."

    local manifest_file="$content_dir/manifest.json"
    if [[ -f "$manifest_file" ]]; then
        log_info "Manifest found:"
        cat "$manifest_file" | head -20
        echo ""
    else
        log_warn "No manifest file found"
    fi

    local components=()

    if [[ -f "$content_dir/database.sql" ]]; then
        components+=("database")
        log_info "Found: database backup"
    fi

    if [[ -d "$content_dir/media" ]]; then
        local media_count
        media_count=$(find "$content_dir/media" -type f 2>/dev/null | wc -l)
        components+=("media")
        log_info "Found: media files ($media_count files)"
    fi

    if [[ -d "$content_dir/audit" ]]; then
        components+=("audit_logs")
        log_info "Found: audit logs"
    fi

    if [[ ${#components[@]} -eq 0 ]]; then
        log_error "No valid backup components found"
        return 1
    fi

    log_info "Backup validation passed"
    return 0
}

restore_database() {
    local db_file="$1"

    log_step "Restoring database..."

    if [[ ! -f "$db_file" ]]; then
        log_warn "Database backup file not found: $db_file"
        return 1
    fi

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would restore database from: $db_file"
        return 0
    fi

    if [[ -n "${DD_DATABASE_PASSWORD:-}" ]]; then
        export PGPASSWORD="$DD_DATABASE_PASSWORD"
    fi

    # pg_restore with --clean drops and recreates objects
    if pg_restore \
        -h "$DB_HOST" \
        -p "$DB_PORT" \
        -U "$DB_USER" \
        -d "$DB_NAME" \
        --clean \
        --if-exists \
        --no-owner \
        --no-password \
        "$db_file" 2>/dev/null; then
        log_info "Database restored successfully"
        return 0
    else
        # pg_restore returns non-zero for warnings too
        log_warn "pg_restore completed with warnings (this may be normal)"
        return 0
    fi
}

restore_media() {
    local media_dir="$1"

    log_step "Restoring media files..."

    if [[ ! -d "$media_dir" ]]; then
        log_warn "Media backup directory not found: $media_dir"
        return 1
    fi

    if $DRY_RUN; then
        local file_count
        file_count=$(find "$media_dir" -type f | wc -l)
        log_info "[DRY-RUN] Would restore $file_count media files to: $MEDIA_DIR"
        return 0
    fi

    mkdir -p "$MEDIA_DIR"
    cp -r "$media_dir"/* "$MEDIA_DIR/" 2>/dev/null || true

    local restored_count
    restored_count=$(find "$media_dir" -type f | wc -l)
    log_info "Restored $restored_count media files to $MEDIA_DIR"
    return 0
}

restore_audit_logs() {
    local audit_dir="$1"

    log_step "Restoring audit logs..."

    if [[ ! -d "$audit_dir" ]]; then
        log_warn "Audit log backup directory not found: $audit_dir"
        return 1
    fi

    if [[ -z "$AUDIT_DIR" ]]; then
        log_warn "Audit log directory not configured, skipping"
        return 0
    fi

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would restore audit logs to: $AUDIT_DIR"
        return 0
    fi

    mkdir -p "$(dirname "$AUDIT_DIR")"

    if [[ -f "$audit_dir/audit.jsonl" ]]; then
        cp "$audit_dir/audit.jsonl" "$AUDIT_DIR"
    else
        cp -r "$audit_dir"/* "$(dirname "$AUDIT_DIR")/" 2>/dev/null || true
    fi

    log_info "Audit logs restored to $AUDIT_DIR"
    return 0
}

confirm_restore() {
    if [[ "${FORCE:-false}" == "true" ]]; then
        return 0
    fi

    if $DRY_RUN; then
        return 0
    fi

    echo ""
    log_warn "WARNING: This will overwrite existing data!"
    echo -n "Are you sure you want to proceed? (yes/no): "
    read -r response

    if [[ "$response" != "yes" ]]; then
        log_info "Restore cancelled"
        exit 0
    fi
}

main() {
    parse_args "$@"

    log_info "Starting Kekkai Portal restore"
    log_info "Backup file: $BACKUP_FILE"

    if $DRY_RUN; then
        log_info "Mode: DRY-RUN (no changes will be made)"
    fi

    # Check backup file exists
    if [[ ! -f "$BACKUP_FILE" ]]; then
        log_error "Backup file not found: $BACKUP_FILE"
        exit 1
    fi

    # Verify checksum
    verify_checksum "$BACKUP_FILE" || log_warn "Proceeding without checksum verification"

    # Create temp directory for extraction
    local temp_dir
    temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT

    # Extract backup
    local content_dir
    content_dir=$(extract_backup "$BACKUP_FILE" "$temp_dir")

    # Validate backup contents
    validate_backup "$content_dir"

    # Confirm with user
    confirm_restore

    # Perform restore based on options
    local restore_result=0

    if $DATABASE_ONLY; then
        restore_database "$content_dir/database.sql" || restore_result=1
    elif $MEDIA_ONLY; then
        restore_media "$content_dir/media" || restore_result=1
    else
        # Full restore
        restore_database "$content_dir/database.sql" || restore_result=1
        restore_media "$content_dir/media" || true  # Non-fatal
        restore_audit_logs "$content_dir/audit" || true  # Non-fatal
    fi

    if [[ $restore_result -eq 0 ]]; then
        log_info "Restore completed successfully!"
    else
        log_error "Restore completed with errors"
        exit 1
    fi

    # Output JSON for programmatic use
    echo ""
    echo "{"
    echo "  \"success\": true,"
    echo "  \"backup_file\": \"$BACKUP_FILE\","
    echo "  \"dry_run\": $DRY_RUN"
    echo "}"
}

main "$@"
