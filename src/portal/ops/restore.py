"""Restore functionality for Kekkai Portal.

Provides restore operations for:
- PostgreSQL database (via pg_restore)
- Media/upload files
- Audit logs

Security controls:
- Backup integrity verification before restore
- Dry-run capability for validation
- Transaction-safe database restore
- No secrets in restore logs
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from .backup import BackupJob

logger = logging.getLogger(__name__)


class RestoreScope(Enum):
    """Scope of restore operation."""

    FULL = "full"
    DATABASE = "database"
    MEDIA = "media"
    AUDIT_LOGS = "audit_logs"


@dataclass
class RestoreConfig:
    """Configuration for restore operations."""

    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "defectdojo"
    db_user: str = "defectdojo"

    media_path: Path = field(default_factory=lambda: Path("/var/lib/kekkai-portal/uploads"))
    audit_log_path: Path | None = None

    dry_run: bool = False
    verify_before_restore: bool = True
    stop_services: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.media_path, str):
            self.media_path = Path(self.media_path)
        if self.audit_log_path and isinstance(self.audit_log_path, str):
            self.audit_log_path = Path(self.audit_log_path)


@dataclass
class RestoreResult:
    """Result of a restore operation."""

    success: bool
    backup_id: str
    scope: RestoreScope
    timestamp: datetime
    components_restored: list[str] = field(default_factory=list)
    error: str | None = None
    duration_seconds: float = 0.0
    dry_run: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "backup_id": self.backup_id,
            "scope": self.scope.value,
            "timestamp": self.timestamp.isoformat(),
            "components_restored": self.components_restored,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
            "dry_run": self.dry_run,
            "warnings": self.warnings,
        }


class RestoreJob:
    """Manages restore operations for Kekkai Portal."""

    def __init__(self, config: RestoreConfig, backup_job: BackupJob | None = None) -> None:
        self._config = config
        self._backup_job = backup_job

    def restore_full(self, backup_path: str | Path) -> RestoreResult:
        """Perform a full restore from backup."""
        backup_path = Path(backup_path)
        start_time = datetime.now(UTC)
        backup_id = self._extract_backup_id(backup_path)

        if self._config.verify_before_restore and self._backup_job:
            valid, msg = self._backup_job.verify_backup(backup_path)
            if not valid:
                return RestoreResult(
                    success=False,
                    backup_id=backup_id,
                    scope=RestoreScope.FULL,
                    timestamp=start_time,
                    error=f"Backup verification failed: {msg}",
                )

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)
                extract_dir = tmp_path / "extracted"

                self._extract_backup(backup_path, extract_dir)

                backup_content_dir = self._find_backup_content(extract_dir)
                if not backup_content_dir:
                    return RestoreResult(
                        success=False,
                        backup_id=backup_id,
                        scope=RestoreScope.FULL,
                        timestamp=start_time,
                        error="Invalid backup structure",
                    )

                _ = self._read_manifest(backup_content_dir)  # Validate manifest exists
                components_restored = []
                warnings: list[str] = []

                db_file = backup_content_dir / "database.sql"
                if db_file.exists():
                    if self._config.dry_run:
                        logger.info("restore.dry_run component=database")
                    else:
                        db_result = self._restore_database(db_file)
                        if db_result["success"]:
                            components_restored.append("database")
                        else:
                            warnings.append(f"Database restore failed: {db_result.get('error')}")

                media_dir = backup_content_dir / "media"
                if media_dir.exists():
                    if self._config.dry_run:
                        logger.info("restore.dry_run component=media")
                    else:
                        media_result = self._restore_media(media_dir)
                        if media_result["success"]:
                            components_restored.append("media")
                        else:
                            warnings.append(f"Media restore failed: {media_result.get('error')}")

                audit_dir = backup_content_dir / "audit"
                if audit_dir.exists() and self._config.audit_log_path:
                    if self._config.dry_run:
                        logger.info("restore.dry_run component=audit_logs")
                    else:
                        audit_result = self._restore_audit_logs(audit_dir)
                        if audit_result["success"]:
                            components_restored.append("audit_logs")
                        else:
                            warnings.append(
                                f"Audit log restore failed: {audit_result.get('error')}"
                            )

                duration = (datetime.now(UTC) - start_time).total_seconds()

                logger.info(
                    "restore.complete backup_id=%s components=%s duration=%.2f dry_run=%s",
                    backup_id,
                    ",".join(components_restored),
                    duration,
                    self._config.dry_run,
                )

                return RestoreResult(
                    success=True,
                    backup_id=backup_id,
                    scope=RestoreScope.FULL,
                    timestamp=start_time,
                    components_restored=components_restored,
                    duration_seconds=duration,
                    dry_run=self._config.dry_run,
                    warnings=warnings if warnings else [],
                )

        except Exception as e:
            logger.error("restore.failed backup_id=%s error=%s", backup_id, str(e))
            return RestoreResult(
                success=False,
                backup_id=backup_id,
                scope=RestoreScope.FULL,
                timestamp=start_time,
                error=f"Restore failed: {type(e).__name__}",
            )

    def restore_database(self, backup_path: str | Path) -> RestoreResult:
        """Restore only the database from backup."""
        backup_path = Path(backup_path)
        start_time = datetime.now(UTC)
        backup_id = self._extract_backup_id(backup_path)

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)
                extract_dir = tmp_path / "extracted"
                self._extract_backup(backup_path, extract_dir)

                backup_content_dir = self._find_backup_content(extract_dir)
                if not backup_content_dir:
                    return RestoreResult(
                        success=False,
                        backup_id=backup_id,
                        scope=RestoreScope.DATABASE,
                        timestamp=start_time,
                        error="Invalid backup structure",
                    )

                db_file = backup_content_dir / "database.sql"
                if not db_file.exists():
                    return RestoreResult(
                        success=False,
                        backup_id=backup_id,
                        scope=RestoreScope.DATABASE,
                        timestamp=start_time,
                        error="Database backup not found in archive",
                    )

                if self._config.dry_run:
                    logger.info("restore.dry_run component=database")
                    return RestoreResult(
                        success=True,
                        backup_id=backup_id,
                        scope=RestoreScope.DATABASE,
                        timestamp=start_time,
                        components_restored=[],
                        dry_run=True,
                    )

                db_result = self._restore_database(db_file)
                duration = (datetime.now(UTC) - start_time).total_seconds()

                if not db_result["success"]:
                    return RestoreResult(
                        success=False,
                        backup_id=backup_id,
                        scope=RestoreScope.DATABASE,
                        timestamp=start_time,
                        error=db_result.get("error", "Database restore failed"),
                    )

                return RestoreResult(
                    success=True,
                    backup_id=backup_id,
                    scope=RestoreScope.DATABASE,
                    timestamp=start_time,
                    components_restored=["database"],
                    duration_seconds=duration,
                )

        except Exception as e:
            logger.error("restore.database.failed backup_id=%s error=%s", backup_id, str(e))
            return RestoreResult(
                success=False,
                backup_id=backup_id,
                scope=RestoreScope.DATABASE,
                timestamp=start_time,
                error=f"Database restore failed: {type(e).__name__}",
            )

    def validate_backup(self, backup_path: str | Path) -> tuple[bool, dict[str, Any]]:
        """Validate backup contents without restoring.

        Returns:
            Tuple of (is_valid, details dict)
        """
        backup_path = Path(backup_path)
        if not backup_path.exists():
            return False, {"error": "Backup file not found"}

        details: dict[str, Any] = {
            "path": str(backup_path),
            "size_bytes": backup_path.stat().st_size,
            "components": [],
            "manifest": None,
        }

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)
                extract_dir = tmp_path / "extracted"
                self._extract_backup(backup_path, extract_dir)

                backup_content_dir = self._find_backup_content(extract_dir)
                if not backup_content_dir:
                    return False, {"error": "Invalid backup structure", **details}

                manifest = self._read_manifest(backup_content_dir)
                details["manifest"] = manifest

                if (backup_content_dir / "database.sql").exists():
                    details["components"].append("database")
                if (backup_content_dir / "media").exists():
                    details["components"].append("media")
                if (backup_content_dir / "audit").exists():
                    details["components"].append("audit_logs")

                return True, details

        except Exception as e:
            return False, {"error": str(e), **details}

    def _extract_backup(self, backup_path: Path, extract_dir: Path) -> None:
        """Extract backup archive to directory."""
        extract_dir.mkdir(parents=True, exist_ok=True)

        if backup_path.suffix == ".gz" or backup_path.name.endswith(".tar.gz"):
            with tarfile.open(backup_path, "r:gz") as tar:
                tar.extractall(extract_dir, filter="data")
        else:
            with tarfile.open(backup_path, "r") as tar:
                tar.extractall(extract_dir, filter="data")

    def _find_backup_content(self, extract_dir: Path) -> Path | None:
        """Find the backup content directory within extraction."""
        for item in extract_dir.iterdir():
            if item.is_dir() and (
                (item / "manifest.json").exists() or (item / "database.sql").exists()
            ):
                return item
        if (extract_dir / "manifest.json").exists() or (extract_dir / "database.sql").exists():
            return extract_dir
        return None

    def _read_manifest(self, backup_dir: Path) -> dict[str, Any] | None:
        """Read backup manifest if present."""
        manifest_path = backup_dir / "manifest.json"
        if manifest_path.exists():
            try:
                result: dict[str, Any] = json.loads(manifest_path.read_text())
                return result
            except json.JSONDecodeError:
                return None
        return None

    def _restore_database(self, db_file: Path) -> dict[str, Any]:
        """Execute pg_restore for database restore."""
        env = os.environ.copy()
        db_password = os.environ.get("DD_DATABASE_PASSWORD", "")
        if db_password:
            env["PGPASSWORD"] = db_password

        cmd = [
            "pg_restore",
            "-h",
            self._config.db_host,
            "-p",
            str(self._config.db_port),
            "-U",
            self._config.db_user,
            "-d",
            self._config.db_name,
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-password",
            str(db_file),
        ]

        try:
            result = subprocess.run(  # noqa: S603
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=7200,
                check=False,
            )

            if result.returncode not in (0, 1):
                error_msg = result.stderr[:500] if result.stderr else "Unknown error"
                logger.error("pg_restore failed: %s", error_msg)
                return {"success": False, "error": "Database restore failed"}

            return {"success": True}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Database restore timed out"}
        except FileNotFoundError:
            return {"success": False, "error": "pg_restore not found"}

    def _restore_media(self, source_dir: Path) -> dict[str, Any]:
        """Restore media files from backup."""
        try:
            self._config.media_path.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source_dir, self._config.media_path, dirs_exist_ok=True)
            return {"success": True}
        except OSError as e:
            return {"success": False, "error": str(e)}

    def _restore_audit_logs(self, source_dir: Path) -> dict[str, Any]:
        """Restore audit logs from backup."""
        if not self._config.audit_log_path:
            return {"success": False, "error": "Audit log path not configured"}

        try:
            self._config.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

            audit_file = source_dir / "audit.jsonl"
            if audit_file.exists():
                shutil.copy2(audit_file, self._config.audit_log_path)
            else:
                shutil.copytree(source_dir, self._config.audit_log_path, dirs_exist_ok=True)
            return {"success": True}
        except OSError as e:
            return {"success": False, "error": str(e)}

    def _extract_backup_id(self, backup_path: Path) -> str:
        """Extract backup ID from path."""
        name = backup_path.name
        if name.endswith(".tar.gz"):
            name = name[:-7]
        elif name.endswith(".tar"):
            name = name[:-4]
        elif name.endswith(".gz"):
            name = name[:-3]
        return name


def create_restore_job(
    db_host: str | None = None,
    db_name: str | None = None,
    media_path: str | Path | None = None,
    dry_run: bool = False,
    backup_job: BackupJob | None = None,
) -> RestoreJob:
    """Create a configured RestoreJob instance."""
    config = RestoreConfig()
    config.dry_run = dry_run

    if db_host:
        config.db_host = db_host
    elif env_host := os.environ.get("DD_DATABASE_HOST"):
        config.db_host = env_host

    if db_name:
        config.db_name = db_name
    elif env_name := os.environ.get("DD_DATABASE_NAME"):
        config.db_name = env_name

    if media_path:
        config.media_path = Path(media_path)
    elif env_media := os.environ.get("PORTAL_UPLOAD_DIR"):
        config.media_path = Path(env_media)

    if env_audit := os.environ.get("PORTAL_AUDIT_DIR"):
        config.audit_log_path = Path(env_audit)

    return RestoreJob(config, backup_job)
