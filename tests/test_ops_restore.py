"""Unit tests for restore operations."""

from __future__ import annotations

import gzip
import json
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from portal.ops.backup import BackupConfig, BackupJob
from portal.ops.restore import (
    RestoreConfig,
    RestoreJob,
    RestoreResult,
    RestoreScope,
    create_restore_job,
)


class TestRestoreConfig:
    """Tests for RestoreConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = RestoreConfig()
        assert config.db_host == "localhost"
        assert config.db_port == 5432
        assert config.dry_run is False
        assert config.verify_before_restore is True

    def test_config_path_conversion(self) -> None:
        """Test string to Path conversion."""
        config = RestoreConfig(media_path="/tmp/media")  # type: ignore
        assert isinstance(config.media_path, Path)


class TestRestoreResult:
    """Tests for RestoreResult."""

    def test_result_to_dict(self) -> None:
        """Test result serialization."""
        result = RestoreResult(
            success=True,
            backup_id="test_123",
            scope=RestoreScope.FULL,
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            components_restored=["database", "media"],
        )
        data = result.to_dict()

        assert data["success"] is True
        assert data["backup_id"] == "test_123"
        assert data["scope"] == "full"
        assert "database" in data["components_restored"]


class TestRestoreJob:
    """Tests for RestoreJob."""

    def _create_test_backup(self, backup_dir: Path, backup_id: str = "test_backup") -> Path:
        """Create a test backup archive."""
        content_dir = backup_dir / "content" / backup_id
        content_dir.mkdir(parents=True)

        # Create database file
        (content_dir / "database.sql").write_bytes(b"fake pg_dump output")

        # Create media directory
        media_dir = content_dir / "media"
        media_dir.mkdir()
        (media_dir / "upload.txt").write_text("user upload")

        # Create audit directory
        audit_dir = content_dir / "audit"
        audit_dir.mkdir()
        (audit_dir / "audit.jsonl").write_text('{"event": "test"}\n')

        # Create manifest
        manifest = {
            "backup_id": backup_id,
            "type": "full",
            "timestamp": datetime.now(UTC).isoformat(),
            "format_version": 1,
            "components": ["database", "media", "audit_logs"],
        }
        (content_dir / "manifest.json").write_text(json.dumps(manifest))

        # Create tar.gz archive
        archive_path = backup_dir / f"{backup_id}.tar.gz"
        with (
            gzip.open(archive_path, "wb") as gz_file,
            tarfile.open(fileobj=gz_file, mode="w") as tar,
        ):
            tar.add(content_dir, arcname=backup_id)

        # Create checksum file
        import hashlib

        with open(archive_path, "rb") as f:
            checksum = hashlib.sha256(f.read()).hexdigest()
        (archive_path.with_suffix(".gz.sha256")).write_text(f"{checksum}  {backup_id}.tar.gz")

        return archive_path

    def test_extract_backup_id(self) -> None:
        """Test backup ID extraction from path."""
        config = RestoreConfig()
        job = RestoreJob(config)

        assert job._extract_backup_id(Path("/backup/full_20240101.tar.gz")) == "full_20240101"
        assert job._extract_backup_id(Path("/backup/db_backup.tar")) == "db_backup"

    def test_validate_backup_nonexistent(self) -> None:
        """Test validation of nonexistent backup."""
        config = RestoreConfig()
        job = RestoreJob(config)

        valid, details = job.validate_backup("/nonexistent/backup.tar.gz")
        assert valid is False
        assert "not found" in details["error"].lower()

    def test_validate_backup_valid(self) -> None:
        """Test validation of valid backup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir)
            archive_path = self._create_test_backup(backup_dir)

            config = RestoreConfig()
            job = RestoreJob(config)

            valid, details = job.validate_backup(archive_path)
            assert valid is True
            assert "database" in details["components"]
            assert "media" in details["components"]

    def test_restore_full_dry_run(self) -> None:
        """Test full restore in dry-run mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()
            archive_path = self._create_test_backup(backup_dir)

            config = RestoreConfig(dry_run=True, verify_before_restore=False)
            job = RestoreJob(config)

            result = job.restore_full(archive_path)
            assert result.success is True
            assert result.dry_run is True
            assert result.scope == RestoreScope.FULL

    @patch("portal.ops.restore.subprocess.run")
    def test_restore_database_success(self, mock_run: MagicMock) -> None:
        """Test successful database restore."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()
            archive_path = self._create_test_backup(backup_dir)

            config = RestoreConfig(verify_before_restore=False)
            job = RestoreJob(config)

            result = job.restore_database(archive_path)
            assert result.success is True
            assert "database" in result.components_restored

    @patch("portal.ops.restore.subprocess.run")
    def test_restore_database_pg_restore_not_found(self, mock_run: MagicMock) -> None:
        """Test database restore when pg_restore is not found."""
        mock_run.side_effect = FileNotFoundError()

        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()
            archive_path = self._create_test_backup(backup_dir)

            config = RestoreConfig(verify_before_restore=False)
            job = RestoreJob(config)

            result = job.restore_full(archive_path)
            # Should have warnings about database restore
            assert "database" not in result.components_restored or len(result.warnings) > 0

    def test_restore_media_dry_run(self) -> None:
        """Test media restore in dry-run mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()
            archive_path = self._create_test_backup(backup_dir)

            media_restore_dir = Path(tmpdir) / "restored_media"

            config = RestoreConfig(
                dry_run=True,
                verify_before_restore=False,
                media_path=media_restore_dir,
            )
            job = RestoreJob(config)

            result = job.restore_full(archive_path)
            assert result.success is True
            assert result.dry_run is True
            # In dry run, media directory should not exist
            assert not media_restore_dir.exists()

    def test_restore_media_actual(self) -> None:
        """Test actual media restore."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()
            archive_path = self._create_test_backup(backup_dir)

            media_restore_dir = Path(tmpdir) / "restored_media"

            config = RestoreConfig(
                dry_run=False,
                verify_before_restore=False,
                media_path=media_restore_dir,
            )

            # Mock database restore to avoid pg_restore requirement
            with patch("portal.ops.restore.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                job = RestoreJob(config)
                result = job.restore_full(archive_path)

            assert "media" in result.components_restored
            assert media_restore_dir.exists()
            assert (media_restore_dir / "upload.txt").exists()

    def test_restore_with_verification(self) -> None:
        """Test restore with backup verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()
            archive_path = self._create_test_backup(backup_dir)

            # Create backup job for verification
            backup_config = BackupConfig(local_path=backup_dir)
            backup_job = BackupJob(backup_config)

            config = RestoreConfig(
                dry_run=True,
                verify_before_restore=True,
            )
            job = RestoreJob(config, backup_job)

            result = job.restore_full(archive_path)
            assert result.success is True

    def test_restore_with_failed_verification(self) -> None:
        """Test restore with failed backup verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()
            archive_path = self._create_test_backup(backup_dir)

            # Corrupt the checksum file
            checksum_file = archive_path.with_suffix(".gz.sha256")
            checksum_file.write_text("badchecksum  test.tar.gz")

            backup_config = BackupConfig(local_path=backup_dir)
            backup_job = BackupJob(backup_config)

            config = RestoreConfig(
                dry_run=True,
                verify_before_restore=True,
            )
            job = RestoreJob(config, backup_job)

            result = job.restore_full(archive_path)
            assert result.success is False
            assert result.error is not None
            assert "verification" in result.error.lower()


class TestCreateRestoreJob:
    """Tests for create_restore_job factory function."""

    def test_create_with_defaults(self) -> None:
        """Test creating restore job with defaults."""
        job = create_restore_job()
        assert isinstance(job, RestoreJob)
        assert job._config.dry_run is False

    def test_create_with_dry_run(self) -> None:
        """Test creating restore job with dry run enabled."""
        job = create_restore_job(dry_run=True)
        assert job._config.dry_run is True

    @patch.dict("os.environ", {"DD_DATABASE_HOST": "db.example.com"})
    def test_create_with_env_vars(self) -> None:
        """Test creating restore job with environment variables."""
        job = create_restore_job()
        assert job._config.db_host == "db.example.com"
