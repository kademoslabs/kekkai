"""Unit tests for backup operations."""

from __future__ import annotations

import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from portal.ops.backup import (
    BackupConfig,
    BackupDestination,
    BackupJob,
    BackupResult,
    BackupType,
    create_backup_job,
)


class TestBackupConfig:
    """Tests for BackupConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = BackupConfig()
        assert config.destination == BackupDestination.LOCAL
        assert config.db_host == "localhost"
        assert config.db_port == 5432
        assert config.db_name == "defectdojo"
        assert config.encryption_enabled is True
        assert config.retention_days == 30
        assert config.compress is True

    def test_config_path_conversion(self) -> None:
        """Test string to Path conversion."""
        config = BackupConfig(local_path="/tmp/backups")  # type: ignore
        assert isinstance(config.local_path, Path)
        assert config.local_path == Path("/tmp/backups")


class TestBackupResult:
    """Tests for BackupResult."""

    def test_result_to_dict(self) -> None:
        """Test result serialization."""
        result = BackupResult(
            success=True,
            backup_id="test_123",
            backup_type=BackupType.FULL,
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            size_bytes=1024,
            checksum="abc123",
            destination_path="/backups/test.tar.gz",
        )
        data = result.to_dict()

        assert data["success"] is True
        assert data["backup_id"] == "test_123"
        assert data["backup_type"] == "full"
        assert data["size_bytes"] == 1024
        assert "format_version" in data


class TestBackupJob:
    """Tests for BackupJob."""

    def test_generate_backup_id(self) -> None:
        """Test backup ID generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = BackupConfig(local_path=Path(tmpdir))
            job = BackupJob(config)

            backup_id = job._generate_backup_id("full")
            assert backup_id.startswith("full_")
            assert len(backup_id) > 20

    def test_compute_checksum(self) -> None:
        """Test checksum computation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = BackupConfig(local_path=Path(tmpdir))
            job = BackupJob(config)

            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("test content")

            checksum = job._compute_checksum(test_file)
            assert len(checksum) == 64  # SHA-256 hex
            assert checksum == job._compute_checksum(test_file)  # Deterministic

    def test_list_backups_empty(self) -> None:
        """Test listing backups from empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = BackupConfig(local_path=Path(tmpdir))
            job = BackupJob(config)

            backups = job.list_backups()
            assert backups == []

    def test_list_backups_with_files(self) -> None:
        """Test listing backups with existing files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir)
            config = BackupConfig(local_path=backup_dir)
            job = BackupJob(config)

            # Create mock backup files
            (backup_dir / "test1.tar.gz").write_text("backup1")
            (backup_dir / "test1.tar.gz.sha256").write_text("abc123  test1.tar.gz")
            (backup_dir / "test2.tar.gz").write_text("backup2")

            backups = job.list_backups()
            assert len(backups) == 2
            assert all("path" in b and "size_bytes" in b for b in backups)

    def test_verify_backup_missing_file(self) -> None:
        """Test backup verification with missing file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = BackupConfig(local_path=Path(tmpdir))
            job = BackupJob(config)

            valid, msg = job.verify_backup("/nonexistent/backup.tar.gz")
            assert valid is False
            assert "not found" in msg.lower()

    def test_verify_backup_missing_checksum(self) -> None:
        """Test backup verification with missing checksum."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir)
            config = BackupConfig(local_path=backup_dir)
            job = BackupJob(config)

            backup_file = backup_dir / "test.tar.gz"
            backup_file.write_text("backup content")

            valid, msg = job.verify_backup(backup_file)
            assert valid is False
            assert "checksum" in msg.lower()

    def test_verify_backup_valid(self) -> None:
        """Test backup verification with valid checksum."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir)
            config = BackupConfig(local_path=backup_dir)
            job = BackupJob(config)

            backup_file = backup_dir / "test.tar.gz"
            backup_file.write_text("backup content")

            checksum = job._compute_checksum(backup_file)
            (backup_file.with_suffix(".gz.sha256")).write_text(f"{checksum}  test.tar.gz")

            valid, msg = job.verify_backup(backup_file)
            assert valid is True
            assert "verified" in msg.lower()

    def test_verify_backup_checksum_mismatch(self) -> None:
        """Test backup verification with checksum mismatch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir)
            config = BackupConfig(local_path=backup_dir)
            job = BackupJob(config)

            backup_file = backup_dir / "test.tar.gz"
            backup_file.write_text("backup content")
            (backup_file.with_suffix(".gz.sha256")).write_text("wrongchecksum  test.tar.gz")

            valid, msg = job.verify_backup(backup_file)
            assert valid is False
            assert "mismatch" in msg.lower()

    @patch("portal.ops.backup.subprocess.run")
    def test_backup_database_pg_dump_not_found(self, mock_run: MagicMock) -> None:
        """Test database backup when pg_dump is not found."""
        mock_run.side_effect = FileNotFoundError()

        with tempfile.TemporaryDirectory() as tmpdir:
            config = BackupConfig(local_path=Path(tmpdir))
            job = BackupJob(config)

            result = job._backup_database(Path(tmpdir) / "db.sql")
            assert result["success"] is False
            assert "not found" in result["error"].lower()

    @patch("portal.ops.backup.subprocess.run")
    def test_backup_database_success(self, mock_run: MagicMock) -> None:
        """Test successful database backup."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        with tempfile.TemporaryDirectory() as tmpdir:
            config = BackupConfig(local_path=Path(tmpdir))
            job = BackupJob(config)

            output_path = Path(tmpdir) / "db.sql"
            result = job._backup_database(output_path)
            assert result["success"] is True

    def test_backup_media_empty(self) -> None:
        """Test media backup with nonexistent source."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = BackupConfig(
                local_path=Path(tmpdir),
                media_path=Path(tmpdir) / "nonexistent",
            )
            job = BackupJob(config)

            result = job._backup_media(Path(tmpdir) / "media_backup")
            assert result["success"] is True
            assert result["files"] == 0

    def test_backup_media_with_files(self) -> None:
        """Test media backup with existing files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            media_dir = Path(tmpdir) / "media"
            media_dir.mkdir()
            (media_dir / "file1.txt").write_text("content1")
            (media_dir / "file2.txt").write_text("content2")

            config = BackupConfig(
                local_path=Path(tmpdir),
                media_path=media_dir,
            )
            job = BackupJob(config)

            backup_dir = Path(tmpdir) / "backup_media"
            result = job._backup_media(backup_dir)
            assert result["success"] is True
            assert result["files"] == 2

    def test_create_archive(self) -> None:
        """Test archive creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            source_dir.mkdir()
            (source_dir / "file.txt").write_text("content")

            config = BackupConfig(local_path=Path(tmpdir))
            job = BackupJob(config)

            archive_path = job._create_archive(source_dir, "test_backup")
            assert archive_path.exists()
            assert archive_path.suffix == ".gz"

            # Verify it's a valid tar.gz
            with tarfile.open(archive_path, "r:gz") as tar:
                names = tar.getnames()
                assert len(names) > 0


class TestCreateBackupJob:
    """Tests for create_backup_job factory function."""

    def test_create_with_defaults(self) -> None:
        """Test creating backup job with defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            job = create_backup_job(local_path=tmpdir)
            assert isinstance(job, BackupJob)

    def test_create_with_custom_path(self) -> None:
        """Test creating backup job with custom path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            job = create_backup_job(local_path=tmpdir)
            assert job._config.local_path == Path(tmpdir)

    def test_create_with_env_vars(self) -> None:
        """Test creating backup job with environment variables."""
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict("os.environ", {"BACKUP_LOCAL_PATH": tmpdir}),
        ):
            job = create_backup_job()
            assert job._config.local_path == Path(tmpdir)


class TestBackupJobIntegration:
    """Integration-style tests for backup job."""

    @patch("portal.ops.backup.subprocess.run")
    def test_backup_full_with_mocked_pg_dump(self, mock_run: MagicMock) -> None:
        """Test full backup with mocked pg_dump."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            media_dir = Path(tmpdir) / "media"
            media_dir.mkdir()
            (media_dir / "upload.txt").write_text("user upload")

            config = BackupConfig(
                local_path=backup_dir,
                media_path=media_dir,
            )
            job = BackupJob(config)

            result = job.backup_full()

            # pg_dump was mocked to succeed, but file won't exist
            # so we expect the backup to handle this gracefully
            assert result.backup_type == BackupType.FULL
            assert result.backup_id.startswith("full_")

    def test_cleanup_respects_retention(self) -> None:
        """Test that cleanup respects retention count."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir)
            config = BackupConfig(
                local_path=backup_dir,
                retention_count=5,
                retention_days=1,
            )
            job = BackupJob(config)

            # Create 3 backup files (under retention count)
            for i in range(3):
                (backup_dir / f"backup{i}.tar.gz").write_text(f"backup{i}")

            removed = job.cleanup_old_backups()
            assert removed == 0  # Under retention count, nothing removed
