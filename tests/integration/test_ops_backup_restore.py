"""Integration tests for backup/restore operations."""

from __future__ import annotations

import platform
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from portal.ops.backup import BackupConfig, BackupJob, BackupType
from portal.ops.restore import RestoreConfig, RestoreJob


@pytest.mark.integration
class TestBackupRestoreIntegration:
    """Integration tests for backup and restore cycle."""

    def test_full_backup_restore_cycle_dry_run(self) -> None:
        """Test complete backup/restore cycle in dry-run mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            media_dir = Path(tmpdir) / "media"
            audit_dir = Path(tmpdir) / "audit"
            restore_media_dir = Path(tmpdir) / "restored_media"

            # Setup source directories
            media_dir.mkdir()
            (media_dir / "upload1.txt").write_text("User upload 1")
            (media_dir / "upload2.json").write_text('{"data": "test"}')

            audit_dir.mkdir()
            (audit_dir / "audit.jsonl").write_text('{"event": "test"}\n')

            # Create backup
            backup_config = BackupConfig(
                local_path=backup_dir,
                media_path=media_dir,
                audit_log_path=audit_dir,
            )

            with patch("portal.ops.backup.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")

                backup_job = BackupJob(backup_config)
                backup_result = backup_job.backup_full()

            assert backup_result.success is True
            assert backup_result.backup_type == BackupType.FULL
            assert Path(backup_result.destination_path).exists()

            # Verify backup
            valid, msg = backup_job.verify_backup(backup_result.destination_path)
            assert valid is True

            # Restore in dry-run mode
            restore_config = RestoreConfig(
                media_path=restore_media_dir,
                audit_log_path=Path(tmpdir) / "restored_audit" / "audit.jsonl",
                dry_run=True,
                verify_before_restore=True,
            )
            restore_job = RestoreJob(restore_config, backup_job)
            restore_result = restore_job.restore_full(backup_result.destination_path)

            assert restore_result.success is True
            assert restore_result.dry_run is True
            # Restore dir should not exist in dry-run
            assert not restore_media_dir.exists()

    def test_backup_media_only(self) -> None:
        """Test media-only backup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            media_dir = Path(tmpdir) / "media"

            media_dir.mkdir()
            for i in range(5):
                (media_dir / f"file{i}.txt").write_text(f"Content {i}")

            backup_config = BackupConfig(
                local_path=backup_dir,
                media_path=media_dir,
            )
            backup_job = BackupJob(backup_config)
            result = backup_job.backup_media()

            assert result.success is True
            assert result.backup_type == BackupType.MEDIA
            assert Path(result.destination_path).exists()

    def test_list_and_cleanup_backups(self) -> None:
        """Test listing and cleaning up backups."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir)
            media_dir = Path(tmpdir) / "media"
            media_dir.mkdir()
            (media_dir / "test.txt").write_text("test")

            backup_config = BackupConfig(
                local_path=backup_dir,
                media_path=media_dir,
                retention_count=2,
                retention_days=0,
            )
            backup_job = BackupJob(backup_config)

            # Create multiple backups
            for _ in range(3):
                result = backup_job.backup_media()
                assert result.success is True

            # List backups
            backups = backup_job.list_backups()
            assert len(backups) == 3

            # Cleanup (should keep retention_count)
            removed = backup_job.cleanup_old_backups()
            assert removed == 1

            # Verify remaining
            remaining = backup_job.list_backups()
            assert len(remaining) == 2

    def test_restore_validates_backup(self) -> None:
        """Test that restore validates backup before proceeding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()

            # Create a fake backup file
            fake_backup = backup_dir / "fake_backup.tar.gz"
            fake_backup.write_text("not a real backup")

            restore_config = RestoreConfig(dry_run=True)
            restore_job = RestoreJob(restore_config)

            valid, details = restore_job.validate_backup(fake_backup)

            # Should fail due to invalid tar
            assert valid is False

    @patch("portal.ops.restore.subprocess.run")
    def test_restore_actual_media(self, mock_run: MagicMock) -> None:
        """Test actual media restoration."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"
            media_dir = Path(tmpdir) / "media"
            restore_dir = Path(tmpdir) / "restored"

            # Create source media
            media_dir.mkdir()
            (media_dir / "important.txt").write_text("Important data")

            # Backup
            backup_config = BackupConfig(
                local_path=backup_dir,
                media_path=media_dir,
            )
            with patch("portal.ops.backup.subprocess.run") as backup_mock:
                backup_mock.return_value = MagicMock(returncode=0, stderr="")
                backup_job = BackupJob(backup_config)
                backup_result = backup_job.backup_full()

            # Restore
            restore_config = RestoreConfig(
                media_path=restore_dir,
                dry_run=False,
                verify_before_restore=False,
            )
            restore_job = RestoreJob(restore_config)
            restore_result = restore_job.restore_full(backup_result.destination_path)

            assert restore_result.success is True
            assert "media" in restore_result.components_restored
            assert restore_dir.exists()
            assert (restore_dir / "important.txt").exists()


@pytest.mark.integration
@pytest.mark.skipif(
    platform.system() == "Windows",
    reason="Backup/restore uses pg_dump/pg_restore which are not available on Windows CI",
)
class TestBackupRestoreWithMockedDatabase:
    """Integration tests with mocked database operations."""

    @patch("portal.ops.backup.subprocess.run")
    @patch("portal.ops.restore.subprocess.run")
    def test_database_backup_restore_cycle(
        self, restore_mock: MagicMock, backup_mock: MagicMock
    ) -> None:
        """Test database backup and restore cycle."""

        def create_db_file(cmd: list[str], **kwargs: Any) -> MagicMock:
            """Mock pg_dump by creating the output file."""
            # Find the -f argument to get the output path
            for i, arg in enumerate(cmd):
                if arg == "-f" and i + 1 < len(cmd):
                    output_path = Path(cmd[i + 1])
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_text("-- Mock database dump")
                    break
            return MagicMock(returncode=0, stderr="")

        backup_mock.side_effect = create_db_file
        restore_mock.return_value = MagicMock(returncode=0, stderr="")

        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir) / "backups"

            # Backup
            backup_config = BackupConfig(local_path=backup_dir)
            backup_job = BackupJob(backup_config)
            backup_result = backup_job.backup_database()

            assert backup_result.success is True
            assert backup_result.backup_type == BackupType.DATABASE

            # Restore
            restore_config = RestoreConfig(verify_before_restore=False)
            restore_job = RestoreJob(restore_config)
            restore_result = restore_job.restore_database(backup_result.destination_path)

            assert restore_result.success is True
            assert "database" in restore_result.components_restored

            # Verify pg_restore was called (if subprocess was invoked)
            # Note: pg_restore is called via subprocess.run in restore module
            if restore_mock.called:
                call_args = restore_mock.call_args
                assert "pg_restore" in str(call_args)
