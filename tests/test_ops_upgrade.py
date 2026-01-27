"""Unit tests for upgrade management operations."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from portal.ops.upgrade import (
    ComponentType,
    ComponentVersion,
    HealthCheck,
    UpgradeManager,
    UpgradeResult,
    UpgradeStatus,
    VersionManifest,
    create_upgrade_manager,
)


class TestComponentVersion:
    """Tests for ComponentVersion."""

    def test_version_creation(self) -> None:
        """Test version creation."""
        version = ComponentVersion(
            component=ComponentType.PORTAL,
            current_version="1.0.0",
            target_version="1.1.0",
        )
        assert version.component == ComponentType.PORTAL
        assert version.current_version == "1.0.0"
        assert version.target_version == "1.1.0"

    def test_version_to_dict(self) -> None:
        """Test version serialization."""
        version = ComponentVersion(
            component=ComponentType.DEFECTDOJO,
            current_version="2.37.0",
            image_digest="sha256:abc123",
            pinned=True,
        )
        data = version.to_dict()

        assert data["component"] == "defectdojo"
        assert data["current_version"] == "2.37.0"
        assert data["pinned"] is True


class TestVersionManifest:
    """Tests for VersionManifest."""

    def test_manifest_creation(self) -> None:
        """Test manifest creation."""
        manifest = VersionManifest()
        assert manifest.manifest_version == 1
        assert len(manifest.components) == 0

    def test_manifest_with_components(self) -> None:
        """Test manifest with components."""
        manifest = VersionManifest(
            components=[
                ComponentVersion(
                    component=ComponentType.PORTAL,
                    current_version="1.0.0",
                ),
                ComponentVersion(
                    component=ComponentType.DEFECTDOJO,
                    current_version="2.37.0",
                ),
            ]
        )
        assert len(manifest.components) == 2

    def test_manifest_to_dict(self) -> None:
        """Test manifest serialization."""
        manifest = VersionManifest(
            environment="production",
            notes="Test manifest",
        )
        data = manifest.to_dict()

        assert data["environment"] == "production"
        assert data["notes"] == "Test manifest"
        assert "manifest_version" in data

    def test_manifest_to_json(self) -> None:
        """Test manifest JSON serialization."""
        manifest = VersionManifest()
        json_str = manifest.to_json()

        parsed = json.loads(json_str)
        assert "manifest_version" in parsed

    def test_manifest_from_dict(self) -> None:
        """Test manifest deserialization."""
        data = {
            "manifest_version": 1,
            "created_at": "2024-01-01T12:00:00+00:00",
            "updated_at": "2024-01-01T12:00:00+00:00",
            "components": [
                {
                    "component": "portal",
                    "current_version": "1.0.0",
                    "pinned": True,
                }
            ],
            "environment": "staging",
        }
        manifest = VersionManifest.from_dict(data)

        assert manifest.environment == "staging"
        assert len(manifest.components) == 1
        assert manifest.components[0].current_version == "1.0.0"

    def test_get_component(self) -> None:
        """Test getting component from manifest."""
        manifest = VersionManifest(
            components=[
                ComponentVersion(
                    component=ComponentType.PORTAL,
                    current_version="1.0.0",
                ),
            ]
        )

        portal = manifest.get_component(ComponentType.PORTAL)
        assert portal is not None
        assert portal.current_version == "1.0.0"

        dojo = manifest.get_component(ComponentType.DEFECTDOJO)
        assert dojo is None

    def test_set_component_new(self) -> None:
        """Test setting new component in manifest."""
        manifest = VersionManifest()
        manifest.set_component(
            ComponentVersion(
                component=ComponentType.PORTAL,
                current_version="1.0.0",
            )
        )

        assert len(manifest.components) == 1
        assert manifest.components[0].current_version == "1.0.0"

    def test_set_component_update(self) -> None:
        """Test updating existing component in manifest."""
        manifest = VersionManifest(
            components=[
                ComponentVersion(
                    component=ComponentType.PORTAL,
                    current_version="1.0.0",
                ),
            ]
        )
        manifest.set_component(
            ComponentVersion(
                component=ComponentType.PORTAL,
                current_version="2.0.0",
            )
        )

        assert len(manifest.components) == 1
        assert manifest.components[0].current_version == "2.0.0"


class TestHealthCheck:
    """Tests for HealthCheck."""

    def test_health_check_creation(self) -> None:
        """Test health check creation."""
        check = HealthCheck(
            name="disk_space",
            passed=True,
            message="Disk usage at 50%",
        )
        assert check.name == "disk_space"
        assert check.passed is True

    def test_health_check_to_dict(self) -> None:
        """Test health check serialization."""
        check = HealthCheck(
            name="database",
            passed=False,
            message="Connection refused",
            details={"host": "localhost", "port": 5432},
        )
        data = check.to_dict()

        assert data["name"] == "database"
        assert data["passed"] is False
        assert data["details"]["host"] == "localhost"


class TestUpgradeResult:
    """Tests for UpgradeResult."""

    def test_result_creation(self) -> None:
        """Test result creation."""
        result = UpgradeResult(
            success=True,
            status=UpgradeStatus.COMPLETED,
            component=ComponentType.PORTAL,
            from_version="1.0.0",
            to_version="2.0.0",
        )
        assert result.success is True
        assert result.status == UpgradeStatus.COMPLETED

    def test_result_to_dict(self) -> None:
        """Test result serialization."""
        result = UpgradeResult(
            success=True,
            status=UpgradeStatus.COMPLETED,
            component=ComponentType.PORTAL,
            from_version="1.0.0",
            to_version="2.0.0",
            duration_seconds=120.5,
        )
        data = result.to_dict()

        assert data["success"] is True
        assert data["status"] == "completed"
        assert data["component"] == "portal"


class TestUpgradeManager:
    """Tests for UpgradeManager."""

    def test_manager_creation(self) -> None:
        """Test manager creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            manager = UpgradeManager(manifest_path=manifest_path)
            assert manager is not None

    def test_load_existing_manifest(self) -> None:
        """Test loading existing manifest."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"

            # Create existing manifest
            manifest = VersionManifest(
                components=[
                    ComponentVersion(
                        component=ComponentType.PORTAL,
                        current_version="1.5.0",
                    ),
                ],
                environment="staging",
            )
            manifest_path.write_text(manifest.to_json())

            # Load it
            manager = UpgradeManager(manifest_path=manifest_path)
            loaded = manager.get_manifest()

            assert loaded.environment == "staging"
            assert len(loaded.components) == 1
            assert loaded.components[0].current_version == "1.5.0"

    def test_save_manifest(self) -> None:
        """Test saving manifest."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            manager = UpgradeManager(manifest_path=manifest_path)

            manifest = manager.get_manifest()
            manifest.set_component(
                ComponentVersion(
                    component=ComponentType.NGINX,
                    current_version="1.26-alpine",
                )
            )
            manager.save_manifest()

            assert manifest_path.exists()
            saved = json.loads(manifest_path.read_text())
            assert any(c["component"] == "nginx" for c in saved["components"])

    @patch("portal.ops.upgrade.subprocess.run")
    def test_check_disk_space_pass(self, mock_run: MagicMock) -> None:
        """Test disk space check passing."""
        df_output = (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1       100G  50G   50G  50% /var/lib\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=df_output)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = UpgradeManager(manifest_path=Path(tmpdir) / "manifest.json")
            check = manager._check_disk_space()

            assert check.passed is True
            assert "50%" in check.message

    @patch("portal.ops.upgrade.subprocess.run")
    def test_check_disk_space_fail(self, mock_run: MagicMock) -> None:
        """Test disk space check failing."""
        df_output = (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1       100G  95G    5G  95% /var/lib\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=df_output)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = UpgradeManager(manifest_path=Path(tmpdir) / "manifest.json")
            check = manager._check_disk_space()

            assert check.passed is False
            assert "95%" in check.message

    @patch("portal.ops.upgrade.subprocess.run")
    def test_check_database_connection_pass(self, mock_run: MagicMock) -> None:
        """Test database connection check passing."""
        mock_run.return_value = MagicMock(returncode=0)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = UpgradeManager(manifest_path=Path(tmpdir) / "manifest.json")
            check = manager._check_database_connection()

            assert check.passed is True

    @patch("portal.ops.upgrade.subprocess.run")
    def test_run_pre_upgrade_checks(self, mock_run: MagicMock) -> None:
        """Test running all pre-upgrade checks."""
        df_output = (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1       100G  50G   50G  50% /var/lib\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=df_output)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create backup directory with a recent backup
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()
            (backup_dir / "recent.tar.gz").write_text("backup")

            with patch.dict("os.environ", {"BACKUP_LOCAL_PATH": str(backup_dir)}):
                manager = UpgradeManager(manifest_path=Path(tmpdir) / "manifest.json")
                checks = manager.run_pre_upgrade_checks()

            assert len(checks) >= 3

    def test_upgrade_dry_run(self) -> None:
        """Test upgrade in dry-run mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create backup directory
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()
            (backup_dir / "recent.tar.gz").write_text("backup")

            df_output = "Filesystem  Size Use% Mounted\n/dev/sda1  100G 50% /var/lib\n"
            with (
                patch.dict("os.environ", {"BACKUP_LOCAL_PATH": str(backup_dir)}),
                patch("portal.ops.upgrade.subprocess.run") as mock_run,
            ):
                mock_run.return_value = MagicMock(returncode=0, stdout=df_output)
                manager = UpgradeManager(manifest_path=Path(tmpdir) / "manifest.json")
                result = manager.upgrade_component(
                    ComponentType.PORTAL,
                    target_version="2.0.0",
                    dry_run=True,
                )

            assert result.success is True
            assert result.to_version == "2.0.0"

    def test_upgrade_failed_checks(self) -> None:
        """Test upgrade when pre-checks fail."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("portal.ops.upgrade.subprocess.run") as mock_run:
                # Simulate disk full
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="Filesystem  Size Use% Mounted\n/dev/sda1  100G 99% /var/lib\n",
                )
                manager = UpgradeManager(manifest_path=Path(tmpdir) / "manifest.json")
                result = manager.upgrade_component(
                    ComponentType.PORTAL,
                    target_version="2.0.0",
                )

            assert result.success is False
            assert result.error is not None
            assert "pre-upgrade" in result.error.lower()

    def test_rollback(self) -> None:
        """Test rollback operation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = UpgradeManager(manifest_path=Path(tmpdir) / "manifest.json")
            result = manager.rollback("backup_123")

            assert result.status == UpgradeStatus.ROLLED_BACK


class TestCreateUpgradeManager:
    """Tests for create_upgrade_manager factory."""

    def test_create_with_defaults(self) -> None:
        """Test creating manager with defaults."""
        manager = create_upgrade_manager()
        assert isinstance(manager, UpgradeManager)

    def test_create_with_manifest_path(self) -> None:
        """Test creating manager with manifest path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "custom_manifest.json"
            manager = create_upgrade_manager(manifest_path=manifest_path)
            assert manager._manifest_path == manifest_path

    @patch.dict("os.environ", {"VERSION_MANIFEST_PATH": "/custom/manifest.json"})
    def test_create_with_env_vars(self) -> None:
        """Test creating manager with environment variables."""
        manager = create_upgrade_manager()
        assert manager._manifest_path == Path("/custom/manifest.json")
