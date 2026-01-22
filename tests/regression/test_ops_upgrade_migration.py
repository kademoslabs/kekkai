"""Regression tests for upgrade and migration operations."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from portal.ops.upgrade import (
    ComponentType,
    ComponentVersion,
    UpgradeManager,
    UpgradeStatus,
    VersionManifest,
)


@pytest.mark.regression
class TestVersionManifestRegression:
    """Regression tests for version manifest format stability."""

    def test_manifest_format_v1_compatibility(self) -> None:
        """Test that v1 manifest format is correctly parsed."""
        v1_manifest = {
            "manifest_version": 1,
            "created_at": "2024-01-01T00:00:00+00:00",
            "updated_at": "2024-01-15T12:00:00+00:00",
            "components": [
                {
                    "component": "portal",
                    "current_version": "1.0.0",
                    "target_version": None,
                    "image_digest": None,
                    "pinned": True,
                },
                {
                    "component": "defectdojo",
                    "current_version": "2.37.0",
                    "target_version": "2.38.0",
                    "image_digest": "sha256:abc123def456",
                    "pinned": True,
                },
            ],
            "environment": "production",
            "notes": "Initial deployment",
        }

        manifest = VersionManifest.from_dict(v1_manifest)

        assert manifest.manifest_version == 1
        assert len(manifest.components) == 2
        assert manifest.environment == "production"

        portal = manifest.get_component(ComponentType.PORTAL)
        assert portal is not None
        assert portal.current_version == "1.0.0"

        dojo = manifest.get_component(ComponentType.DEFECTDOJO)
        assert dojo is not None
        assert dojo.target_version == "2.38.0"
        assert dojo.image_digest == "sha256:abc123def456"

    def test_manifest_roundtrip(self) -> None:
        """Test that manifest can be serialized and deserialized without data loss."""
        original = VersionManifest(
            manifest_version=1,
            created_at=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
            updated_at=datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC),
            components=[
                ComponentVersion(
                    component=ComponentType.PORTAL,
                    current_version="1.5.0",
                    pinned=True,
                ),
                ComponentVersion(
                    component=ComponentType.DEFECTDOJO,
                    current_version="2.37.0",
                    image_digest="sha256:test",
                    pinned=True,
                ),
                ComponentVersion(
                    component=ComponentType.POSTGRES,
                    current_version="16-alpine",
                    pinned=True,
                ),
            ],
            environment="staging",
            notes="Test manifest",
        )

        # Serialize and deserialize
        json_str = original.to_json()
        parsed = json.loads(json_str)
        restored = VersionManifest.from_dict(parsed)

        # Verify all fields preserved
        assert restored.manifest_version == original.manifest_version
        assert restored.environment == original.environment
        assert restored.notes == original.notes
        assert len(restored.components) == len(original.components)

        for orig_comp in original.components:
            restored_comp = restored.get_component(orig_comp.component)
            assert restored_comp is not None
            assert restored_comp.current_version == orig_comp.current_version
            assert restored_comp.image_digest == orig_comp.image_digest
            assert restored_comp.pinned == orig_comp.pinned

    def test_manifest_schema_stability(self) -> None:
        """Test that manifest JSON schema remains stable."""
        manifest = VersionManifest(
            components=[
                ComponentVersion(
                    component=ComponentType.PORTAL,
                    current_version="1.0.0",
                ),
            ],
        )

        data = manifest.to_dict()

        # Required top-level fields
        assert "manifest_version" in data
        assert "created_at" in data
        assert "updated_at" in data
        assert "components" in data
        assert "environment" in data
        assert "notes" in data

        # Component structure
        comp = data["components"][0]
        assert "component" in comp
        assert "current_version" in comp
        assert "target_version" in comp
        assert "image_digest" in comp
        assert "pinned" in comp


@pytest.mark.regression
class TestUpgradeResultRegression:
    """Regression tests for upgrade result format."""

    def test_upgrade_result_schema(self) -> None:
        """Test that upgrade result schema is stable."""
        from portal.ops.upgrade import HealthCheck, UpgradeResult

        result = UpgradeResult(
            success=True,
            status=UpgradeStatus.COMPLETED,
            component=ComponentType.PORTAL,
            from_version="1.0.0",
            to_version="2.0.0",
            duration_seconds=120.5,
            health_checks=[
                HealthCheck(name="disk_space", passed=True, message="OK"),
                HealthCheck(name="database", passed=True, message="OK"),
            ],
            backup_id="backup_123",
            rollback_available=True,
        )

        data = result.to_dict()

        # Required fields
        assert "success" in data
        assert "status" in data
        assert "component" in data
        assert "from_version" in data
        assert "to_version" in data
        assert "timestamp" in data
        assert "duration_seconds" in data
        assert "error" in data
        assert "health_checks" in data
        assert "backup_id" in data
        assert "rollback_available" in data

        # Health check structure
        assert len(data["health_checks"]) == 2
        for hc in data["health_checks"]:
            assert "name" in hc
            assert "passed" in hc
            assert "message" in hc


@pytest.mark.regression
class TestUpgradeManagerRegression:
    """Regression tests for upgrade manager behavior."""

    def test_default_manifest_components(self) -> None:
        """Test that default manifest has expected components."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = UpgradeManager(manifest_path=Path(tmpdir) / "manifest.json")
            manifest = manager.get_manifest()

            # Verify default components exist
            expected_components = {
                ComponentType.PORTAL,
                ComponentType.DEFECTDOJO,
                ComponentType.POSTGRES,
                ComponentType.NGINX,
                ComponentType.VALKEY,
            }

            actual_components = {c.component for c in manifest.components}
            assert expected_components == actual_components

    def test_manifest_persistence(self) -> None:
        """Test that manifest is correctly persisted to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"

            # Create and save
            manager1 = UpgradeManager(manifest_path=manifest_path)
            manifest1 = manager1.get_manifest()
            manifest1.set_component(
                ComponentVersion(
                    component=ComponentType.PORTAL,
                    current_version="2.0.0",
                )
            )
            manager1.save_manifest()

            # Reload
            manager2 = UpgradeManager(manifest_path=manifest_path)
            manifest2 = manager2.get_manifest()

            portal = manifest2.get_component(ComponentType.PORTAL)
            assert portal is not None
            assert portal.current_version == "2.0.0"

    def test_pre_upgrade_checks_consistent(self) -> None:
        """Test that pre-upgrade checks return consistent structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create backup dir with recent backup
            backup_dir = Path(tmpdir) / "backups"
            backup_dir.mkdir()
            (backup_dir / "recent.tar.gz").write_text("backup")

            with pytest.MonkeyPatch.context() as mp:
                mp.setenv("BACKUP_LOCAL_PATH", str(backup_dir))

                from unittest.mock import MagicMock, patch

                with patch("portal.ops.upgrade.subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(
                        returncode=0,
                        stdout="Filesystem  Size Use% Mounted\n/dev/sda1  100G 50% /var/lib\n",
                    )

                    manager = UpgradeManager(manifest_path=Path(tmpdir) / "manifest.json")
                    checks = manager.run_pre_upgrade_checks()

            # Verify consistent check structure
            assert len(checks) >= 3

            check_names = {c.name for c in checks}
            assert "disk_space" in check_names
            assert "database_connection" in check_names
            assert "services_running" in check_names
            assert "backup_recent" in check_names

            for check in checks:
                assert hasattr(check, "name")
                assert hasattr(check, "passed")
                assert hasattr(check, "message")
                assert isinstance(check.passed, bool)


@pytest.mark.regression
class TestComponentVersionRegression:
    """Regression tests for component version handling."""

    def test_all_component_types_serializable(self) -> None:
        """Test that all component types can be serialized."""
        for comp_type in ComponentType:
            version = ComponentVersion(
                component=comp_type,
                current_version="1.0.0",
            )
            data = version.to_dict()
            assert data["component"] == comp_type.value

    def test_component_version_fields_preserved(self) -> None:
        """Test that all version fields are preserved in serialization."""
        original = ComponentVersion(
            component=ComponentType.DEFECTDOJO,
            current_version="2.37.0",
            target_version="2.38.0",
            image_digest="sha256:abc123",
            pinned=True,
        )

        data = original.to_dict()

        assert data["component"] == "defectdojo"
        assert data["current_version"] == "2.37.0"
        assert data["target_version"] == "2.38.0"
        assert data["image_digest"] == "sha256:abc123"
        assert data["pinned"] is True
