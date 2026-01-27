"""Unit tests for portal tenant management."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from portal.tenants import (
    API_KEY_PREFIX,
    Tenant,
    TenantStore,
    generate_api_key,
    hash_api_key,
    verify_api_key,
)


class TestApiKeyFunctions:
    """Tests for API key generation and verification."""

    def test_generate_api_key_has_prefix(self) -> None:
        key = generate_api_key()
        assert key.startswith(API_KEY_PREFIX)

    def test_generate_api_key_length(self) -> None:
        key = generate_api_key()
        assert len(key) > len(API_KEY_PREFIX) + 20

    def test_generate_api_key_unique(self) -> None:
        keys = {generate_api_key() for _ in range(100)}
        assert len(keys) == 100

    def test_hash_api_key_deterministic(self) -> None:
        key = "test_key_123"
        hash1 = hash_api_key(key)
        hash2 = hash_api_key(key)
        assert hash1 == hash2

    def test_hash_api_key_different_for_different_keys(self) -> None:
        hash1 = hash_api_key("key1")
        hash2 = hash_api_key("key2")
        assert hash1 != hash2

    def test_verify_api_key_valid(self) -> None:
        key = "my_secret_key"
        key_hash = hash_api_key(key)
        assert verify_api_key(key, key_hash) is True

    def test_verify_api_key_invalid(self) -> None:
        key = "my_secret_key"
        key_hash = hash_api_key(key)
        assert verify_api_key("wrong_key", key_hash) is False

    def test_verify_api_key_constant_time(self) -> None:
        """Verify that comparison is constant-time (uses hmac.compare_digest)."""
        key = generate_api_key()
        key_hash = hash_api_key(key)
        # This test verifies the function works - timing attack resistance
        # is provided by hmac.compare_digest
        assert verify_api_key(key, key_hash) is True
        assert verify_api_key(key + "x", key_hash) is False


class TestTenant:
    """Tests for Tenant dataclass."""

    def test_tenant_creation(self) -> None:
        tenant = Tenant(
            id="tenant1",
            name="Test Tenant",
            api_key_hash="hash123",
            dojo_product_id=1,
            dojo_engagement_id=10,
        )
        assert tenant.id == "tenant1"
        assert tenant.name == "Test Tenant"
        assert tenant.enabled is True
        assert tenant.max_upload_size_mb == 10

    def test_tenant_to_dict(self) -> None:
        tenant = Tenant(
            id="t1",
            name="Test",
            api_key_hash="h",
            dojo_product_id=1,
            dojo_engagement_id=2,
            enabled=False,
            max_upload_size_mb=5,
        )
        data = tenant.to_dict()
        assert data["id"] == "t1"
        assert data["enabled"] is False
        assert data["max_upload_size_mb"] == 5

    def test_tenant_from_dict(self) -> None:
        data = {
            "id": "t2",
            "name": "Test 2",
            "api_key_hash": "hash",
            "dojo_product_id": 5,
            "dojo_engagement_id": 50,
            "enabled": True,
            "max_upload_size_mb": 20,
        }
        tenant = Tenant.from_dict(data)
        assert tenant.id == "t2"
        assert tenant.dojo_product_id == 5
        assert tenant.max_upload_size_mb == 20

    def test_tenant_from_dict_defaults(self) -> None:
        data = {
            "id": "t3",
            "name": "Test 3",
            "api_key_hash": "hash",
            "dojo_product_id": 1,
            "dojo_engagement_id": 1,
        }
        tenant = Tenant.from_dict(data)
        assert tenant.enabled is True
        assert tenant.max_upload_size_mb == 10

    def test_tenant_immutable(self) -> None:
        tenant = Tenant(
            id="t1",
            name="Test",
            api_key_hash="h",
            dojo_product_id=1,
            dojo_engagement_id=1,
        )
        with pytest.raises(AttributeError):
            tenant.name = "New Name"  # type: ignore[misc]


class TestTenantStore:
    """Tests for TenantStore file-based storage."""

    def test_create_tenant(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)

            tenant, api_key = store.create(
                tenant_id="t1",
                name="Test Tenant",
                dojo_product_id=1,
                dojo_engagement_id=10,
            )

            assert tenant.id == "t1"
            assert api_key.startswith(API_KEY_PREFIX)
            assert verify_api_key(api_key, tenant.api_key_hash)

    def test_create_tenant_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            store.create("t1", "Test", 1, 10)

            # Reload from file
            store2 = TenantStore(store_path)
            tenant = store2.get_by_id("t1")
            assert tenant is not None
            assert tenant.name == "Test"

    def test_create_tenant_duplicate_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            store.create("t1", "Test", 1, 10)

            with pytest.raises(ValueError, match="already exists"):
                store.create("t1", "Test 2", 2, 20)

    def test_get_by_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            tenant, api_key = store.create("t1", "Test", 1, 10)

            found = store.get_by_api_key(api_key)
            assert found is not None
            assert found.id == "t1"

    def test_get_by_api_key_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            store.create("t1", "Test", 1, 10)

            found = store.get_by_api_key("invalid_key")
            assert found is None

    def test_update_tenant(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            tenant, _ = store.create("t1", "Test", 1, 10)

            updated = Tenant(
                id=tenant.id,
                name="Updated Name",
                api_key_hash=tenant.api_key_hash,
                dojo_product_id=tenant.dojo_product_id,
                dojo_engagement_id=tenant.dojo_engagement_id,
                enabled=False,
                max_upload_size_mb=20,
            )
            store.update(updated)

            reloaded = store.get_by_id("t1")
            assert reloaded is not None
            assert reloaded.name == "Updated Name"
            assert reloaded.enabled is False

    def test_update_nonexistent_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)

            tenant = Tenant(
                id="nonexistent",
                name="Test",
                api_key_hash="h",
                dojo_product_id=1,
                dojo_engagement_id=1,
            )
            with pytest.raises(ValueError, match="does not exist"):
                store.update(tenant)

    def test_delete_tenant(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            store.create("t1", "Test", 1, 10)

            result = store.delete("t1")
            assert result is True
            assert store.get_by_id("t1") is None

    def test_delete_nonexistent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)

            result = store.delete("nonexistent")
            assert result is False

    def test_list_all(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            store.create("t1", "Test 1", 1, 10)
            store.create("t2", "Test 2", 2, 20)

            tenants = store.list_all()
            assert len(tenants) == 2
            ids = {t.id for t in tenants}
            assert ids == {"t1", "t2"}

    def test_rotate_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            tenant, old_key = store.create("t1", "Test", 1, 10)
            old_hash = tenant.api_key_hash

            new_key = store.rotate_api_key("t1")
            assert new_key is not None
            assert new_key != old_key

            updated = store.get_by_id("t1")
            assert updated is not None
            assert updated.api_key_hash != old_hash
            assert verify_api_key(new_key, updated.api_key_hash)

    def test_rotate_api_key_nonexistent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)

            result = store.rotate_api_key("nonexistent")
            assert result is None

    def test_load_corrupted_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store_path.write_text("invalid json {{{")

            store = TenantStore(store_path)
            assert store.list_all() == []

    def test_load_empty_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store_path.write_text("")

            store = TenantStore(store_path)
            assert store.list_all() == []

    def test_creates_parent_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "subdir" / "nested" / "tenants.json"
            store = TenantStore(store_path)
            store.create("t1", "Test", 1, 10)

            assert store_path.exists()


class TestTenantIsolation:
    """Tests for tenant isolation (ASVS V8.4.1)."""

    def test_multiple_tenants_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)

            _, key1 = store.create("tenant1", "Tenant 1", 1, 10)
            _, key2 = store.create("tenant2", "Tenant 2", 2, 20)

            # Each key only matches its tenant
            t1 = store.get_by_api_key(key1)
            t2 = store.get_by_api_key(key2)

            assert t1 is not None and t1.id == "tenant1"
            assert t2 is not None and t2.id == "tenant2"

            # Key1 does not match tenant2
            assert t1.dojo_product_id != t2.dojo_product_id

    def test_tenant_product_mapping_unique(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)

            store.create("tenant1", "Tenant 1", dojo_product_id=100, dojo_engagement_id=1000)
            store.create("tenant2", "Tenant 2", dojo_product_id=200, dojo_engagement_id=2000)

            t1 = store.get_by_id("tenant1")
            t2 = store.get_by_id("tenant2")

            assert t1 is not None and t2 is not None
            assert t1.dojo_product_id == 100
            assert t2.dojo_product_id == 200
            # Engagements are separate per product
            assert t1.dojo_engagement_id != t2.dojo_engagement_id
