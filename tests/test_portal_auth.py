"""Unit tests for portal authentication."""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from portal.auth import AuthResult, _get_header, authenticate_request
from portal.tenants import Tenant, TenantStore


class TestAuthenticateRequest:
    """Tests for request authentication."""

    @pytest.fixture
    def tenant_store(self) -> Generator[TenantStore, None, None]:
        """Create a tenant store with test data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            yield store

    @pytest.fixture
    def tenant_with_key(self, tenant_store: TenantStore) -> tuple[Tenant, str]:
        """Create a test tenant and return (tenant, api_key)."""
        return tenant_store.create(
            tenant_id="test_tenant",
            name="Test Tenant",
            dojo_product_id=1,
            dojo_engagement_id=10,
        )

    def test_authenticate_valid_token(
        self, tenant_store: TenantStore, tenant_with_key: tuple[Tenant, str]
    ) -> None:
        tenant, api_key = tenant_with_key
        headers = {"Authorization": f"Bearer {api_key}"}

        result = authenticate_request(headers, tenant_store, "127.0.0.1")

        assert result.authenticated is True
        assert result.tenant is not None
        assert result.tenant.id == tenant.id
        assert result.error is None

    def test_authenticate_missing_header(self, tenant_store: TenantStore) -> None:
        headers: dict[str, str] = {}

        result = authenticate_request(headers, tenant_store, "127.0.0.1")

        assert result.authenticated is False
        assert result.tenant is None
        assert result.error == "Missing Authorization header"

    def test_authenticate_invalid_format(self, tenant_store: TenantStore) -> None:
        headers = {"Authorization": "Basic dXNlcjpwYXNz"}

        result = authenticate_request(headers, tenant_store, "127.0.0.1")

        assert result.authenticated is False
        assert result.error == "Invalid Authorization format"

    def test_authenticate_empty_token(self, tenant_store: TenantStore) -> None:
        headers = {"Authorization": "Bearer "}

        result = authenticate_request(headers, tenant_store, "127.0.0.1")

        assert result.authenticated is False
        assert result.error == "Invalid Authorization format"

    def test_authenticate_invalid_token(
        self, tenant_store: TenantStore, tenant_with_key: tuple[Tenant, str]
    ) -> None:
        headers = {"Authorization": "Bearer invalid_token_12345"}

        result = authenticate_request(headers, tenant_store, "127.0.0.1")

        assert result.authenticated is False
        assert result.error == "Invalid API key"

    def test_authenticate_disabled_tenant(
        self, tenant_store: TenantStore, tenant_with_key: tuple[Tenant, str]
    ) -> None:
        tenant, api_key = tenant_with_key
        # Disable the tenant
        disabled = Tenant(
            id=tenant.id,
            name=tenant.name,
            api_key_hash=tenant.api_key_hash,
            dojo_product_id=tenant.dojo_product_id,
            dojo_engagement_id=tenant.dojo_engagement_id,
            enabled=False,
            max_upload_size_mb=tenant.max_upload_size_mb,
        )
        tenant_store.update(disabled)

        headers = {"Authorization": f"Bearer {api_key}"}
        result = authenticate_request(headers, tenant_store, "127.0.0.1")

        assert result.authenticated is False
        assert result.error == "Tenant is disabled"

    def test_authenticate_case_insensitive_header(
        self, tenant_store: TenantStore, tenant_with_key: tuple[Tenant, str]
    ) -> None:
        _, api_key = tenant_with_key
        headers = {"authorization": f"Bearer {api_key}"}

        result = authenticate_request(headers, tenant_store, "127.0.0.1")

        assert result.authenticated is True

    def test_authenticate_bearer_case_insensitive(
        self, tenant_store: TenantStore, tenant_with_key: tuple[Tenant, str]
    ) -> None:
        _, api_key = tenant_with_key
        headers = {"Authorization": f"bearer {api_key}"}

        result = authenticate_request(headers, tenant_store, "127.0.0.1")

        assert result.authenticated is True


class TestGetHeader:
    """Tests for case-insensitive header lookup."""

    def test_get_header_exact_match(self) -> None:
        headers = {"Content-Type": "application/json"}
        assert _get_header(headers, "Content-Type") == "application/json"

    def test_get_header_case_insensitive(self) -> None:
        headers = {"content-type": "application/json"}
        assert _get_header(headers, "Content-Type") == "application/json"

    def test_get_header_not_found(self) -> None:
        headers = {"Content-Type": "application/json"}
        assert _get_header(headers, "Authorization") is None


class TestAuthResultDataclass:
    """Tests for AuthResult dataclass."""

    def test_auth_result_success(self) -> None:
        tenant = Tenant(
            id="t1",
            name="Test",
            api_key_hash="h",
            dojo_product_id=1,
            dojo_engagement_id=1,
        )
        result = AuthResult(authenticated=True, tenant=tenant)

        assert result.authenticated is True
        assert result.tenant == tenant
        assert result.error is None

    def test_auth_result_failure(self) -> None:
        result = AuthResult(authenticated=False, error="Test error")

        assert result.authenticated is False
        assert result.tenant is None
        assert result.error == "Test error"


class TestAuthLogging:
    """Tests for authentication failure logging (ASVS V16.3.2)."""

    def test_log_auth_failure_called(self, caplog: pytest.LogCaptureFixture) -> None:
        """Verify that failed auth attempts are logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            headers = {"Authorization": "Bearer invalid_token"}

            with caplog.at_level("WARNING"):
                authenticate_request(headers, store, "192.168.1.100")

            assert "auth.failure" in caplog.text
            assert "invalid_token" in caplog.text

    def test_log_missing_header(self, caplog: pytest.LogCaptureFixture) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            headers: dict[str, str] = {}

            with caplog.at_level("WARNING"):
                authenticate_request(headers, store, "10.0.0.1")

            assert "auth.failure" in caplog.text
            assert "missing_header" in caplog.text


class TestCrossTenantPrevention:
    """Tests for cross-tenant access prevention (ASVS V8.4.1)."""

    def test_tenant_a_cannot_use_tenant_b_key(self) -> None:
        """Verify that one tenant's API key cannot access another tenant's data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)

            tenant_a, key_a = store.create("tenant_a", "Tenant A", 100, 1000)
            tenant_b, key_b = store.create("tenant_b", "Tenant B", 200, 2000)

            # Key A authenticates as Tenant A
            result_a = authenticate_request(
                {"Authorization": f"Bearer {key_a}"}, store, "127.0.0.1"
            )
            assert result_a.tenant is not None
            assert result_a.tenant.id == "tenant_a"
            assert result_a.tenant.dojo_product_id == 100

            # Key B authenticates as Tenant B (different product)
            result_b = authenticate_request(
                {"Authorization": f"Bearer {key_b}"}, store, "127.0.0.1"
            )
            assert result_b.tenant is not None
            assert result_b.tenant.id == "tenant_b"
            assert result_b.tenant.dojo_product_id == 200

            # Key A does NOT give access to Tenant B's product
            assert result_a.tenant.dojo_product_id != result_b.tenant.dojo_product_id
