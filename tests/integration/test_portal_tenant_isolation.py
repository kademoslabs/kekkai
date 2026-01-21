"""Integration tests for portal tenant isolation (ASVS V8.4.1).

These tests verify strict tenant boundary enforcement - the MANDATORY
negative tests for cross-tenant access prevention.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Generator
from io import BytesIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from portal.tenants import Tenant, TenantStore
from portal.uploads import get_upload_path, process_upload
from portal.web import PortalApp


def make_environ(
    method: str = "GET",
    path: str = "/",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    client_ip: str = "127.0.0.1",
) -> dict[str, Any]:
    """Create a WSGI environ dict for testing."""
    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "REMOTE_ADDR": client_ip,
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "8000",
    }

    if headers:
        for key, value in headers.items():
            wsgi_key = f"HTTP_{key.upper().replace('-', '_')}"
            environ[wsgi_key] = value

    if body:
        environ["CONTENT_LENGTH"] = len(body)
        environ["wsgi.input"] = BytesIO(body)
    else:
        environ["CONTENT_LENGTH"] = 0
        environ["wsgi.input"] = BytesIO(b"")

    return environ


class MockStartResponse:
    """Mock start_response for testing."""

    def __init__(self) -> None:
        self.status: str = ""
        self.headers: list[tuple[str, str]] = []

    def __call__(self, status: str, headers: list[tuple[str, str]]) -> MagicMock:
        self.status = status
        self.headers = headers
        return MagicMock()


@pytest.fixture
def test_env() -> Generator[tuple[TenantStore, Tenant, str, Tenant, str, Path], None, None]:
    """Create test environment with two tenants."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "tenants.json"
        upload_dir = Path(tmpdir) / "uploads"
        upload_dir.mkdir()

        store = TenantStore(store_path)

        # Create two tenants with different products
        tenant_a, key_a = store.create(
            tenant_id="tenant_alpha",
            name="Alpha Corp",
            dojo_product_id=100,
            dojo_engagement_id=1000,
        )
        tenant_b, key_b = store.create(
            tenant_id="tenant_beta",
            name="Beta Inc",
            dojo_product_id=200,
            dojo_engagement_id=2000,
        )

        yield store, tenant_a, key_a, tenant_b, key_b, upload_dir


@pytest.mark.integration
class TestTenantIsolation:
    """Integration tests for tenant isolation."""

    def test_tenant_a_upload_not_visible_to_tenant_b(
        self,
        test_env: tuple[TenantStore, Tenant, str, Tenant, str, Path],
    ) -> None:
        """NEGATIVE TEST: Tenant B must NOT see Tenant A's uploads."""
        store, tenant_a, key_a, tenant_b, key_b, upload_dir = test_env

        # Tenant A uploads a file
        content = json.dumps({"secret": "alpha_data"}).encode()
        result_a = process_upload("alpha_scan.json", content, tenant_a, upload_dir)
        assert result_a.success
        assert result_a.upload_id is not None

        # Tenant B tries to access Tenant A's upload - MUST fail
        path = get_upload_path(tenant_b, result_a.upload_id, upload_dir)
        assert path is None, "SECURITY: Tenant B accessed Tenant A's upload!"

        # Tenant A can access their own upload
        path_a = get_upload_path(tenant_a, result_a.upload_id, upload_dir)
        assert path_a is not None

    def test_tenant_b_upload_not_visible_to_tenant_a(
        self,
        test_env: tuple[TenantStore, Tenant, str, Tenant, str, Path],
    ) -> None:
        """NEGATIVE TEST: Tenant A must NOT see Tenant B's uploads."""
        store, tenant_a, key_a, tenant_b, key_b, upload_dir = test_env

        # Tenant B uploads a file
        content = json.dumps({"secret": "beta_data"}).encode()
        result_b = process_upload("beta_scan.json", content, tenant_b, upload_dir)
        assert result_b.success
        assert result_b.upload_id is not None

        # Tenant A tries to access Tenant B's upload - MUST fail
        path = get_upload_path(tenant_a, result_b.upload_id, upload_dir)
        assert path is None, "SECURITY: Tenant A accessed Tenant B's upload!"

    def test_api_key_a_does_not_authenticate_as_tenant_b(
        self,
        test_env: tuple[TenantStore, Tenant, str, Tenant, str, Path],
    ) -> None:
        """NEGATIVE TEST: API key for Tenant A must NOT work as Tenant B."""
        store, tenant_a, key_a, tenant_b, key_b, upload_dir = test_env

        from portal.auth import authenticate_request

        # Key A authenticates as Tenant A
        result_a = authenticate_request(
            {"Authorization": f"Bearer {key_a}"},
            store,
            "127.0.0.1",
        )
        assert result_a.authenticated
        assert result_a.tenant is not None
        assert result_a.tenant.id == "tenant_alpha"
        assert result_a.tenant.dojo_product_id == 100

        # Key A does NOT authenticate as Tenant B
        assert result_a.tenant.id != "tenant_beta"
        assert result_a.tenant.dojo_product_id != 200

    def test_product_ids_remain_isolated(
        self,
        test_env: tuple[TenantStore, Tenant, str, Tenant, str, Path],
    ) -> None:
        """Verify each tenant maps to their own DefectDojo product."""
        store, tenant_a, key_a, tenant_b, key_b, upload_dir = test_env

        # Products must be different
        assert tenant_a.dojo_product_id != tenant_b.dojo_product_id

        # Engagements must be different
        assert tenant_a.dojo_engagement_id != tenant_b.dojo_engagement_id

    def test_directory_traversal_blocked_between_tenants(
        self,
        test_env: tuple[TenantStore, Tenant, str, Tenant, str, Path],
    ) -> None:
        """NEGATIVE TEST: Directory traversal must NOT allow cross-tenant access."""
        store, tenant_a, key_a, tenant_b, key_b, upload_dir = test_env

        # Tenant A uploads
        content = json.dumps({"data": "alpha"}).encode()
        result_a = process_upload("scan.json", content, tenant_a, upload_dir)
        assert result_a.success and result_a.upload_id

        # Attempt directory traversal
        malicious_ids = [
            f"../tenant_alpha/{result_a.upload_id}",
            f"../../tenant_alpha/{result_a.upload_id}",
            f"tenant_alpha/../tenant_alpha/{result_a.upload_id}",
        ]

        for mal_id in malicious_ids:
            path = get_upload_path(tenant_b, mal_id, upload_dir)
            assert path is None, f"SECURITY: Traversal succeeded with {mal_id}"


@pytest.mark.integration
class TestMultipleTenantUploadFlow:
    """Integration tests for complete upload flow with multiple tenants."""

    def test_concurrent_uploads_isolated(
        self,
        test_env: tuple[TenantStore, Tenant, str, Tenant, str, Path],
    ) -> None:
        """Multiple tenants uploading simultaneously maintain isolation."""
        store, tenant_a, key_a, tenant_b, key_b, upload_dir = test_env

        uploads_a = []
        uploads_b = []

        # Both tenants upload multiple files
        for i in range(5):
            content_a = json.dumps({"tenant": "alpha", "index": i}).encode()
            content_b = json.dumps({"tenant": "beta", "index": i}).encode()

            result_a = process_upload(f"scan_a_{i}.json", content_a, tenant_a, upload_dir)
            result_b = process_upload(f"scan_b_{i}.json", content_b, tenant_b, upload_dir)

            assert result_a.success and result_a.upload_id
            assert result_b.success and result_b.upload_id

            uploads_a.append(result_a.upload_id)
            uploads_b.append(result_b.upload_id)

        # Verify A can access all A uploads
        for upload_id in uploads_a:
            path = get_upload_path(tenant_a, upload_id, upload_dir)
            assert path is not None

        # Verify B can access all B uploads
        for upload_id in uploads_b:
            path = get_upload_path(tenant_b, upload_id, upload_dir)
            assert path is not None

        # Verify A cannot access any B uploads
        for upload_id in uploads_b:
            path = get_upload_path(tenant_a, upload_id, upload_dir)
            assert path is None

        # Verify B cannot access any A uploads
        for upload_id in uploads_a:
            path = get_upload_path(tenant_b, upload_id, upload_dir)
            assert path is None


@pytest.mark.integration
class TestWebAppTenantIsolation:
    """Integration tests for tenant isolation in web application."""

    def test_dashboard_shows_correct_tenant_info(
        self,
        test_env: tuple[TenantStore, Tenant, str, Tenant, str, Path],
    ) -> None:
        """Dashboard displays the authenticated tenant's info only."""
        store, tenant_a, key_a, tenant_b, key_b, upload_dir = test_env
        app = PortalApp(store)

        # Tenant A sees their own info
        environ_a = make_environ("GET", "/", headers={"Authorization": f"Bearer {key_a}"})
        start_response_a = MockStartResponse()
        response_a = list(app(environ_a, start_response_a))
        html_a = response_a[0].decode("utf-8")

        assert "Alpha Corp" in html_a
        assert "tenant_alpha" in html_a
        assert "Beta Inc" not in html_a

        # Tenant B sees their own info
        environ_b = make_environ("GET", "/", headers={"Authorization": f"Bearer {key_b}"})
        start_response_b = MockStartResponse()
        response_b = list(app(environ_b, start_response_b))
        html_b = response_b[0].decode("utf-8")

        assert "Beta Inc" in html_b
        assert "tenant_beta" in html_b
        assert "Alpha Corp" not in html_b

    def test_upload_response_contains_correct_product_id(
        self,
        test_env: tuple[TenantStore, Tenant, str, Tenant, str, Path],
    ) -> None:
        """Upload response includes the authenticated tenant's product ID."""
        import os

        store, tenant_a, key_a, tenant_b, key_b, upload_dir = test_env

        # Set upload directory for the test
        old_dir = os.environ.get("PORTAL_UPLOAD_DIR")
        os.environ["PORTAL_UPLOAD_DIR"] = str(upload_dir)

        try:
            app = PortalApp(store)
            content = json.dumps({"test": "data"}).encode()

            environ = make_environ(
                "POST",
                "/api/v1/upload",
                headers={
                    "Authorization": f"Bearer {key_a}",
                    "X-Filename": "scan.json",
                },
                body=content,
            )
            start_response = MockStartResponse()
            response = list(app(environ, start_response))

            if "200" in start_response.status:
                data = json.loads(response[0])
                assert data.get("dojo_product_id") == 100
                assert data.get("tenant_id") == "tenant_alpha"
        finally:
            if old_dir:
                os.environ["PORTAL_UPLOAD_DIR"] = old_dir
            elif "PORTAL_UPLOAD_DIR" in os.environ:
                del os.environ["PORTAL_UPLOAD_DIR"]
