"""Regression tests for portal API contract.

Ensures API responses maintain backward compatibility and secure defaults.
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

from portal.tenants import TenantStore
from portal.web import SECURE_HEADERS, PortalApp


def make_environ(
    method: str = "GET",
    path: str = "/",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> dict[str, Any]:
    """Create a WSGI environ dict for testing."""
    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "REMOTE_ADDR": "127.0.0.1",
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
def app() -> Generator[PortalApp, None, None]:
    """Create a portal app for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "tenants.json"
        store = TenantStore(store_path)
        yield PortalApp(store)


@pytest.mark.regression
class TestHealthApiContract:
    """Regression tests for health endpoint contract."""

    def test_health_response_schema(self, app: PortalApp) -> None:
        """Health endpoint returns expected JSON schema."""
        environ = make_environ("GET", "/api/v1/health")
        start_response = MockStartResponse()

        response = list(app(environ, start_response))
        data = json.loads(response[0])

        # Schema must include 'status' field
        assert "status" in data
        assert data["status"] == "healthy"

    def test_health_content_type(self, app: PortalApp) -> None:
        """Health endpoint returns JSON content type."""
        environ = make_environ("GET", "/api/v1/health")
        start_response = MockStartResponse()

        list(app(environ, start_response))

        header_dict = dict(start_response.headers)
        assert "application/json" in header_dict.get("Content-Type", "")


@pytest.mark.regression
class TestErrorResponseContract:
    """Regression tests for error response format."""

    def test_401_response_schema(self, app: PortalApp) -> None:
        """Unauthorized response has expected format."""
        environ = make_environ(
            "POST",
            "/api/v1/upload",
            body=b"{}",
        )
        start_response = MockStartResponse()

        response = list(app(environ, start_response))
        data = json.loads(response[0])

        assert "401" in start_response.status
        assert data.get("success") is False
        assert "error" in data

    def test_404_response_schema(self, app: PortalApp) -> None:
        """Not found response has expected format."""
        environ = make_environ("GET", "/nonexistent")
        start_response = MockStartResponse()

        response = list(app(environ, start_response))
        data = json.loads(response[0])

        assert "404" in start_response.status
        assert data.get("success") is False
        assert "error" in data


@pytest.mark.regression
class TestSecureDefaultsContract:
    """Regression tests ensuring secure defaults are maintained."""

    def test_all_responses_have_security_headers(self, app: PortalApp) -> None:
        """All responses include security headers."""
        endpoints = [
            ("GET", "/"),
            ("GET", "/api/v1/health"),
            ("GET", "/static/kekkai.css"),
        ]

        required_headers = {
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
        }

        for method, path in endpoints:
            environ = make_environ(method, path)
            start_response = MockStartResponse()
            list(app(environ, start_response))

            header_names = {h[0] for h in start_response.headers}
            missing = required_headers - header_names
            assert not missing, f"Missing headers for {path}: {missing}"

    def test_x_frame_options_deny(self, app: PortalApp) -> None:
        """X-Frame-Options must be DENY to prevent clickjacking."""
        environ = make_environ("GET", "/")
        start_response = MockStartResponse()
        list(app(environ, start_response))

        header_dict = dict(start_response.headers)
        assert header_dict.get("X-Frame-Options") == "DENY"

    def test_content_type_nosniff(self, app: PortalApp) -> None:
        """X-Content-Type-Options must be nosniff."""
        environ = make_environ("GET", "/")
        start_response = MockStartResponse()
        list(app(environ, start_response))

        header_dict = dict(start_response.headers)
        assert header_dict.get("X-Content-Type-Options") == "nosniff"

    def test_csp_default_src_self(self, app: PortalApp) -> None:
        """CSP must restrict default-src to 'self'."""
        environ = make_environ("GET", "/")
        start_response = MockStartResponse()
        list(app(environ, start_response))

        header_dict = dict(start_response.headers)
        csp = header_dict.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp


@pytest.mark.regression
class TestUploadApiContract:
    """Regression tests for upload endpoint contract."""

    def test_upload_success_response_schema(self) -> None:
        """Successful upload response has expected fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            import os

            store_path = Path(tmpdir) / "tenants.json"
            upload_dir = Path(tmpdir) / "uploads"
            upload_dir.mkdir()

            os.environ["PORTAL_UPLOAD_DIR"] = str(upload_dir)

            try:
                store = TenantStore(store_path)
                _, api_key = store.create("test", "Test", 1, 10)
                app = PortalApp(store)

                content = json.dumps({"findings": []}).encode()
                environ = make_environ(
                    "POST",
                    "/api/v1/upload",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "X-Filename": "scan.json",
                    },
                    body=content,
                )
                start_response = MockStartResponse()
                response = list(app(environ, start_response))

                if "200" in start_response.status:
                    data = json.loads(response[0])

                    # Required fields in success response
                    assert data.get("success") is True
                    assert "upload_id" in data
                    assert "file_hash" in data
                    assert "tenant_id" in data
                    assert "dojo_product_id" in data
                    assert "dojo_engagement_id" in data
            finally:
                if "PORTAL_UPLOAD_DIR" in os.environ:
                    del os.environ["PORTAL_UPLOAD_DIR"]


@pytest.mark.regression
class TestSecureHeadersConstant:
    """Regression tests for SECURE_HEADERS constant."""

    def test_secure_headers_not_empty(self) -> None:
        """SECURE_HEADERS must contain headers."""
        assert len(SECURE_HEADERS) > 0

    def test_required_headers_present(self) -> None:
        """All required security headers are defined."""
        header_names = {h[0] for h in SECURE_HEADERS}
        required = {
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Content-Security-Policy",
        }
        assert required.issubset(header_names)

    def test_header_values_not_empty(self) -> None:
        """All header values are non-empty."""
        for name, value in SECURE_HEADERS:
            assert value, f"Header {name} has empty value"


@pytest.mark.regression
class TestTenantDataContract:
    """Regression tests for tenant data structure."""

    def test_tenant_to_dict_schema(self) -> None:
        """Tenant.to_dict() returns expected schema."""
        from portal.tenants import Tenant

        tenant = Tenant(
            id="test",
            name="Test",
            api_key_hash="hash",
            dojo_product_id=1,
            dojo_engagement_id=10,
            enabled=True,
            max_upload_size_mb=10,
        )
        data = tenant.to_dict()

        required_keys = {
            "id",
            "name",
            "api_key_hash",
            "dojo_product_id",
            "dojo_engagement_id",
            "enabled",
            "max_upload_size_mb",
            "auth_method",
            "saml_config",
            "license_token",
            "default_role",
        }
        assert set(data.keys()) == required_keys

    def test_tenant_store_file_format(self) -> None:
        """Tenant store file has expected JSON structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            store.create("test", "Test", 1, 10)

            # Verify file structure
            data = json.loads(store_path.read_text())
            assert "tenants" in data
            assert isinstance(data["tenants"], dict)
            assert "test" in data["tenants"]


@pytest.mark.regression
class TestTenantInfoApiContract:
    """Regression tests for /api/v1/tenant/info endpoint."""

    def test_tenant_info_response_schema(self) -> None:
        """Tenant info endpoint returns expected schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            _, api_key = store.create("test", "Test Org", 1, 10)
            app = PortalApp(store)

            environ = make_environ(
                "GET",
                "/api/v1/tenant/info",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            start_response = MockStartResponse()
            response = list(app(environ, start_response))

            assert "200" in start_response.status
            data = json.loads(response[0])

            # Required fields
            required_keys = {
                "id",
                "name",
                "dojo_product_id",
                "dojo_engagement_id",
                "enabled",
                "max_upload_size_mb",
                "auth_method",
                "default_role",
            }
            assert required_keys.issubset(set(data.keys()))

    def test_tenant_info_requires_auth(self, app: PortalApp) -> None:
        """Tenant info endpoint requires authentication."""
        environ = make_environ("GET", "/api/v1/tenant/info")
        start_response = MockStartResponse()
        response = list(app(environ, start_response))

        assert "401" in start_response.status
        data = json.loads(response[0])
        assert data.get("success") is False


@pytest.mark.regression
class TestUploadsApiContract:
    """Regression tests for /api/v1/uploads endpoint."""

    def test_uploads_response_schema(self) -> None:
        """Uploads list endpoint returns expected schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            _, api_key = store.create("test", "Test Org", 1, 10)
            app = PortalApp(store)

            environ = make_environ(
                "GET",
                "/api/v1/uploads",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            start_response = MockStartResponse()
            response = list(app(environ, start_response))

            assert "200" in start_response.status
            data = json.loads(response[0])

            assert "uploads" in data
            assert isinstance(data["uploads"], list)

    def test_uploads_requires_auth(self, app: PortalApp) -> None:
        """Uploads list endpoint requires authentication."""
        environ = make_environ("GET", "/api/v1/uploads")
        start_response = MockStartResponse()
        list(app(environ, start_response))

        assert "401" in start_response.status


@pytest.mark.regression
class TestStatsApiContract:
    """Regression tests for /api/v1/stats endpoint."""

    def test_stats_response_schema(self) -> None:
        """Stats endpoint returns expected schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            store = TenantStore(store_path)
            _, api_key = store.create("test", "Test Org", 1, 10)
            app = PortalApp(store)

            environ = make_environ(
                "GET",
                "/api/v1/stats",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            start_response = MockStartResponse()
            response = list(app(environ, start_response))

            assert "200" in start_response.status
            data = json.loads(response[0])

            # Required fields
            required_keys = {"total_uploads", "total_size_bytes", "last_upload_time"}
            assert set(data.keys()) == required_keys

    def test_stats_requires_auth(self, app: PortalApp) -> None:
        """Stats endpoint requires authentication."""
        environ = make_environ("GET", "/api/v1/stats")
        start_response = MockStartResponse()
        list(app(environ, start_response))

        assert "401" in start_response.status
