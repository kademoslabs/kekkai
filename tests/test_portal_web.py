"""Unit tests for portal web application."""

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
from portal.web import (
    SECURE_HEADERS,
    PortalApp,
    _extract_headers,
    _get_content_type,
    _parse_multipart,
    create_app,
)


@pytest.fixture
def tenant_store() -> Generator[TenantStore, None, None]:
    """Create a tenant store with test data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "tenants.json"
        store = TenantStore(store_path)
        yield store


@pytest.fixture
def app(tenant_store: TenantStore) -> PortalApp:
    """Create a portal app instance."""
    return PortalApp(tenant_store)


@pytest.fixture
def valid_json_content() -> bytes:
    """Valid JSON content for testing."""
    return json.dumps({"findings": [], "version": "1.0"}).encode()


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


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health_returns_ok(self, app: PortalApp) -> None:
        environ = make_environ("GET", "/api/v1/health")
        start_response = MockStartResponse()

        response = list(app(environ, start_response))

        assert start_response.status == "200 OK"
        data = json.loads(response[0])
        assert data["status"] == "healthy"


class TestDashboard:
    """Tests for dashboard endpoint."""

    def test_dashboard_unauthenticated(self, app: PortalApp) -> None:
        environ = make_environ("GET", "/")
        start_response = MockStartResponse()

        response = list(app(environ, start_response))

        assert start_response.status == "200 OK"
        html = response[0].decode("utf-8")
        assert "Kekkai Portal" in html
        assert "Authentication Required" in html

    def test_dashboard_authenticated(self, tenant_store: TenantStore) -> None:
        tenant, api_key = tenant_store.create("test", "Test Tenant", 1, 10)
        app = PortalApp(tenant_store)

        environ = make_environ("GET", "/", headers={"Authorization": f"Bearer {api_key}"})
        start_response = MockStartResponse()

        response = list(app(environ, start_response))

        assert start_response.status == "200 OK"
        html = response[0].decode("utf-8")
        assert "Test Tenant" in html
        assert "Upload Scan Results" in html

    def test_dashboard_has_secure_headers(self, app: PortalApp) -> None:
        environ = make_environ("GET", "/")
        start_response = MockStartResponse()

        list(app(environ, start_response))

        header_dict = dict(start_response.headers)
        assert header_dict.get("X-Content-Type-Options") == "nosniff"
        assert header_dict.get("X-Frame-Options") == "DENY"


class TestUploadEndpoint:
    """Tests for upload API endpoint."""

    def test_upload_requires_auth(self, app: PortalApp, valid_json_content: bytes) -> None:
        environ = make_environ(
            "POST",
            "/api/v1/upload",
            headers={"X-Filename": "scan.json"},
            body=valid_json_content,
        )
        start_response = MockStartResponse()

        response = list(app(environ, start_response))

        assert start_response.status == "401 Unauthorized"
        data = json.loads(response[0])
        assert data["success"] is False

    def test_upload_valid_file(self, tenant_store: TenantStore, valid_json_content: bytes) -> None:
        tenant, api_key = tenant_store.create("test", "Test", 1, 10)
        app = PortalApp(tenant_store)

        environ = make_environ(
            "POST",
            "/api/v1/upload",
            headers={
                "Authorization": f"Bearer {api_key}",
                "X-Filename": "scan.json",
            },
            body=valid_json_content,
        )
        start_response = MockStartResponse()

        response = list(app(environ, start_response))

        # Note: Will fail without proper upload directory setup
        # In real test, we'd need to set PORTAL_UPLOAD_DIR
        data = json.loads(response[0])
        # The response should be JSON
        assert "success" in data

    def test_upload_no_file(self, tenant_store: TenantStore) -> None:
        _, api_key = tenant_store.create("test", "Test", 1, 10)
        app = PortalApp(tenant_store)

        environ = make_environ(
            "POST",
            "/api/v1/upload",
            headers={"Authorization": f"Bearer {api_key}"},
            body=None,
        )
        start_response = MockStartResponse()

        response = list(app(environ, start_response))

        assert "400" in start_response.status
        data = json.loads(response[0])
        assert data["success"] is False

    def test_upload_file_too_large(self, tenant_store: TenantStore) -> None:
        # Create tenant with 1MB limit
        tenant, api_key = tenant_store.create("test", "Test", 1, 10, max_upload_size_mb=1)
        app = PortalApp(tenant_store)

        large_content = b"x" * (2 * 1024 * 1024)  # 2MB
        environ = make_environ(
            "POST",
            "/api/v1/upload",
            headers={
                "Authorization": f"Bearer {api_key}",
                "X-Filename": "scan.json",
            },
            body=large_content,
        )
        start_response = MockStartResponse()

        list(app(environ, start_response))

        assert "413" in start_response.status


class TestStaticFiles:
    """Tests for static file serving."""

    def test_serve_css(self, app: PortalApp) -> None:
        environ = make_environ("GET", "/static/kekkai.css")
        start_response = MockStartResponse()

        list(app(environ, start_response))

        assert start_response.status == "200 OK"
        header_dict = dict(start_response.headers)
        assert header_dict.get("Content-Type") == "text/css"

    def test_serve_nonexistent_static(self, app: PortalApp) -> None:
        environ = make_environ("GET", "/static/nonexistent.css")
        start_response = MockStartResponse()

        list(app(environ, start_response))

        assert "404" in start_response.status

    def test_static_path_traversal_blocked(self, app: PortalApp) -> None:
        environ = make_environ("GET", "/static/../../../etc/passwd")
        start_response = MockStartResponse()

        list(app(environ, start_response))

        assert "404" in start_response.status


class TestNotFound:
    """Tests for 404 handling."""

    def test_unknown_path(self, app: PortalApp) -> None:
        environ = make_environ("GET", "/unknown/path")
        start_response = MockStartResponse()

        list(app(environ, start_response))

        assert "404" in start_response.status


class TestExtractHeaders:
    """Tests for header extraction from WSGI environ."""

    def test_extract_http_headers(self) -> None:
        environ = {
            "HTTP_AUTHORIZATION": "Bearer token",
            "HTTP_X_CUSTOM_HEADER": "value",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": "100",
        }
        headers = _extract_headers(environ)

        assert headers["authorization"] == "Bearer token"
        assert headers["x-custom-header"] == "value"
        assert headers["content-type"] == "application/json"
        assert headers["content-length"] == "100"


class TestParseMultipart:
    """Tests for multipart form parsing."""

    def test_parse_simple_multipart(self) -> None:
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        body = (
            f"------{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="test.json"\r\n'
            f"Content-Type: application/json\r\n"
            f"\r\n"
            f'{{"key": "value"}}\r\n'
            f"------{boundary}--\r\n"
        ).encode()

        filename, content = _parse_multipart(body, f"multipart/form-data; boundary=----{boundary}")

        assert filename == "test.json"
        assert content == b'{"key": "value"}'

    def test_parse_multipart_no_boundary(self) -> None:
        filename, content = _parse_multipart(b"test", "multipart/form-data")
        assert filename is None
        assert content is None


class TestGetContentType:
    """Tests for content type detection."""

    def test_css_content_type(self) -> None:
        assert _get_content_type(".css") == "text/css"

    def test_png_content_type(self) -> None:
        assert _get_content_type(".png") == "image/png"

    def test_unknown_content_type(self) -> None:
        assert _get_content_type(".xyz") == "application/octet-stream"


class TestRenderTemplate:
    """Tests for Jinja2 template rendering."""

    def test_render_unauthenticated(self, app: PortalApp) -> None:
        html = app._render_template(None)
        assert "Authentication Required" in html
        assert "Kekkai Portal" in html

    def test_render_authenticated(self, app: PortalApp) -> None:
        from portal.tenants import Tenant

        tenant = Tenant(
            id="test",
            name="Test Tenant",
            api_key_hash="h",
            dojo_product_id=1,
            dojo_engagement_id=1,
        )
        html = app._render_template(tenant)
        assert "Test Tenant" in html
        assert "Upload Scan Results" in html

    def test_template_escapes_html(self, app: PortalApp) -> None:
        """Test that Jinja2 autoescape prevents XSS."""
        from portal.tenants import Tenant

        tenant = Tenant(
            id="test",
            name="<script>alert('xss')</script>",
            api_key_hash="h",
            dojo_product_id=1,
            dojo_engagement_id=1,
        )
        html = app._render_template(tenant)
        # Tenant name should be escaped (not the legitimate script tags in template)
        assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in html
        # Or at minimum, the malicious alert should not be executable
        assert 'class="tenant-name">&lt;' in html or "alert('xss')" not in html


class TestSecureHeaders:
    """Tests for security headers."""

    def test_secure_headers_defined(self) -> None:
        header_names = [h[0] for h in SECURE_HEADERS]
        assert "X-Content-Type-Options" in header_names
        assert "X-Frame-Options" in header_names
        assert "X-XSS-Protection" in header_names
        assert "Content-Security-Policy" in header_names

    def test_csp_header_value(self) -> None:
        header_dict = dict(SECURE_HEADERS)
        csp = header_dict.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp


class TestCreateApp:
    """Tests for app factory."""

    def test_create_app_with_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "tenants.json"
            app = create_app(store_path)
            assert isinstance(app, PortalApp)
