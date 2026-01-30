"""Portal WSGI web application with Kekkai theming.

Provides:
- Upload API endpoint (POST /api/v1/upload)
- Dashboard with Kekkai branding
- Static asset serving
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, BinaryIO, cast

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .api import get_tenant_info, get_tenant_stats, list_uploads
from .auth import authenticate_request
from .tenants import Tenant, TenantStore
from .uploads import process_upload, validate_upload

try:
    from .enterprise import ENTERPRISE_AVAILABLE
    from .enterprise import rbac as enterprise_rbac
    from .enterprise import saml as enterprise_saml
except ImportError:
    ENTERPRISE_AVAILABLE = False
    enterprise_saml = None  # type: ignore[assignment]
    enterprise_rbac = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

Environ = dict[str, Any]
StartResponse = Callable[[str, list[tuple[str, str]]], Callable[[bytes], Any]]

STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"

SECURE_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("X-XSS-Protection", "1; mode=block"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    (
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
    ),
]

MULTIPART_BOUNDARY_PATTERN = re.compile(r"boundary=([^\s;]+)", re.IGNORECASE)


class PortalApp:
    """Kekkai Portal WSGI Application."""

    def __init__(self, tenant_store: TenantStore) -> None:
        self._tenant_store = tenant_store
        self._jinja_env = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def __call__(self, environ: Environ, start_response: StartResponse) -> Iterable[bytes]:
        path = str(environ.get("PATH_INFO", "/"))
        method = str(environ.get("REQUEST_METHOD", "GET"))

        if path.startswith("/static/"):
            return self._serve_static(path, start_response)

        if path == "/api/v1/upload" and method == "POST":
            return self._handle_upload(environ, start_response)

        if path == "/api/v1/health":
            return self._handle_health(start_response)

        if path == "/api/v1/tenant/info" and method == "GET":
            return self._handle_tenant_info(environ, start_response)

        if path == "/api/v1/uploads" and method == "GET":
            return self._handle_list_uploads(environ, start_response)

        if path == "/api/v1/stats" and method == "GET":
            return self._handle_stats(environ, start_response)

        if path == "/" and method == "GET":
            return self._serve_dashboard(environ, start_response)

        return self._not_found(start_response)

    def _handle_upload(self, environ: Environ, start_response: StartResponse) -> Iterable[bytes]:
        """Handle file upload with authentication and validation."""
        client_ip = str(environ.get("REMOTE_ADDR", "unknown"))
        headers = _extract_headers(environ)

        auth_result = authenticate_request(headers, self._tenant_store, client_ip)
        if not auth_result.authenticated or not auth_result.tenant:
            return self._unauthorized(start_response, auth_result.error or "Unauthorized")

        tenant = auth_result.tenant

        content_type = headers.get("content-type", "")
        content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)

        if content_length > tenant.max_upload_size_mb * 1024 * 1024:
            return self._error_response(
                start_response,
                413,
                f"File too large. Maximum: {tenant.max_upload_size_mb}MB",
            )

        input_stream = environ.get("wsgi.input")
        if not input_stream or content_length == 0:
            return self._error_response(start_response, 400, "No file provided")

        body = cast(BinaryIO, input_stream).read(content_length)

        if "multipart/form-data" in content_type:
            filename, file_content = _parse_multipart(body, content_type)
        else:
            filename = headers.get("x-filename", "upload.json")
            file_content = body

        if not filename or not file_content:
            return self._error_response(start_response, 400, "Invalid upload")

        validation = validate_upload(filename, content_type, file_content, tenant)
        if not validation.success:
            return self._error_response(
                start_response, 400, validation.error or "Validation failed"
            )

        result = process_upload(filename, file_content, tenant)
        if not result.success:
            return self._error_response(start_response, 500, result.error or "Upload failed")

        logger.info(
            "upload.complete tenant=%s upload_id=%s",
            tenant.id,
            result.upload_id,
        )

        response_data = {
            "success": True,
            "upload_id": result.upload_id,
            "file_hash": result.file_hash,
            "tenant_id": tenant.id,
            "dojo_product_id": tenant.dojo_product_id,
            "dojo_engagement_id": tenant.dojo_engagement_id,
        }

        return self._json_response(start_response, 200, response_data)

    def _handle_health(self, start_response: StartResponse) -> Iterable[bytes]:
        """Health check endpoint."""
        return self._json_response(start_response, 200, {"status": "healthy"})

    def _handle_tenant_info(
        self, environ: Environ, start_response: StartResponse
    ) -> Iterable[bytes]:
        """Get current tenant information."""
        headers = _extract_headers(environ)
        client_ip = str(environ.get("REMOTE_ADDR", "unknown"))

        auth_result = authenticate_request(headers, self._tenant_store, client_ip)
        if not auth_result.authenticated or not auth_result.tenant:
            return self._unauthorized(start_response, auth_result.error or "Unauthorized")

        tenant_info = get_tenant_info(auth_result.tenant)
        return self._json_response(start_response, 200, tenant_info)

    def _handle_list_uploads(
        self, environ: Environ, start_response: StartResponse
    ) -> Iterable[bytes]:
        """List recent uploads for authenticated tenant."""
        headers = _extract_headers(environ)
        client_ip = str(environ.get("REMOTE_ADDR", "unknown"))

        auth_result = authenticate_request(headers, self._tenant_store, client_ip)
        if not auth_result.authenticated or not auth_result.tenant:
            return self._unauthorized(start_response, auth_result.error or "Unauthorized")

        # Parse limit parameter from query string
        query_string = str(environ.get("QUERY_STRING", ""))
        limit = 50
        if "limit=" in query_string:
            try:
                limit_str = query_string.split("limit=")[1].split("&")[0]
                limit = min(int(limit_str), 100)  # Cap at 100
            except (ValueError, IndexError):
                pass

        uploads = list_uploads(auth_result.tenant, limit)
        return self._json_response(start_response, 200, {"uploads": uploads})

    def _handle_stats(self, environ: Environ, start_response: StartResponse) -> Iterable[bytes]:
        """Get statistics for authenticated tenant."""
        headers = _extract_headers(environ)
        client_ip = str(environ.get("REMOTE_ADDR", "unknown"))

        auth_result = authenticate_request(headers, self._tenant_store, client_ip)
        if not auth_result.authenticated or not auth_result.tenant:
            return self._unauthorized(start_response, auth_result.error or "Unauthorized")

        stats = get_tenant_stats(auth_result.tenant)
        return self._json_response(start_response, 200, stats)

    def _serve_dashboard(self, environ: Environ, start_response: StartResponse) -> Iterable[bytes]:
        """Serve the Kekkai-themed dashboard."""
        headers = _extract_headers(environ)
        client_ip = str(environ.get("REMOTE_ADDR", "unknown"))

        auth_result = authenticate_request(headers, self._tenant_store, client_ip)
        tenant = auth_result.tenant if auth_result.authenticated else None

        content = self._render_template(tenant)
        response_headers = [("Content-Type", "text/html; charset=utf-8")] + SECURE_HEADERS
        start_response("200 OK", response_headers)
        return [content.encode("utf-8")]

    def _render_template(self, tenant: Tenant | None) -> str:
        """Render dashboard or login template based on authentication."""
        if tenant:
            template = self._jinja_env.get_template("dashboard.html")
            return str(template.render(tenant=tenant.to_dict()))
        else:
            template = self._jinja_env.get_template("login.html")
            return str(template.render())

    def _serve_static(self, path: str, start_response: StartResponse) -> Iterable[bytes]:
        """Serve static assets with security checks."""
        relative_path = path.removeprefix("/static/")
        if ".." in relative_path or relative_path.startswith("/"):
            return self._not_found(start_response)

        file_path = STATIC_DIR / relative_path
        try:
            resolved = file_path.resolve()
            if not resolved.is_relative_to(STATIC_DIR.resolve()):
                return self._not_found(start_response)
        except (ValueError, OSError):
            return self._not_found(start_response)

        if not file_path.exists() or not file_path.is_file():
            return self._not_found(start_response)

        content_type = _get_content_type(file_path.suffix)
        content = file_path.read_bytes()

        response_headers = [("Content-Type", content_type)] + SECURE_HEADERS
        start_response("200 OK", response_headers)
        return [content]

    def _json_response(
        self,
        start_response: StartResponse,
        status_code: int,
        data: dict[str, Any],
    ) -> Iterable[bytes]:
        """Send a JSON response."""
        status = f"{status_code} {'OK' if status_code == 200 else 'Error'}"
        response_headers = [("Content-Type", "application/json")] + SECURE_HEADERS
        start_response(status, response_headers)
        return [json.dumps(data).encode("utf-8")]

    def _error_response(
        self,
        start_response: StartResponse,
        status_code: int,
        message: str,
    ) -> Iterable[bytes]:
        """Send an error response."""
        return self._json_response(
            start_response,
            status_code,
            {"success": False, "error": message},
        )

    def _unauthorized(self, start_response: StartResponse, message: str) -> Iterable[bytes]:
        """Send 401 Unauthorized response."""
        response_headers = [
            ("Content-Type", "application/json"),
            ("WWW-Authenticate", "Bearer"),
        ] + SECURE_HEADERS
        start_response("401 Unauthorized", response_headers)
        return [json.dumps({"success": False, "error": message}).encode("utf-8")]

    def _not_found(self, start_response: StartResponse) -> Iterable[bytes]:
        """Send 404 Not Found response."""
        return self._error_response(start_response, 404, "Not found")


def create_app(tenant_store_path: Path | None = None) -> PortalApp:
    """Create a configured PortalApp instance."""
    store_path = tenant_store_path or Path(
        os.environ.get("PORTAL_TENANT_STORE", "/var/lib/kekkai-portal/tenants.json")
    )
    tenant_store = TenantStore(store_path)
    return PortalApp(tenant_store)


def main() -> int:
    """Run the portal development server."""
    from wsgiref.simple_server import make_server

    host = os.environ.get("PORTAL_HOST", "127.0.0.1")
    port = int(os.environ.get("PORTAL_PORT", "8000"))
    tenant_store = os.environ.get("PORTAL_TENANT_STORE")

    store_path = Path(tenant_store) if tenant_store else None
    app = create_app(store_path)

    print(f"Starting Kekkai Portal on http://{host}:{port}")
    print("Press Ctrl+C to stop")

    with make_server(host, port, app) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())


def _extract_headers(environ: Environ) -> dict[str, str]:
    """Extract HTTP headers from WSGI environ."""
    headers: dict[str, str] = {}
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            header_name = key[5:].replace("_", "-").lower()
            headers[header_name] = str(value)
        elif key == "CONTENT_TYPE":
            headers["content-type"] = str(value)
        elif key == "CONTENT_LENGTH":
            headers["content-length"] = str(value)
    return headers


def _parse_multipart(body: bytes, content_type: str) -> tuple[str | None, bytes | None]:
    """Parse multipart form data to extract file."""
    match = MULTIPART_BOUNDARY_PATTERN.search(content_type)
    if not match:
        return None, None

    boundary = match.group(1).encode()
    if boundary.startswith(b'"') and boundary.endswith(b'"'):
        boundary = boundary[1:-1]

    parts = body.split(b"--" + boundary)
    for part in parts:
        if b"Content-Disposition" not in part:
            continue

        header_end = part.find(b"\r\n\r\n")
        if header_end == -1:
            continue

        headers_raw = part[:header_end].decode("utf-8", errors="replace")
        content = part[header_end + 4 :]

        if content.endswith(b"\r\n"):
            content = content[:-2]

        filename_match = re.search(r'filename="([^"]+)"', headers_raw)
        if filename_match:
            return filename_match.group(1), content

    return None, None


def _get_content_type(extension: str) -> str:
    """Get MIME type for file extension."""
    types = {
        ".css": "text/css",
        ".js": "application/javascript",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".svg": "image/svg+xml",
        ".ico": "image/x-icon",
        ".woff": "font/woff",
        ".woff2": "font/woff2",
    }
    return types.get(extension.lower(), "application/octet-stream")
