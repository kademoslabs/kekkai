"""Regression tests for portal HTML snapshots.

Ensures HTML structure stability and prevents breaking changes to UI.
"""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from portal.tenants import Tenant, TenantStore
from portal.web import PortalApp


@pytest.fixture
def app() -> Generator[PortalApp, None, None]:
    """Create a portal app for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "tenants.json"
        store = TenantStore(store_path)
        yield PortalApp(store)


@pytest.fixture
def test_tenant() -> Tenant:
    """Create a test tenant."""
    return Tenant(
        id="test-tenant",
        name="Test Organization",
        api_key_hash="hash123",
        dojo_product_id=42,
        dojo_engagement_id=100,
        enabled=True,
        max_upload_size_mb=10,
    )


@pytest.mark.regression
class TestDashboardHtmlSnapshot:
    """Regression tests for dashboard HTML structure."""

    def test_authenticated_dashboard_structure(self, app: PortalApp, test_tenant: Tenant) -> None:
        """Authenticated dashboard contains expected structural elements."""
        html = app._render_template(test_tenant)

        # Verify core HTML structure
        assert "<!DOCTYPE html>" in html
        assert '<html lang="en">' in html
        assert "<head>" in html and "</head>" in html
        assert "<body>" in html and "</body>" in html

        # Verify header section
        assert '<header class="header">' in html
        assert "Kekkai Portal" in html
        assert '<div class="logo">' in html

        # Verify tenant info is displayed
        assert '<div class="tenant-info">' in html
        assert "Test Organization" in html
        assert "test-tenant" in html

        # Verify main content
        assert '<main class="main">' in html
        assert '<section class="hero">' in html
        assert "Security that moves at developer speed" in html

        # Verify upload section
        assert '<section class="upload-section">' in html
        assert "Upload Scan Results" in html
        assert '<form id="upload-form"' in html
        assert 'type="file"' in html
        assert 'accept=".json,.sarif"' in html

        # Verify footer
        assert '<footer class="footer">' in html
        assert "Kademos Labs" in html

        # Verify JavaScript is present
        assert "<script>" in html
        assert "upload-form" in html
        assert "/api/v1/upload" in html

    def test_authenticated_dashboard_no_fstrings(self, app: PortalApp, test_tenant: Tenant) -> None:
        """Dashboard HTML should not contain f-string artifacts."""
        html = app._render_template(test_tenant)

        # These would appear if f-strings were still being used incorrectly
        assert "{tenant" not in html.lower()
        assert "{{" not in html or "addEventListener" in html  # Allow in JS
        assert "}}" not in html or "addEventListener" in html  # Allow in JS


@pytest.mark.regression
class TestLoginHtmlSnapshot:
    """Regression tests for unauthenticated login page structure."""

    def test_unauthenticated_login_structure(self, app: PortalApp) -> None:
        """Unauthenticated page contains expected structural elements."""
        html = app._render_template(None)

        # Verify core HTML structure
        assert "<!DOCTYPE html>" in html
        assert '<html lang="en">' in html
        assert "<head>" in html and "</head>" in html
        assert "<body>" in html and "</body>" in html

        # Verify header section (no tenant info)
        assert '<header class="header">' in html
        assert "Kekkai Portal" in html
        assert '<div class="tenant-info">' not in html

        # Verify main content
        assert '<main class="main">' in html
        assert '<section class="hero">' in html
        assert "Security that moves at developer speed" in html

        # Verify auth prompt
        assert '<section class="auth-section">' in html
        assert "Authentication Required" in html
        assert "Authorization: Bearer" in html
        assert "api-key" in html

        # Verify upload form is NOT present
        assert '<section class="upload-section">' not in html
        assert '<form id="upload-form"' not in html

        # Verify footer
        assert '<footer class="footer">' in html
        assert "Kademos Labs" in html

    def test_unauthenticated_no_sensitive_data(self, app: PortalApp) -> None:
        """Unauthenticated page should not leak tenant data."""
        html = app._render_template(None)

        # Should not contain any tenant-specific information
        assert "tenant_id" not in html.lower()
        assert "api_key" not in html.lower() or "api-key" in html.lower()  # Allow instruction text
        assert "dojo_product" not in html.lower()


@pytest.mark.regression
class TestHtmlSecurityHeaders:
    """Regression tests ensuring security-critical HTML features."""

    def test_meta_charset_present(self, app: PortalApp) -> None:
        """HTML must declare UTF-8 charset."""
        html = app._render_template(None)
        assert '<meta charset="UTF-8">' in html

    def test_viewport_meta_present(self, app: PortalApp) -> None:
        """HTML must include viewport meta for responsive design."""
        html = app._render_template(None)
        assert '<meta name="viewport"' in html

    def test_css_linked(self, app: PortalApp) -> None:
        """HTML must link to kekkai.css."""
        html = app._render_template(None)
        assert 'href="/static/kekkai.css"' in html

    def test_xss_protection_escaping(self, app: PortalApp) -> None:
        """HTML content must be escaped to prevent XSS."""
        tenant = Tenant(
            id="<script>alert(1)</script>",
            name='"><img src=x onerror=alert(1)>',
            api_key_hash="hash",
            dojo_product_id=1,
            dojo_engagement_id=1,
        )
        html = app._render_template(tenant)

        # Malicious content should be escaped - raw tags should not appear
        assert "<script>alert(1)</script>" not in html
        assert "<img src=x onerror=alert(1)>" not in html

        # Check that escaping occurred (HTML entities)
        assert "&lt;script&gt;" in html
        assert "&lt;" in html or "&gt;" in html


@pytest.mark.regression
class TestTemplateStability:
    """Regression tests for template file stability."""

    def test_base_template_extends(self, app: PortalApp, test_tenant: Tenant) -> None:
        """Dashboard and login templates should use consistent base structure."""
        dashboard_html = app._render_template(test_tenant)
        login_html = app._render_template(None)

        # Both should share common elements from base.html
        common_elements = [
            '<header class="header">',
            "Kekkai Portal",
            '<footer class="footer">',
            "Kademos Labs",
            "/static/kekkai.css",
        ]

        for element in common_elements:
            assert element in dashboard_html, f"Dashboard missing: {element}"
            assert element in login_html, f"Login missing: {element}"

    def test_template_title_tag(self, app: PortalApp) -> None:
        """HTML must have proper title tag."""
        html = app._render_template(None)
        assert "<title>" in html
        assert "</title>" in html
        assert "Kekkai Portal" in html
