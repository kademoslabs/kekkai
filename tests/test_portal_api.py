"""Unit tests for portal API module."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from portal.api import get_tenant_info, get_tenant_stats, list_uploads, serialize_api_response
from portal.tenants import Tenant


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


class TestGetTenantInfo:
    """Tests for get_tenant_info function."""

    def test_returns_tenant_metadata(self, test_tenant: Tenant) -> None:
        """get_tenant_info returns expected tenant metadata."""
        info = get_tenant_info(test_tenant)

        assert info["id"] == "test-tenant"
        assert info["name"] == "Test Organization"
        assert info["dojo_product_id"] == 42
        assert info["dojo_engagement_id"] == 100
        assert info["enabled"] is True
        assert info["max_upload_size_mb"] == 10
        assert "auth_method" in info
        assert "default_role" in info

    def test_does_not_leak_sensitive_data(self, test_tenant: Tenant) -> None:
        """get_tenant_info does not include sensitive fields."""
        info = get_tenant_info(test_tenant)

        assert "api_key_hash" not in info
        assert "api_key" not in info


class TestListUploads:
    """Tests for list_uploads function."""

    def test_returns_empty_list_when_no_uploads(self, test_tenant: Tenant) -> None:
        """list_uploads returns empty list when tenant has no uploads."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["PORTAL_UPLOAD_DIR"] = tmpdir
            try:
                uploads = list_uploads(test_tenant)
                assert uploads == []
            finally:
                del os.environ["PORTAL_UPLOAD_DIR"]

    def test_returns_uploads_for_tenant(self, test_tenant: Tenant) -> None:
        """list_uploads returns uploads only for the specified tenant."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["PORTAL_UPLOAD_DIR"] = tmpdir
            try:
                # Create tenant upload directory
                tenant_dir = Path(tmpdir) / "test-tenant"
                tenant_dir.mkdir()

                # Create upload files
                (tenant_dir / "upload1.json").write_text("{}")
                (tenant_dir / "upload2.json").write_text("{}")

                uploads = list_uploads(test_tenant)

                assert len(uploads) == 2
                assert uploads[0]["filename"] in ["upload1.json", "upload2.json"]
                assert "upload_id" in uploads[0]
                assert "timestamp" in uploads[0]
                assert "size_bytes" in uploads[0]
            finally:
                del os.environ["PORTAL_UPLOAD_DIR"]

    def test_respects_limit_parameter(self, test_tenant: Tenant) -> None:
        """list_uploads respects the limit parameter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["PORTAL_UPLOAD_DIR"] = tmpdir
            try:
                tenant_dir = Path(tmpdir) / "test-tenant"
                tenant_dir.mkdir()

                # Create 5 upload files
                for i in range(5):
                    (tenant_dir / f"upload{i}.json").write_text("{}")

                uploads = list_uploads(test_tenant, limit=2)

                assert len(uploads) == 2
            finally:
                del os.environ["PORTAL_UPLOAD_DIR"]


class TestGetTenantStats:
    """Tests for get_tenant_stats function."""

    def test_returns_zero_stats_when_no_uploads(self, test_tenant: Tenant) -> None:
        """get_tenant_stats returns zero stats when no uploads exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["PORTAL_UPLOAD_DIR"] = tmpdir
            try:
                stats = get_tenant_stats(test_tenant)

                assert stats["total_uploads"] == 0
                assert stats["total_size_bytes"] == 0
                assert stats["last_upload_time"] is None
            finally:
                del os.environ["PORTAL_UPLOAD_DIR"]

    def test_calculates_stats_correctly(self, test_tenant: Tenant) -> None:
        """get_tenant_stats calculates statistics correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["PORTAL_UPLOAD_DIR"] = tmpdir
            try:
                tenant_dir = Path(tmpdir) / "test-tenant"
                tenant_dir.mkdir()

                # Create upload files with different sizes
                (tenant_dir / "upload1.json").write_text("abc")  # 3 bytes
                (tenant_dir / "upload2.json").write_text("defgh")  # 5 bytes

                stats = get_tenant_stats(test_tenant)

                assert stats["total_uploads"] == 2
                assert stats["total_size_bytes"] == 8
                assert stats["last_upload_time"] is not None
            finally:
                del os.environ["PORTAL_UPLOAD_DIR"]


class TestSerializeApiResponse:
    """Tests for serialize_api_response function."""

    def test_serializes_dict_to_json(self) -> None:
        """serialize_api_response converts dict to JSON bytes."""
        data = {"key": "value", "number": 42}
        result = serialize_api_response(data)

        assert isinstance(result, bytes)
        assert b'"key"' in result
        assert b'"value"' in result
        assert b'"number"' in result
        assert b"42" in result
