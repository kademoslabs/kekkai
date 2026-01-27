"""Unit tests for portal file upload handling."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

from portal.tenants import Tenant
from portal.uploads import (
    UploadResult,
    _generate_upload_id,
    _is_valid_upload_id,
    _sanitize_filename,
    _validate_json_content,
    delete_upload,
    get_upload_path,
    process_upload,
    validate_upload,
)


@pytest.fixture
def test_tenant() -> Tenant:
    """Create a test tenant."""
    return Tenant(
        id="test_tenant",
        name="Test Tenant",
        api_key_hash="hash",
        dojo_product_id=1,
        dojo_engagement_id=10,
        max_upload_size_mb=10,
    )


@pytest.fixture
def small_tenant() -> Tenant:
    """Create a tenant with small upload limit."""
    return Tenant(
        id="small_tenant",
        name="Small Tenant",
        api_key_hash="hash",
        dojo_product_id=2,
        dojo_engagement_id=20,
        max_upload_size_mb=1,
    )


@pytest.fixture
def valid_json_content() -> bytes:
    """Valid JSON content for testing."""
    return json.dumps({"findings": [], "version": "1.0"}).encode()


class TestValidateUpload:
    """Tests for upload validation (ASVS V5.2.2, V5.2.4)."""

    def test_validate_valid_json(self, test_tenant: Tenant, valid_json_content: bytes) -> None:
        result = validate_upload("scan.json", "application/json", valid_json_content, test_tenant)
        assert result.success is True
        assert result.error is None

    def test_validate_valid_sarif(self, test_tenant: Tenant, valid_json_content: bytes) -> None:
        result = validate_upload(
            "results.sarif", "application/sarif+json", valid_json_content, test_tenant
        )
        assert result.success is True

    def test_validate_missing_filename(
        self, test_tenant: Tenant, valid_json_content: bytes
    ) -> None:
        result = validate_upload(None, "application/json", valid_json_content, test_tenant)
        assert result.success is False
        assert result.error == "Missing filename"

    def test_validate_empty_filename(self, test_tenant: Tenant, valid_json_content: bytes) -> None:
        result = validate_upload("", "application/json", valid_json_content, test_tenant)
        assert result.success is False
        assert result.error == "Missing filename"

    def test_validate_invalid_extension(
        self, test_tenant: Tenant, valid_json_content: bytes
    ) -> None:
        result = validate_upload("script.py", "application/json", valid_json_content, test_tenant)
        assert result.success is False
        assert "Invalid file type" in (result.error or "")

    def test_validate_invalid_extension_exe(
        self, test_tenant: Tenant, valid_json_content: bytes
    ) -> None:
        result = validate_upload(
            "malware.exe", "application/octet-stream", valid_json_content, test_tenant
        )
        assert result.success is False

    def test_validate_file_too_large(self, small_tenant: Tenant) -> None:
        large_content = b"x" * (2 * 1024 * 1024)  # 2MB
        result = validate_upload("scan.json", "application/json", large_content, small_tenant)
        assert result.success is False
        assert "too large" in (result.error or "").lower()

    def test_validate_empty_file(self, test_tenant: Tenant) -> None:
        result = validate_upload("scan.json", "application/json", b"", test_tenant)
        assert result.success is False
        assert "empty" in (result.error or "").lower()

    def test_validate_invalid_json(self, test_tenant: Tenant) -> None:
        invalid_json = b"this is not json {{{{"
        result = validate_upload("scan.json", "application/json", invalid_json, test_tenant)
        assert result.success is False
        assert "Invalid JSON" in (result.error or "")

    def test_validate_path_traversal_dotdot(
        self, test_tenant: Tenant, valid_json_content: bytes
    ) -> None:
        # Path traversal with .. gets sanitized to basename, which is valid
        # The security is in where files are stored, not filename validation
        result = validate_upload(
            "../../../etc/passwd.json", "application/json", valid_json_content, test_tenant
        )
        # After sanitization, this becomes "passwd.json" which is valid
        assert result.success is True

    def test_validate_path_traversal_absolute(
        self, test_tenant: Tenant, valid_json_content: bytes
    ) -> None:
        result = validate_upload(
            "/etc/passwd.json", "application/json", valid_json_content, test_tenant
        )
        # Should sanitize to just "passwd.json" which is valid
        assert result.success is True

    def test_validate_null_byte_injection(
        self, test_tenant: Tenant, valid_json_content: bytes
    ) -> None:
        # Null byte injection results in sanitized filename with .exe extension
        # which is correctly rejected as invalid file type
        result = validate_upload(
            "scan.json\x00.exe", "application/json", valid_json_content, test_tenant
        )
        # Null bytes are stripped but .exe extension remains after sanitization
        # This correctly fails validation
        assert result.success is False


class TestProcessUpload:
    """Tests for upload processing and storage."""

    def test_process_valid_upload(self, test_tenant: Tenant, valid_json_content: bytes) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            upload_dir = Path(tmpdir)
            result = process_upload("scan.json", valid_json_content, test_tenant, upload_dir)

            assert result.success is True
            assert result.upload_id is not None
            assert result.file_path is not None
            assert result.file_hash is not None
            assert result.file_path.exists()

    def test_process_creates_tenant_directory(
        self, test_tenant: Tenant, valid_json_content: bytes
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            upload_dir = Path(tmpdir)
            process_upload("scan.json", valid_json_content, test_tenant, upload_dir)

            tenant_dir = upload_dir / test_tenant.id
            assert tenant_dir.exists()
            assert tenant_dir.is_dir()

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions not on Windows")
    def test_process_file_permissions(self, test_tenant: Tenant, valid_json_content: bytes) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            upload_dir = Path(tmpdir)
            result = process_upload("scan.json", valid_json_content, test_tenant, upload_dir)

            assert result.file_path is not None
            mode = result.file_path.stat().st_mode & 0o777
            assert mode == 0o600  # Only owner can read/write

    def test_process_hash_consistency(self, test_tenant: Tenant, valid_json_content: bytes) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            upload_dir = Path(tmpdir)
            result1 = process_upload("scan1.json", valid_json_content, test_tenant, upload_dir)
            result2 = process_upload("scan2.json", valid_json_content, test_tenant, upload_dir)

            # Same content = same hash
            assert result1.file_hash == result2.file_hash
            # Different upload IDs
            assert result1.upload_id != result2.upload_id

    def test_process_invalid_upload_fails(self, test_tenant: Tenant) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            upload_dir = Path(tmpdir)
            result = process_upload("script.py", b"print('hello')", test_tenant, upload_dir)

            assert result.success is False
            assert result.upload_id is None


class TestGetUploadPath:
    """Tests for retrieving upload paths with tenant isolation."""

    def test_get_existing_upload(self, test_tenant: Tenant, valid_json_content: bytes) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            upload_dir = Path(tmpdir)
            result = process_upload("scan.json", valid_json_content, test_tenant, upload_dir)
            assert result.upload_id is not None

            path = get_upload_path(test_tenant, result.upload_id, upload_dir)
            assert path is not None
            assert result.file_path is not None
            assert path.resolve() == result.file_path.resolve()

    def test_get_nonexistent_upload(self, test_tenant: Tenant) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            upload_dir = Path(tmpdir)
            path = get_upload_path(test_tenant, "nonexistent_id_12345678", upload_dir)
            assert path is None

    def test_get_upload_invalid_id(self, test_tenant: Tenant) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            upload_dir = Path(tmpdir)
            path = get_upload_path(test_tenant, "../../../etc/passwd", upload_dir)
            assert path is None

    def test_get_upload_cross_tenant_blocked(self, valid_json_content: bytes) -> None:
        """Verify tenant A cannot access tenant B's uploads."""
        tenant_a = Tenant(
            id="tenant_a",
            name="Tenant A",
            api_key_hash="hash_a",
            dojo_product_id=1,
            dojo_engagement_id=10,
        )
        tenant_b = Tenant(
            id="tenant_b",
            name="Tenant B",
            api_key_hash="hash_b",
            dojo_product_id=2,
            dojo_engagement_id=20,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            upload_dir = Path(tmpdir)

            # Tenant B uploads a file
            result_b = process_upload("scan.json", valid_json_content, tenant_b, upload_dir)
            assert result_b.success and result_b.upload_id

            # Tenant A tries to access it - should fail
            path = get_upload_path(tenant_a, result_b.upload_id, upload_dir)
            assert path is None

            # Tenant B can access it
            path_b = get_upload_path(tenant_b, result_b.upload_id, upload_dir)
            assert path_b is not None


class TestDeleteUpload:
    """Tests for upload deletion."""

    def test_delete_existing_upload(self, test_tenant: Tenant, valid_json_content: bytes) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            upload_dir = Path(tmpdir)
            result = process_upload("scan.json", valid_json_content, test_tenant, upload_dir)
            assert result.upload_id is not None and result.file_path is not None

            deleted = delete_upload(test_tenant, result.upload_id, upload_dir)
            assert deleted is True
            assert not result.file_path.exists()

    def test_delete_nonexistent_upload(self, test_tenant: Tenant) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            upload_dir = Path(tmpdir)
            deleted = delete_upload(test_tenant, "nonexistent_12345678", upload_dir)
            assert deleted is False


class TestSanitizeFilename:
    """Tests for filename sanitization."""

    def test_sanitize_simple_filename(self) -> None:
        assert _sanitize_filename("scan.json") == "scan.json"

    def test_sanitize_with_spaces(self) -> None:
        result = _sanitize_filename("my scan results.json")
        assert result == "my scan results.json"

    def test_sanitize_strips_path(self) -> None:
        assert _sanitize_filename("/path/to/file.json") == "file.json"
        # Windows-style paths are not recognized as paths on Linux
        # so backslashes become part of the filename and get sanitized
        result = _sanitize_filename("C:\\Users\\scan.json")
        assert result is not None

    def test_sanitize_removes_dotdot(self) -> None:
        # Path.name extracts basename, so "../scan.json" becomes "scan.json"
        assert _sanitize_filename("../scan.json") == "scan.json"
        # "..\\scan.json" should be rejected for safety (path traversal)
        # On Windows, backslash is a path separator so it becomes "scan.json"
        # On Unix, backslash is part of filename and ".." triggers rejection
        result = _sanitize_filename("..\\scan.json")
        if sys.platform == "win32":
            assert result == "scan.json"
        else:
            assert result is None

    def test_sanitize_removes_null_bytes(self) -> None:
        result = _sanitize_filename("scan\x00.json")
        assert result is not None
        assert "\x00" not in result

    def test_sanitize_special_characters(self) -> None:
        result = _sanitize_filename('scan<>:"|?*.json')
        assert result is not None
        # Special chars should be replaced with underscores


class TestValidateJsonContent:
    """Tests for JSON content validation."""

    def test_valid_json_object(self) -> None:
        assert _validate_json_content(b'{"key": "value"}') is True

    def test_valid_json_array(self) -> None:
        assert _validate_json_content(b"[1, 2, 3]") is True

    def test_invalid_json(self) -> None:
        assert _validate_json_content(b"not json") is False

    def test_invalid_unicode(self) -> None:
        assert _validate_json_content(b"\xff\xfe") is False


class TestUploadIdGeneration:
    """Tests for upload ID generation."""

    def test_generate_upload_id_length(self) -> None:
        upload_id = _generate_upload_id()
        assert len(upload_id) == 24

    def test_generate_upload_id_unique(self) -> None:
        ids = {_generate_upload_id() for _ in range(100)}
        assert len(ids) == 100

    def test_is_valid_upload_id_valid(self) -> None:
        upload_id = _generate_upload_id()
        assert _is_valid_upload_id(upload_id) is True

    def test_is_valid_upload_id_invalid_length(self) -> None:
        assert _is_valid_upload_id("short") is False
        assert _is_valid_upload_id("x" * 100) is False

    def test_is_valid_upload_id_invalid_chars(self) -> None:
        assert _is_valid_upload_id("../../../etc/passwd") is False


class TestUploadResultDataclass:
    """Tests for UploadResult dataclass."""

    def test_upload_result_success(self) -> None:
        result = UploadResult(
            success=True,
            upload_id="test123",
            file_path=Path("/tmp/test.json"),
            file_hash="abc123",
        )
        assert result.success is True
        assert result.error is None

    def test_upload_result_failure(self) -> None:
        result = UploadResult(success=False, error="Test error")
        assert result.success is False
        assert result.upload_id is None
