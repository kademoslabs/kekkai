"""Unit tests for installer checksum verification."""

from __future__ import annotations

import hashlib

import pytest

from kekkai.installer import SecurityError, compute_sha256, verify_checksum
from kekkai.installer.verify import MAX_DOWNLOAD_SIZE, verify_file_size


class TestComputeSha256:
    """Test SHA256 computation."""

    def test_compute_sha256_empty(self) -> None:
        expected = hashlib.sha256(b"").hexdigest()
        assert compute_sha256(b"") == expected

    def test_compute_sha256_content(self) -> None:
        content = b"test content for hashing"
        expected = hashlib.sha256(content).hexdigest()
        assert compute_sha256(content) == expected

    def test_compute_sha256_binary(self) -> None:
        content = bytes(range(256))
        expected = hashlib.sha256(content).hexdigest()
        assert compute_sha256(content) == expected


class TestVerifyChecksum:
    """Test checksum verification."""

    def test_valid_checksum_passes(self) -> None:
        content = b"valid binary content"
        valid_hash = hashlib.sha256(content).hexdigest()
        verify_checksum(content, valid_hash, "test_tool")

    def test_invalid_checksum_raises_security_error(self) -> None:
        content = b"actual content"
        wrong_hash = hashlib.sha256(b"different content").hexdigest()

        with pytest.raises(SecurityError, match="Checksum mismatch"):
            verify_checksum(content, wrong_hash, "test_tool")

    def test_tampered_binary_rejected(self) -> None:
        original = b"original safe binary"
        tampered = b"malicious binary content"
        original_hash = hashlib.sha256(original).hexdigest()

        with pytest.raises(SecurityError, match="Checksum mismatch"):
            verify_checksum(tampered, original_hash, "test_tool")

    def test_empty_content_with_correct_hash(self) -> None:
        content = b""
        valid_hash = hashlib.sha256(content).hexdigest()
        verify_checksum(content, valid_hash, "test_tool")


class TestVerifyFileSize:
    """Test file size verification."""

    def test_normal_size_passes(self) -> None:
        verify_file_size(1024 * 1024, "test_tool")  # 1MB

    def test_max_size_passes(self) -> None:
        verify_file_size(MAX_DOWNLOAD_SIZE, "test_tool")

    def test_exceeds_max_raises_security_error(self) -> None:
        with pytest.raises(SecurityError, match="exceeds maximum"):
            verify_file_size(MAX_DOWNLOAD_SIZE + 1, "test_tool")

    def test_zero_size_passes(self) -> None:
        verify_file_size(0, "test_tool")
