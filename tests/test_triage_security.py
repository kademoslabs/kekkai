"""Security tests for triage code context extraction.

Tests ASVS 5.0 compliance:
- V5.3.3: Path traversal prevention
- V7.4.1: Error message sanitization
- V8.3.4: Sensitive data protection
- V10.3.3: DoS mitigation
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kekkai.triage.code_context import CodeContextExtractor


class TestTriageSecurityControls:
    """Security tests for code context extraction."""

    @pytest.fixture
    def temp_repo(self, tmp_path: Path) -> Path:
        """Create a temporary repository structure."""
        repo = tmp_path / "repo"
        repo.mkdir()
        return repo

    @pytest.fixture
    def extractor(self, temp_repo: Path) -> CodeContextExtractor:
        """Create a code context extractor."""
        return CodeContextExtractor(temp_repo)

    def test_path_traversal_blocked(self, extractor: CodeContextExtractor) -> None:
        """Test that path traversal attacks are blocked (ASVS V5.3.3)."""
        # Attempt to read file outside repo
        context = extractor.extract("../../../etc/passwd", 1)
        assert context is None

    def test_path_traversal_absolute_path_blocked(self, extractor: CodeContextExtractor) -> None:
        """Test that absolute paths outside repo are blocked (ASVS V5.3.3)."""
        context = extractor.extract("/etc/passwd", 1)
        assert context is None

    def test_path_traversal_relative_escapes_blocked(self, extractor: CodeContextExtractor) -> None:
        """Test that relative paths escaping repo are blocked (ASVS V5.3.3)."""
        context = extractor.extract("../../outside.txt", 1)
        assert context is None

    def test_dos_via_large_file_mitigated(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that large files are rejected to prevent DoS (ASVS V10.3.3)."""
        # Create a file larger than 10MB
        large_file = temp_repo / "large.txt"
        # Write 11MB of data
        with large_file.open("w") as f:
            f.write("x" * (11 * 1024 * 1024))

        context = extractor.extract("large.txt", 1)
        assert context is not None
        assert context.error is not None
        assert "too large" in context.error.lower()
        assert "11.0MB" in context.error

    def test_sensitive_files_not_displayed_env(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that .env files are blocked (ASVS V8.3.4)."""
        env_file = temp_repo / ".env"
        env_file.write_text("SECRET_KEY=super_secret_value\n")

        context = extractor.extract(".env", 1)
        assert context is not None
        assert context.error is not None
        assert "sensitive" in context.error.lower()

    def test_sensitive_files_not_displayed_pem(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that .pem files are blocked (ASVS V8.3.4)."""
        pem_file = temp_repo / "private.pem"
        # detect-private-key: test file, not a real key
        pem_file.write_text("-----BEGIN RSA PRIVATE KEY-----\n")

        context = extractor.extract("private.pem", 1)
        assert context is not None
        assert context.error is not None
        assert "sensitive" in context.error.lower()

    def test_sensitive_files_not_displayed_key(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that .key files are blocked (ASVS V8.3.4)."""
        key_file = temp_repo / "server.key"
        key_file.write_text("PRIVATE KEY DATA\n")

        context = extractor.extract("server.key", 1)
        assert context is not None
        assert context.error is not None
        assert "sensitive" in context.error.lower()

    def test_sensitive_files_by_name_pattern(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that files with 'secret' in name are blocked (ASVS V8.3.4)."""
        secret_file = temp_repo / "app_secrets.py"
        secret_file.write_text("API_KEY = 'secret123'\n")

        context = extractor.extract("app_secrets.py", 1)
        assert context is not None
        assert context.error is not None
        assert "sensitive" in context.error.lower()

    def test_error_messages_sanitized(
        self, extractor: CodeContextExtractor, temp_repo: Path
    ) -> None:
        """Test that error messages don't leak full paths (ASVS V7.4.1)."""
        # Try to access non-existent file
        context = extractor.extract("nonexistent.py", 1)
        assert context is not None
        assert context.error is not None

        # Error should not contain full system path
        assert str(temp_repo) not in context.error
        assert "not found" in context.error.lower()

    def test_binary_files_skipped_pyc(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that .pyc files are skipped."""
        pyc_file = temp_repo / "module.pyc"
        pyc_file.write_bytes(b"\x00\x00\x00\x00binary data")

        context = extractor.extract("module.pyc", 1)
        assert context is None

    def test_binary_files_skipped_so(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that .so files are skipped."""
        so_file = temp_repo / "lib.so"
        so_file.write_bytes(b"\x7fELF binary data")

        context = extractor.extract("lib.so", 1)
        assert context is None

    def test_binary_files_skipped_exe(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that .exe files are skipped."""
        exe_file = temp_repo / "program.exe"
        exe_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

        context = extractor.extract("program.exe", 1)
        assert context is None

    def test_invalid_path_sanitized(self, extractor: CodeContextExtractor) -> None:
        """Test that invalid paths produce sanitized errors (ASVS V7.4.1)."""
        # Test with various invalid path characters
        context = extractor.extract("\x00invalid\x00", 1)
        assert context is not None
        assert context.error is not None
        assert "invalid" in context.error.lower()

    def test_size_limit_configurable(self, temp_repo: Path) -> None:
        """Test that size limit is configurable."""
        # Create extractor with 1MB limit
        extractor = CodeContextExtractor(temp_repo, max_file_size_mb=1)

        # Create 2MB file
        large_file = temp_repo / "medium.txt"
        with large_file.open("w") as f:
            f.write("x" * (2 * 1024 * 1024))

        context = extractor.extract("medium.txt", 1)
        assert context is not None
        assert context.error is not None
        assert "too large" in context.error.lower()

    def test_unicode_decode_error_handled(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that binary files with text extension are handled gracefully."""
        # Create file with invalid UTF-8
        bad_file = temp_repo / "bad.txt"
        bad_file.write_bytes(b"\xff\xfe invalid utf-8 \x80\x81")

        context = extractor.extract("bad.txt", 1)
        assert context is not None
        assert context.error is not None
        assert "cannot read" in context.error.lower()
