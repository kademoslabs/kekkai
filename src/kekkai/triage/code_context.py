"""Code context extraction for triage TUI.

Provides secure code context extraction with security controls:
- Path traversal protection (ASVS V5.3.3)
- File size limits (ASVS V10.3.3)
- Sensitive file detection (ASVS V8.3.4)
- Error sanitization (ASVS V7.4.1)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from ..fix.prompts import FixPromptBuilder

logger = logging.getLogger(__name__)

__all__ = [
    "CodeContext",
    "CodeContextExtractor",
]

# Security limits per ASVS V10.3.3
MAX_FILE_SIZE_MB = 10

# Sensitive file extensions to block (ASVS V8.3.4)
SENSITIVE_EXTENSIONS = {
    ".env",
    ".pem",
    ".key",
    ".crt",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".pub",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

# Binary file extensions to skip
BINARY_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".so",
    ".dll",
    ".dylib",
    ".exe",
    ".bin",
    ".class",
    ".jar",
    ".war",
    ".ear",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".7z",
    ".rar",
    ".whl",
    ".egg",
}


@dataclass
class CodeContext:
    """Code context with syntax highlighting metadata.

    Attributes:
        code: Formatted code with line numbers and >>> marker.
        language: Detected programming language for syntax highlighting.
        vulnerable_line: The specific vulnerable line text.
        error: Error message if extraction failed (None on success).
    """

    code: str
    language: str
    vulnerable_line: str
    error: str | None = None


class CodeContextExtractor:
    """Extracts code context from files with security controls.

    Security features:
    - Path validation to prevent traversal attacks (ASVS V5.3.3)
    - File size limits to prevent DoS (ASVS V10.3.3)
    - Sensitive file detection (ASVS V8.3.4)
    - Sanitized error messages (ASVS V7.4.1)

    Performance features:
    - LRU cache for file contents (max 20 files, ~200KB per file = ~4MB total)
    - Reduces re-reads when navigating between findings in same files
    """

    def __init__(self, repo_path: Path, max_file_size_mb: int = MAX_FILE_SIZE_MB) -> None:
        """Initialize code context extractor.

        Args:
            repo_path: Repository root path (for path validation).
            max_file_size_mb: Maximum file size in MB (DoS protection).
        """
        self.repo_path = repo_path.resolve()
        self.max_file_size_mb = max_file_size_mb
        self._prompt_builder = FixPromptBuilder(context_lines=10)
        # Simple LRU cache: {file_path: file_content}
        # Limited to 20 files to prevent memory bloat
        self._file_cache: dict[str, str] = {}
        self._cache_max_size = 20

    def extract(self, file_path: str, line: int | None) -> CodeContext | None:
        """Extract code context from a file.

        Args:
            file_path: Relative or absolute path to the file.
            line: Line number (1-indexed) of the vulnerability.

        Returns:
            CodeContext object with code and metadata, or None if unavailable.

        Security:
            - Path validation (ASVS V5.3.3)
            - Size limits (ASVS V10.3.3)
            - Sensitive file blocking (ASVS V8.3.4)
            - Error sanitization (ASVS V7.4.1)
        """
        if not file_path or not line:
            return None

        # Resolve path
        try:
            full_path = (self.repo_path / file_path).resolve()
        except (ValueError, OSError):
            # ASVS V7.4.1: Sanitized error (no full path)
            logger.warning(
                "code_context_path_invalid",
                extra={"file_path": Path(file_path).name, "reason": "invalid_path"},
            )
            return CodeContext(
                code="",
                language="",
                vulnerable_line="",
                error="Invalid file path",
            )

        # ASVS V5.3.3: Path traversal check
        if not self._validate_path(full_path):
            logger.warning(
                "code_context_path_traversal",
                extra={"file_path": Path(file_path).name, "reason": "path_traversal"},
            )
            return None

        # Check if file exists
        if not full_path.exists():
            logger.info(
                "code_context_file_not_found",
                extra={"file_path": Path(file_path).name},
            )
            return CodeContext(
                code="",
                language="",
                vulnerable_line="",
                error="File not found",
            )

        # ASVS V8.3.4: Sensitive file check
        if self._is_sensitive_file(full_path):
            logger.info(
                "code_context_sensitive_file",
                extra={"file_path": Path(file_path).name},
            )
            return CodeContext(
                code="",
                language="",
                vulnerable_line="",
                error="Code hidden (sensitive file type)",
            )

        # Binary file check
        if not self._is_text_file(full_path):
            logger.info(
                "code_context_binary_file",
                extra={"file_path": Path(file_path).name},
            )
            return None

        # ASVS V10.3.3: File size check
        size_mb = full_path.stat().st_size / (1024 * 1024)
        if size_mb > self.max_file_size_mb:
            logger.warning(
                "code_context_file_too_large",
                extra={"file_path": Path(file_path).name, "size_mb": f"{size_mb:.1f}"},
            )
            return CodeContext(
                code="",
                language="",
                vulnerable_line="",
                error=f"File too large for display ({size_mb:.1f}MB)",
            )

        # Read file content (with caching for performance)
        cache_key = str(full_path)
        if cache_key in self._file_cache:
            file_content = self._file_cache[cache_key]
        else:
            try:
                file_content = full_path.read_text(encoding="utf-8")
                # Cache the content
                self._file_cache[cache_key] = file_content
                # Evict oldest entry if cache is full (simple FIFO)
                if len(self._file_cache) > self._cache_max_size:
                    # Remove first (oldest) entry
                    oldest_key = next(iter(self._file_cache))
                    del self._file_cache[oldest_key]
            except (OSError, UnicodeDecodeError) as e:
                # ASVS V7.4.1: Sanitized error
                logger.warning(
                    "code_context_read_error",
                    extra={"file_path": Path(file_path).name, "error": str(e)},
                )
                return CodeContext(
                    code="",
                    language="",
                    vulnerable_line="",
                    error="Cannot read file",
                )

        # Extract code context using existing logic from fix engine
        code_context, vulnerable_line = self._prompt_builder.extract_code_context(
            file_content, line
        )

        # Detect language for syntax highlighting
        language = self._detect_language(full_path)

        return CodeContext(
            code=code_context,
            language=language,
            vulnerable_line=vulnerable_line,
            error=None,
        )

    def _validate_path(self, path: Path) -> bool:
        """Validate that path is within repo_path (prevent traversal).

        Args:
            path: Resolved path to validate.

        Returns:
            True if path is safe, False otherwise.

        Security:
            ASVS V5.3.3: Path validation to prevent directory traversal.
        """
        try:
            # Check if path is within repo_path
            path.relative_to(self.repo_path)
            return True
        except ValueError:
            return False

    def _is_text_file(self, path: Path) -> bool:
        """Check if file is a text file (not binary).

        Args:
            path: Path to check.

        Returns:
            True if likely a text file, False if binary.
        """
        suffix = path.suffix.lower()
        name = path.name.lower()

        # Check against binary extensions
        if suffix in BINARY_EXTENSIONS:
            return False

        # Special cases without extensions
        if name in ("dockerfile", "makefile", "vagrantfile", "jenkinsfile"):
            return True

        return True

    def _is_sensitive_file(self, path: Path) -> bool:
        """Check if file contains sensitive data (secrets, keys).

        Args:
            path: Path to check.

        Returns:
            True if file is sensitive and should not be displayed.

        Security:
            ASVS V8.3.4: Prevent sensitive data in outputs.
        """
        suffix = path.suffix.lower()
        name = path.name.lower()

        # Check extension
        if suffix in SENSITIVE_EXTENSIONS:
            return True

        # Check if the entire filename (including leading dot) matches sensitive patterns
        # For files like .env, .pem, etc., the suffix is empty but name includes the dot
        if name in {".env", ".pem", ".key", ".crt"}:
            return True

        # Check filename patterns
        return any(
            pattern in name
            for pattern in [
                "secret",
                "credential",
                "password",
                "token",
                "apikey",
                "private_key",
                "id_rsa",
                "id_dsa",
                "id_ecdsa",
            ]
        )

    def _detect_language(self, path: Path) -> str:
        """Detect programming language from file extension.

        Args:
            path: Path to the file.

        Returns:
            Language identifier for syntax highlighting.
        """
        return self._prompt_builder._detect_language(str(path))
