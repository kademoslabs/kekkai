"""Sanitization utilities for GitHub PR comments."""

from __future__ import annotations

import re

# Markdown special characters that need escaping
MARKDOWN_SPECIAL_CHARS = r"[\`*_{}\[\]()#+\-.!|>~]"

# Patterns for potential secrets (conservative to avoid false positives)
_AWS_KEY_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE)
_API_KEY_PATTERN = re.compile(
    r"(?:api[_-]?key|apikey|secret|password|token)\s*[:=]\s*['\"]?" r"([A-Za-z0-9_\-]{20,})['\"]?",
    re.IGNORECASE,
)
_BEARER_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}", re.IGNORECASE)
_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*")
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----.*?" r"-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
    re.DOTALL,
)
_GITHUB_TOKEN_PATTERN = re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")
_HEX_SECRET_PATTERN = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40,}(?![A-Fa-f0-9])")

# Order matters: specific patterns first, generic last
SECRET_PATTERNS = [
    # Specific patterns first
    (_JWT_PATTERN, "[JWT_REDACTED]"),
    (_GITHUB_TOKEN_PATTERN, "[GITHUB_TOKEN_REDACTED]"),
    (_AWS_KEY_PATTERN, "[AWS_KEY_REDACTED]"),
    (_PRIVATE_KEY_PATTERN, "[PRIVATE_KEY_REDACTED]"),
    (_BEARER_PATTERN, "Bearer [REDACTED]"),
    # Generic patterns last
    (_API_KEY_PATTERN, "[REDACTED]"),
    (_HEX_SECRET_PATTERN, "[HEX_SECRET_REDACTED]"),
]

# Patterns for redacting common sensitive values (applied last)
SENSITIVE_VALUE_PATTERN = re.compile(
    r"(api[_-]?key|apikey|secret|password|credential|auth)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
    re.IGNORECASE,
)


def escape_markdown(text: str) -> str:
    """Escape markdown special characters to prevent injection.

    Args:
        text: Raw text that may contain markdown special characters.

    Returns:
        Text with markdown characters escaped.
    """
    if not text:
        return ""

    # Escape backslashes first to avoid double-escaping
    result = text.replace("\\", "\\\\")

    # Escape markdown special characters
    for char in "`*_{}[]()#+-.!|>~":
        result = result.replace(char, f"\\{char}")

    # Remove potential HTML tags
    result = re.sub(r"<[^>]+>", "", result)

    # Truncate to reasonable length
    max_length = 2000
    if len(result) > max_length:
        result = result[: max_length - 3] + "..."

    return result


def redact_secrets(text: str) -> str:
    """Redact potential secrets from text.

    Args:
        text: Text that may contain secrets.

    Returns:
        Text with secrets redacted.
    """
    if not text:
        return ""

    result = text

    # Apply secret patterns
    for pattern, replacement in SECRET_PATTERNS:
        result = pattern.sub(replacement, result)

    # Redact sensitive key=value pairs
    result = SENSITIVE_VALUE_PATTERN.sub(r"\1=[REDACTED]", result)

    return result


def sanitize_for_comment(text: str) -> str:
    """Full sanitization pipeline for PR comments.

    Args:
        text: Raw text to sanitize.

    Returns:
        Text safe for PR comments.
    """
    # First redact secrets
    text = redact_secrets(text)
    # Then escape markdown
    text = escape_markdown(text)
    return text
