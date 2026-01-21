from __future__ import annotations

import re

# Conservative redaction: hide common token/secret patterns while preserving debugging structure.
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)\b(bearer)\s+([a-z0-9\-\._~\+\/]+=*)"),
]

# Extended patterns for comprehensive secret detection
_EXTENDED_PATTERNS: list[re.Pattern[str]] = [
    # AWS keys
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    re.compile(r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*([A-Za-z0-9/+=]{40})"),
    # GitHub tokens
    re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
    re.compile(r"\b(gho_[A-Za-z0-9]{36})\b"),
    re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,})\b"),
    # GitLab tokens
    re.compile(r"\b(glpat-[A-Za-z0-9\-_]{20,})\b"),
    # Slack tokens
    re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]+)\b"),
    # Stripe keys
    re.compile(r"\b(sk_(?:live|test)_[A-Za-z0-9]{24,})\b"),
    re.compile(r"\b(pk_(?:live|test)_[A-Za-z0-9]{24,})\b"),
    # Private key headers
    re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
    # JWT tokens (simplified)
    re.compile(r"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b"),
]


def redact(text: str) -> str:
    """Redact likely secrets from a string (best-effort, non-destructive)."""
    redacted = text
    for pat in _SECRET_PATTERNS:
        redacted = pat.sub(lambda m: f"{m.group(1)} [REDACTED]", redacted)
    return redacted


def redact_extended(text: str) -> str:
    """Redact secrets using both core and extended patterns.

    Includes AWS, GitHub, GitLab, Slack, Stripe tokens, private keys, and JWTs.
    """
    result = redact(text)
    for pat in _EXTENDED_PATTERNS:
        result = pat.sub("[REDACTED]", result)
    return result


def detect_secrets(text: str) -> list[str]:
    """Detect types of secrets present in text without returning values.

    Returns list of pattern names/descriptions found.
    """
    found: list[str] = []

    # Check core patterns
    for pat in _SECRET_PATTERNS:
        if pat.search(text):
            found.append("credential_pattern")

    # Check extended patterns with descriptions
    pattern_names = [
        ("aws_key", _EXTENDED_PATTERNS[0]),
        ("aws_secret", _EXTENDED_PATTERNS[1]),
        ("github_token", _EXTENDED_PATTERNS[2]),
        ("github_oauth", _EXTENDED_PATTERNS[3]),
        ("github_pat", _EXTENDED_PATTERNS[4]),
        ("gitlab_token", _EXTENDED_PATTERNS[5]),
        ("slack_token", _EXTENDED_PATTERNS[6]),
        ("stripe_secret", _EXTENDED_PATTERNS[7]),
        ("stripe_publishable", _EXTENDED_PATTERNS[8]),
        ("private_key", _EXTENDED_PATTERNS[9]),
        ("jwt_token", _EXTENDED_PATTERNS[10]),
    ]

    for name, pat in pattern_names:
        if pat.search(text):
            found.append(name)

    return list(set(found))  # Dedupe
