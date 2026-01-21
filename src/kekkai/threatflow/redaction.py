"""Extended secret redaction for ThreatFlow.

Provides comprehensive secret detection and redaction beyond the core module.
Handles AWS keys, GCP credentials, RSA/SSH keys, OAuth tokens, and more.

ASVS V16.2.5: No sensitive data in logs or outputs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import ClassVar

from kekkai_core import redact as core_redact


@dataclass
class RedactionPattern:
    """A pattern for detecting secrets."""

    name: str
    pattern: re.Pattern[str]
    replacement: str = "[REDACTED:{name}]"


# Comprehensive secret patterns for threat modeling
_EXTENDED_PATTERNS: list[RedactionPattern] = [
    # AWS credentials
    RedactionPattern(
        name="aws_access_key",
        pattern=re.compile(r"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*([A-Z0-9]{20})"),
    ),
    RedactionPattern(
        name="aws_secret_key",
        pattern=re.compile(
            r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*([A-Za-z0-9/+=]{40})"
        ),
    ),
    RedactionPattern(
        name="aws_key_inline",
        pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    ),
    # GCP credentials
    RedactionPattern(
        name="gcp_api_key",
        pattern=re.compile(r"(?i)(gcp[_-]?api[_-]?key|google[_-]?api[_-]?key)\s*[:=]\s*(\S+)"),
    ),
    RedactionPattern(
        name="gcp_service_account",
        pattern=re.compile(r'"type"\s*:\s*"service_account"'),
    ),
    # Azure credentials
    RedactionPattern(
        name="azure_key",
        pattern=re.compile(r"(?i)(azure[_-]?(?:storage[_-]?)?key)\s*[:=]\s*(\S+)"),
    ),
    # Private keys (RSA, EC, etc.)
    RedactionPattern(
        name="private_key_header",
        pattern=re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
    ),
    RedactionPattern(
        name="private_key_content",
        pattern=re.compile(
            r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
        ),
    ),
    RedactionPattern(
        name="ec_private_key",
        pattern=re.compile(
            r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+EC\s+PRIVATE\s+KEY-----"
        ),
    ),
    RedactionPattern(
        name="openssh_private_key",
        pattern=re.compile(
            r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----"
        ),
    ),
    # OAuth tokens
    RedactionPattern(
        name="oauth_token",
        pattern=re.compile(r"(?i)(oauth[_-]?token|access[_-]?token)\s*[:=]\s*([^\s,;\"']+)"),
    ),
    RedactionPattern(
        name="refresh_token",
        pattern=re.compile(r"(?i)(refresh[_-]?token)\s*[:=]\s*([^\s,;\"']+)"),
    ),
    RedactionPattern(
        name="client_secret",
        pattern=re.compile(r"(?i)(client[_-]?secret)\s*[:=]\s*([^\s,;\"']+)"),
    ),
    # GitHub tokens
    RedactionPattern(
        name="github_token",
        pattern=re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
    ),
    RedactionPattern(
        name="github_oauth",
        pattern=re.compile(r"\b(gho_[A-Za-z0-9]{36})\b"),
    ),
    RedactionPattern(
        name="github_pat",
        pattern=re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,})\b"),
    ),
    # GitLab tokens
    RedactionPattern(
        name="gitlab_token",
        pattern=re.compile(r"\b(glpat-[A-Za-z0-9\-_]{20,})\b"),
    ),
    # Slack tokens
    RedactionPattern(
        name="slack_token",
        pattern=re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]+)\b"),
    ),
    # Generic database URLs with passwords
    RedactionPattern(
        name="database_url",
        pattern=re.compile(
            r"(?i)((?:postgres|mysql|mongodb|redis)(?:ql)?://[^:]+:)([^@]+)(@[^\s]+)"
        ),
    ),
    # .env style secrets
    RedactionPattern(
        name="env_password",
        pattern=re.compile(r"(?i)^(\s*(?:DB_)?PASSWORD)\s*=\s*(.+)$", re.MULTILINE),
    ),
    RedactionPattern(
        name="env_secret",
        pattern=re.compile(r"(?i)^(\s*(?:\w+_)?SECRET(?:_KEY)?)\s*=\s*(.+)$", re.MULTILINE),
    ),
    RedactionPattern(
        name="env_api_key",
        pattern=re.compile(r"(?i)^(\s*(?:\w+_)?API_KEY)\s*=\s*(.+)$", re.MULTILINE),
    ),
    # JWT tokens (simplified pattern)
    RedactionPattern(
        name="jwt_token",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b"),
    ),
    # Generic high-entropy strings (potential secrets)
    RedactionPattern(
        name="base64_secret",
        pattern=re.compile(r"(?i)(secret|key|token|password)\s*[:=]\s*([A-Za-z0-9+/]{32,}={0,2})"),
    ),
    # Stripe keys
    RedactionPattern(
        name="stripe_key",
        pattern=re.compile(r"\b(sk_(?:live|test)_[A-Za-z0-9]{24,})\b"),
    ),
    RedactionPattern(
        name="stripe_publishable",
        pattern=re.compile(r"\b(pk_(?:live|test)_[A-Za-z0-9]{24,})\b"),
    ),
    # SendGrid
    RedactionPattern(
        name="sendgrid_key",
        pattern=re.compile(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"),
    ),
    # Twilio
    RedactionPattern(
        name="twilio_key",
        pattern=re.compile(r"\b(SK[A-Za-z0-9]{32})\b"),
    ),
]


@dataclass
class ThreatFlowRedactor:
    """Extended redactor for ThreatFlow with comprehensive secret detection."""

    custom_patterns: list[RedactionPattern] = field(default_factory=list)
    _patterns: list[RedactionPattern] = field(init=False)

    PATTERNS: ClassVar[list[RedactionPattern]] = _EXTENDED_PATTERNS

    def __post_init__(self) -> None:
        self._patterns = list(self.PATTERNS) + self.custom_patterns

    def redact(self, text: str) -> str:
        """Redact all detected secrets from text.

        First applies core redaction, then extended patterns.
        """
        result = core_redact(text)

        for pattern in self._patterns:
            replacement = pattern.replacement.format(name=pattern.name)
            result = self._apply_pattern(result, pattern, replacement)

        return result

    def _apply_pattern(self, text: str, pat: RedactionPattern, repl: str) -> str:
        """Apply a single redaction pattern to text."""
        if pat.pattern.groups > 0:
            # Handle patterns with capture groups
            def replacer(m: re.Match[str]) -> str:
                if m.lastindex and m.lastindex >= 2:
                    # Pattern like (key)=(value) - keep key, redact value
                    # Reconstruct with original separators if possible
                    if "database_url" in pat.name:
                        return f"{m.group(1)}{repl}{m.group(3)}"
                    return f"{m.group(1)}={repl}"
                return repl

            return pat.pattern.sub(replacer, text)
        return pat.pattern.sub(repl, text)

    def detect_secrets(self, text: str) -> list[tuple[str, str]]:
        """Detect potential secrets and return (pattern_name, matched_text) pairs.

        Used for logging which types of secrets were found (without values).
        """
        found: list[tuple[str, str]] = []
        for pattern in self._patterns:
            matches = pattern.pattern.findall(text)
            if matches:
                # Only report the type, not the actual values
                found.append((pattern.name, f"{len(matches)} occurrence(s)"))
        return found

    def add_pattern(self, name: str, regex: str, replacement: str | None = None) -> None:
        """Add a custom redaction pattern."""
        repl = replacement or f"[REDACTED:{name}]"
        self._patterns.append(
            RedactionPattern(name=name, pattern=re.compile(regex), replacement=repl)
        )
