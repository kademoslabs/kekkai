from __future__ import annotations

import re

# Conservative redaction: hide common token/secret patterns while preserving debugging structure.
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)\b(bearer)\s+([a-z0-9\-\._~\+\/]+=*)"),
]


def redact(text: str) -> str:
    """Redact likely secrets from a string (best-effort, non-destructive)."""
    redacted = text
    for pat in _SECRET_PATTERNS:
        redacted = pat.sub(lambda m: f"{m.group(1)} [REDACTED]", redacted)
    return redacted
